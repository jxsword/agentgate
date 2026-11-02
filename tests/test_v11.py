"""V1.1 tests: prompts/resources proxy (EX-4), HTTP entry (EX-1), approval HMAC (EX-3)."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentgate.approvals import ApprovalManager, approval_secret, verify_decision
from agentgate.config import ConfigError, load_config
from agentgate.policy import PolicyEngine

from tests.test_e2e import SRC, open_session, write_config  # shared e2e harness


# ---- unit: capability checks ----

def make_cfg(tmp_path):
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "version": 1,
        "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"default": "ask", "prompts": "allow",
                                              "resources": "deny"}}}},
    }), encoding="utf-8")
    return load_config(cfg_path)


def test_capability_matrix(tmp_path):
    engine = PolicyEngine(make_cfg(tmp_path))
    assert engine.check_capability("bot", "fs", "prompts") == (
        True, "agents.bot.servers.fs.prompts")
    assert engine.check_capability("bot", "fs", "resources")[0] is False
    # unknown agent / server fail closed
    assert engine.check_capability("ghost", "fs", "prompts")[0] is False
    assert engine.check_capability("bot", "nope", "prompts")[0] is False


def test_capability_value_validation(tmp_path):
    cfg_path = tmp_path / "bad.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "version": 1,
        "agents": {"bot": {"servers": {"fs": {"prompts": "ask"}}}},  # ask not allowed here
    }), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(cfg_path)


# ---- unit: approval HMAC (EX-3) ----

def test_signature_roundtrip_and_tamper(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_APPROVAL_SECRET", "test-secret-from-env")
    mgr = ApprovalManager(tmp_path / "state")
    req = mgr.create_request("bot", "fs", "t", {"a": 1}, "rule")
    decision = mgr.decide(req["id"], allow=True, approver="alice")
    assert "sig" in decision
    assert verify_decision(req, decision, "test-secret-from-env")
    # tampered approver -> invalid; unsigned -> invalid
    tampered = {**decision, "approver": "mallory"}
    assert not verify_decision(req, tampered, "test-secret-from-env")
    assert not verify_decision(req, {"id": req["id"], "allow": True}, "test-secret-from-env")


def test_secret_only_from_env(monkeypatch):
    monkeypatch.delenv("AGENTGATE_APPROVAL_SECRET", raising=False)
    assert approval_secret() is None
    monkeypatch.setenv("AGENTGATE_APPROVAL_SECRET", "")
    assert approval_secret() is None  # empty counts as off


# ---- e2e: prompts/resources through the gateway (EX-4) ----

async def test_prompts_and_resources_flow(workdir):
    sandbox = workdir / "sandbox"
    sandbox.mkdir(exist_ok=True)
    (sandbox / "note.txt").write_text("resource-body", encoding="utf-8")
    cfg = write_config(workdir)
    doc = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    doc["agents"]["bot"]["servers"]["demo"]["prompts"] = "allow"
    doc["agents"]["bot"]["servers"]["demo"]["resources"] = "allow"
    cfg.write_text(yaml.safe_dump(doc), encoding="utf-8")

    async with open_session(workdir, cfg) as (session, init):
        prompts = await session.list_prompts()
        assert "demo--greet" in [p.name for p in prompts.prompts]

        got = await session.get_prompt("demo--greet", {"user": "agentgate"})
        assert "Hello, agentgate!" in got.messages[0].content.text

        resources = await session.list_resources()
        uris = [str(r.uri) for r in resources.resources]
        assert "demo://file/note.txt" in uris
        read = await session.read_resource("demo://file/note.txt")
        assert read.contents[0].text == "resource-body"

        # unknown uri: fail closed with readable denial text
        res = await session.read_resource("demo://file/nope.txt")
        assert "not reachable" in res.contents[0].text

        state = workdir / "state"
        events = [json.loads(l) for l in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "prompt_call" for e in events)
        assert any(e["event"] == "resource_call" for e in events)


async def test_prompts_denied_by_default(workdir):
    cfg = write_config(workdir)  # no prompts/resources keys -> deny
    async with open_session(workdir, cfg) as (session, init):
        prompts = await session.list_prompts()
        assert prompts.prompts == []
        got = await session.get_prompt("demo--greet", {"user": "x"})
        assert "denied by policy" in got.messages[0].content.text


# ---- e2e: HTTP entry (EX-1) ----

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_http_gateway(workdir):
    from mcp.client.streamable_http import streamable_http_client

    port = _free_port()
    cfg = write_config(workdir)
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "run", "--config", str(cfg), "--agent", "bot",
         "--http", f"127.0.0.1:{port}"],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        from mcp.client.streamable_http import streamable_http_client
        from contextlib import asynccontextmanager

        url = f"http://127.0.0.1:{port}/mcp"

        @asynccontextmanager
        async def open_http_session():
            # plain `async with` blocks (like tests/test_e2e.py stdio pattern):
            # enter and exit stay in one task, which keeps anyio cancel scopes
            # happy even when a retry attempt fails mid-connect
            deadline = time.monotonic() + 20
            last = None
            connected = False
            while not connected and time.monotonic() < deadline:
                try:
                    async with streamable_http_client(url) as (read, write):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            connected = True
                            yield session
                except Exception as e:  # noqa: BLE001
                    if connected:
                        raise  # session worked; failure is in the test body
                    last = e
                    await asyncio.sleep(0.4)
            if not connected:
                raise RuntimeError(f"could not connect to http gateway: {last}")

        async with open_http_session() as session:
            tools = await session.list_tools()
            assert "demo--echo" in [t.name for t in tools.tools]
            res = await session.call_tool("demo--echo", {"text": "over-http"})
            assert not res.is_error
            assert "echo: over-http" in res.content[0].text
            res = await session.call_tool("demo--delete_file", {"path": "x"})
            assert res.is_error and "denied by policy" in res.content[0].text
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---- e2e: signed approval enforced by gateway (EX-3) ----

async def test_signed_approval_enforced(workdir, monkeypatch):
    monkeypatch.setenv("AGENTGATE_APPROVAL_SECRET", "e2e-secret")
    cfg = write_config(workdir)
    env = {**os.environ, "AGENTGATE_APPROVAL_SECRET": "e2e-secret", "PYTHONPATH": str(SRC)}
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentgate", "run", "--config", str(cfg), "--agent", "bot",
              "--ask-timeout", "60"],
        env=env,
    )

    @asynccontextmanager
    async def open_signed():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=30)
                yield session

    async with open_signed() as session:
        # 1) properly signed decision (decide() picks up the same env) -> allowed
        args = {"path": "sandbox/signed.txt", "content": "signed"}
        call_task = asyncio.create_task(session.call_tool("demo--write_file", args))
        state = workdir / "state"
        mgr = ApprovalManager(state)
        deadline = time.monotonic() + 20
        req = None
        while time.monotonic() < deadline:
            pending = mgr.list_pending()
            if pending and "id" in pending[0]:
                req = pending[0]
                break
            await asyncio.sleep(0.1)
        assert req, "no pending request appeared"
        mgr.decide(req["id"], allow=True, approver="alice")  # signs via env secret
        res = await call_task
        assert not res.is_error, res.content[0].text

        # 2) forged decision (unsigned, same shape) -> gateway denies fail-closed.
        # different args so the tool+args grant from step 1 does NOT cover it
        args2 = {"path": "sandbox/signed.txt", "content": "forged"}
        call_task = asyncio.create_task(session.call_tool("demo--write_file", args2))
        deadline = time.monotonic() + 20
        req2 = None
        while time.monotonic() < deadline:
            pending = mgr.list_pending()
            if pending and "id" in pending[0]:
                req2 = pending[0]
                break
            await asyncio.sleep(0.1)
        assert req2
        decision_path = state / "decisions" / f"{req2['id']}.json"
        decision_path.write_text(json.dumps({
            "id": req2["id"], "allow": True, "approver": "mallory",
            "decided_at": "2026-11-02T00:00:00+0000",
        }), encoding="utf-8")
        res = await call_task
        assert res.is_error
        assert "signature" in res.content[0].text
        events = [json.loads(l) for l in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "approval_signature_invalid" for e in events)
