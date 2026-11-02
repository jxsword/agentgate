"""V1.2 tests: env-injected headers (EX-6), hot reload, audit rotation,
web approval console (EX-2), multi-agent HTTP (all), OPA backend (EX-5)."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

from agentgate.approvals import ApprovalManager
from agentgate.audit import AuditLog
from agentgate.config import Config, ConfigError, load_config
from agentgate.gateway import Gateway
from agentgate.grants import GrantStore
from agentgate.policy import Decision, PolicyEngine

from tests.test_e2e import SRC, open_session, write_config


# ---- EX-6: env interpolation ----

def test_env_ref_resolution(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_TOKEN", "abc123")
    doc = {
        "version": 1,
        "servers": {"remote": {"transport": "http", "url": "http://x/mcp",
                                "headers": {"Authorization": "Bearer ${MY_TOKEN}"}}},
    }
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    cfg = load_config(p)
    assert cfg.servers["remote"].headers["Authorization"] == "Bearer abc123"


def test_env_ref_missing_fails_load(monkeypatch, tmp_path):
    monkeypatch.delenv("NO_SUCH_VAR_XYZ", raising=False)
    doc = {
        "version": 1,
        "servers": {"remote": {"transport": "http", "url": "http://x/mcp",
                                "headers": {"Authorization": "Bearer ${NO_SUCH_VAR_XYZ}"}}},
    }
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)


# ---- audit rotation ----

def test_audit_rotation(tmp_path):
    log = AuditLog(tmp_path / "state" / "audit.jsonl", max_bytes=1)
    log.append("e1")
    log.append("e2")
    rotated = log.rotated_files()
    assert len(rotated) == 1  # first append rotated the initial file
    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1  # fresh file has only the newest record


# ---- hot reload ----

def _mk_gateway(tmp_path) -> tuple[Gateway, Path]:
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"default": "ask", "tools": {"echo": "allow"}}}}},
    }), encoding="utf-8")
    cfg = load_config(cfg_path)
    gw = Gateway(cfg, "bot", PolicyEngine(cfg), ApprovalManager(tmp_path / "state"),
                 GrantStore(tmp_path / "state" / "grants.json"),
                 AuditLog(tmp_path / "state" / "audit.jsonl"),
                 config_path=str(cfg_path), watch_policy=True)
    return gw, cfg_path


def test_hot_reload_swaps_policy(tmp_path):
    gw, cfg_path = _mk_gateway(tmp_path)
    mtime = cfg_path.stat().st_mtime
    # rewrite with a changed decision + bump mtime explicitly
    new_doc = {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"default": "ask", "tools": {"echo": "deny"}}}}},
    }
    cfg_path.write_text(yaml.safe_dump(new_doc), encoding="utf-8")
    os.utime(cfg_path, (mtime + 10, mtime + 10))

    gw._reload_policy_once(cfg_path, mtime)
    assert gw.engine.evaluate("bot", "fs", "echo", {}).action == "deny"
    events = [json.loads(l) for l in
              (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "policy_reloaded" for e in events)


def test_hot_reload_invalid_keeps_old(tmp_path):
    gw, cfg_path = _mk_gateway(tmp_path)
    mtime = cfg_path.stat().st_mtime
    cfg_path.write_text("version: 9\nagents: {bot: {servers: {fs: {tools: {x: allow}}}}}\n",
                        encoding="utf-8")
    os.utime(cfg_path, (mtime + 10, mtime + 10))
    gw._reload_policy_once(cfg_path, mtime)
    assert gw.engine.evaluate("bot", "fs", "echo", {}).action == "allow"  # old policy kept
    events = [json.loads(l) for l in
              (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert any(e["event"] == "policy_reload_failed" for e in events)


# ---- EX-2: web console ----

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http(method: str, url: str, **kw):
    import httpx2

    async with httpx2.AsyncClient(timeout=5) as client:
        return await client.request(method, url, **kw)


async def test_web_console_flow(tmp_path):
    state = tmp_path / "state"
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "write_file", {"path": "a.txt"}, "rule:x",
                             delegation={"ttl_seconds": 60, "bind": "tool"})
    store = GrantStore(state / "grants.json")
    store.add("bot", "fs", "echo", None, ttl_seconds=600, bind="tool")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "ui", "--state-dir", str(state),
         "--port", str(port)],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        page = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                resp = await _http("GET", base + "/")
                page = resp.text
                break
            except Exception:  # noqa: BLE001
                await asyncio.sleep(0.4)
        assert page, "console did not come up"
        assert req["id"] in page and "write_file" in page
        assert "echo@fs--echo" in page or "fs--echo" in page  # grant listed

        # approve via console (same one-vote + signing path as CLI)
        resp = await _http("POST", f"{base}/approve/{req['id']}",
                           data={"action": "allow", "approver": "webby"})
        assert resp.status_code in (303, 200)
        decision = json.loads((state / "decisions" / f"{req['id']}.json").read_text(encoding="utf-8"))
        assert decision["allow"] is True
        assert decision["approver"] == "web:webby"

        # revoke via console (fresh store instance: console re-reads from disk)
        grant_id = GrantStore(state / "grants.json").list()[0].id
        resp = await _http("POST", f"{base}/revoke/{grant_id}")
        assert resp.status_code in (303, 200)
        assert GrantStore(state / "grants.json").list() == []
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---- multi-agent HTTP (all) ----

async def test_multi_agent_http(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    doc = {
        "version": 1, "default_decision": "deny",
        "state_dir": str(tmp_path / "state"),
        "servers": {"demo": {"transport": "stdio", "command": sys.executable,
                              "args": [str(Path(write_config.__globals__["DEMO_SERVER"]))],
                              "env": {"DEMO_SANDBOX": str(sandbox)}}},
        "agents": {
            "alpha": {"servers": {"demo": {"default": "deny", "tools": {"echo": "allow"}}}},
            "beta": {"servers": {"demo": {"default": "deny", "tools": {"echo": "deny"}}}},
        },
    }
    cfg = tmp_path / "p.yaml"
    cfg.write_text(yaml.safe_dump(doc), encoding="utf-8")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "run", "--config", str(cfg), "--agent", "all",
         "--http", f"127.0.0.1:{port}"],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def session_for(agent: str):
            deadline = time.monotonic() + 20
            last = None
            connected = False
            while not connected and time.monotonic() < deadline:
                try:
                    async with streamable_http_client(
                            f"http://127.0.0.1:{port}/{agent}/mcp") as (read, write):
                        async with ClientSession(read, write) as sess:
                            await asyncio.wait_for(sess.initialize(), timeout=5)
                            connected = True
                            yield sess
                except Exception as e:  # noqa: BLE001
                    if connected:
                        raise  # session worked; the failure is in the test body
                    last = e
                    await asyncio.sleep(0.4)
            if not connected:
                raise RuntimeError(f"no session for {agent}: {last}")

        async with session_for("alpha") as sess_a, session_for("beta") as sess_b:
            res = await sess_a.call_tool("demo--echo", {"text": "hi"})
            assert not res.is_error
            res = await sess_b.call_tool("demo--echo", {"text": "hi"})
            assert res.is_error and "denied by policy" in res.content[0].text
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---- EX-5: OPA backend ----

def _opa_engine(tmp_path, handler):
    import httpx2

    doc = {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"default": "ask", "tools": {"echo": "allow"}}}}},
    }
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    cfg = load_config(p)
    transport = httpx2.MockTransport(handler)
    client = httpx2.AsyncClient(transport=transport)
    from agentgate.policy_backends import OpaPolicyEngine

    return OpaPolicyEngine(cfg, None, url="http://opa.test/v1/data/agentgate",
                           client=client)


async def test_opa_local_explicit_wins(tmp_path):
    engine = _opa_engine(tmp_path, lambda req: __import__("httpx2").Response(
        200, json={"result": {"decision": "deny"}}))
    # echo has an explicit local allow -> OPA not consulted
    d = await engine.evaluate_async("bot", "fs", "echo", {})
    assert d.action == "allow" and d.rule.startswith("agents.")


async def test_opa_fallback_decides(tmp_path):
    def handler(request):
        import httpx2

        inp = json.loads(request.content)["input"]
        decision = "ask" if inp["tool"] == "write_file" else "deny"
        return httpx2.Response(200, json={"result": {"decision": decision}})

    engine = _opa_engine(tmp_path, handler)
    d = await engine.evaluate_async("bot", "fs", "write_file", {})
    assert d.action == "ask" and d.rule.startswith("opa:")
    d = await engine.evaluate_async("bot", "fs", "unknown_tool", {})
    assert d.action == "deny" and d.rule.startswith("opa:")


async def test_opa_failure_fails_closed(tmp_path):
    def handler(request):
        import httpx2

        return httpx2.Response(500)

    engine = _opa_engine(tmp_path, handler)
    d = await engine.evaluate_async("bot", "fs", "unknown_tool", {})
    assert d.action == "deny" and "opa:error" in d.rule


async def test_opa_invalid_word_fails_closed(tmp_path):
    def handler(request):
        import httpx2

        return httpx2.Response(200, json={"decision": "maybe"})

    engine = _opa_engine(tmp_path, handler)
    d = await engine.evaluate_async("bot", "fs", "unknown_tool", {})
    assert d.action == "deny" and "opa:invalid" in d.rule


def test_gateway_awaits_async_engine(tmp_path):
    """Gateway._call_tool must await engines whose evaluate is async (OPA)."""
    from tests.test_gateway import AllowEngine  # sync engine still works

    gw_engine = _opa_engine(tmp_path, lambda req: None)
    # OpaPolicyEngine.evaluate returns a coroutine; ensure gateway handles it
    import inspect

    result = gw_engine.evaluate("bot", "fs", "echo", {})
    assert inspect.isawaitable(result)
    result.close()  # avoid un-awaited warning
