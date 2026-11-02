"""v0.5 tests: log filters (I1), redaction (I3), agent-header routing (I2)."""

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

import httpx2
import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentgate.approvals import ApprovalManager
from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.config import load_config
from agentgate.policy import canonical_args

from tests.test_e2e import SRC, open_session, write_config


# ---- I1: log filters ----

def _seed(state: Path):
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="allow")
    log.append("call_denied", agent="bot", server="fs", tool="rm", decision="deny")
    log.append("call", agent="alice", server="fs", tool="echo", decision="allow")


def test_log_filter_key_value(tmp_path, capsys):
    _seed(tmp_path / "state")
    rc = main(["log", "--filter", "agent=alice", "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    out = capsys.readouterr().out
    recs = [json.loads(l) for l in out.splitlines()]
    assert len(recs) == 1 and recs[0]["agent"] == "alice"


def test_log_filter_grep(tmp_path, capsys):
    _seed(tmp_path / "state")
    rc = main(["log", "--grep", "rm", "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    recs = [json.loads(l) for l in capsys.readouterr().out.splitlines()]
    assert len(recs) == 1 and recs[0]["tool"] == "rm"


def test_log_filter_bad_spec(tmp_path):
    rc = main(["log", "--filter", "noequals", "--state-dir", str(tmp_path / "state")])
    assert rc == 2


# ---- I3: redaction ----

def test_redact_masks_values_but_not_hash(tmp_path):
    from agentgate.config import ServerPolicy

    spol = ServerPolicy(default="ask", redact=["pass*", "api_key"])
    real = {"password": "hunter2", "api_key": "xyz", "path": "a/b", "nested": {"token": "t"}}
    shown = spol.redact_arguments(real)
    assert shown["password"] == "***" and shown["api_key"] == "***"
    assert shown["path"] == "a/b"
    assert shown["nested"] == {"token": "t"}  # v0.5 masks top level only (documented)
    # hash uses the real arguments
    assert canonical_args(real) != canonical_args(shown)


async def test_redact_applied_to_pending_and_audit(workdir):
    """E2E: redact:'password' masks pending display; grant binding uses real args."""
    cfg = write_config(workdir)
    doc = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    doc["agents"]["bot"]["servers"]["demo"]["redact"] = ["content"]
    doc["agents"]["bot"]["servers"]["demo"]["tools"]["write_file"] = {
        "decision": "ask",
        "args_match": {"path": "*sandbox*"},
        "delegation": {"ttl_seconds": 600, "bind": "tool+args"},
    }
    cfg.write_text(yaml.safe_dump(doc), encoding="utf-8")

    async with open_session(workdir, cfg) as (session, init):
        args = {"path": "sandbox/redact.txt", "content": "TOPSECRET"}
        call_task = asyncio.create_task(session.call_tool("demo--write_file", args))
        state = workdir / "state"
        mgr = ApprovalManager(state)
        deadline = time.monotonic() + 20
        pending = None
        while time.monotonic() < deadline:
            plist = mgr.list_pending()
            if plist and "id" in plist[0]:
                pending = plist[0]
                break
            await asyncio.sleep(0.1)
        assert pending
        # pending shows the masked value...
        assert pending["arguments"]["content"] == "***"
        # ...but the hash matches the REAL arguments (grant binding correctness)
        assert pending["arguments_hash"] == canonical_args(args)
        mgr.decide(pending["id"], allow=True, approver="tester")
        res = await call_task
        assert not res.is_error, res.content[0].text
        # repeat call hits the grant -> hash bound to real args works
        res = await session.call_tool("demo--write_file", args)
        assert not res.is_error


# ---- I2: agent header routing ----

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_agent_header_routing(workdir):
    port = _free_port()
    cfg = write_config(workdir)
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "run", "--config", str(cfg), "--agent", "all",
         "--http", f"127.0.0.1:{port}", "--trust-agent-header"],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        # raw-HTTP probe of the fail-closed behavior + per-agent routing
        deadline = time.monotonic() + 20
        got = {}
        while time.monotonic() < deadline and len(got) < 3:
            try:
                async with httpx2.AsyncClient(timeout=3) as client:
                    r_none = await client.post(f"{base}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
                    r_bad = await client.post(f"{base}/mcp", headers={"X-Agentgate-Agent": "ghost"},
                                              json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
                    r_ok = await client.get(f"{base}/mcp", headers={"X-Agentgate-Agent": "bot"})
                    got = {"none": r_none.status_code, "bad": r_bad.status_code, "ok": r_ok.status_code}
            except Exception:  # noqa: BLE001
                await asyncio.sleep(0.4)
        assert got["none"] == 401 and got["bad"] == 401, got
        assert got["ok"] != 401, got  # known identity passes the auth gate

        # full MCP session with the header (streamable-http per-request headers)
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client, create_mcp_http_client

        client = create_mcp_http_client(headers={"X-Agentgate-Agent": "bot"})
        async with streamable_http_client(f"{base}/mcp", http_client=client) as (read, write):
            async with ClientSession(read, write) as session:
                await asyncio.wait_for(session.initialize(), timeout=10)
                res = await session.call_tool("demo--echo", {"text": "via-header"})
                assert not res.is_error and "echo: via-header" in res.content[0].text
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_trust_header_requires_all_and_http(tmp_path):
    cfg = write_config(tmp_path)
    from agentgate.config import load_config
    from agentgate.gateway import serve
    with pytest.raises(ValueError):
        asyncio.run(serve(load_config(cfg), "all", state_dir=str(tmp_path / "s"),
                          config_path=str(cfg)))  # all without --http
    with pytest.raises(ValueError):
        asyncio.run(serve(load_config(cfg), "bot", state_dir=str(tmp_path / "s"),
                          config_path=str(cfg), trust_agent_header=True))  # header without all
