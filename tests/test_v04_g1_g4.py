"""v0.4 tests: validate (G1), stale-pending cleanup (G2), denial reason (G3),
health/status endpoints (G4)."""

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
from agentgate.cli import main

from tests.test_e2e import SRC, open_session, write_config


# ---- G1: validate ----

def test_validate_ok(tmp_path, capsys):
    cfg = write_config(tmp_path)
    rc = main(["validate", "--config", str(cfg)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK: 1 server(s), 1 agent(s)" in out and "server demo: stdio" in out


def test_validate_invalid(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nagents: {bot: {servers: {fs: {tools: {x: maybe}}}}}\n",
                   encoding="utf-8")
    rc = main(["validate", "--config", str(bad)])
    assert rc == 1
    assert "INVALID" in capsys.readouterr().err


# ---- G2: stale pending cleanup ----

def test_cleanup_stale_removes_old_only(tmp_path):
    mgr = ApprovalManager(tmp_path / "state")
    old = mgr.create_request("bot", "fs", "t1", None, "r")
    fresh = mgr.create_request("bot", "fs", "t2", None, "r")
    # age the first file artificially
    old_t = time.time() - 10_000
    os.utime(tmp_path / "state" / "pending" / f"{old['id']}.json", (old_t, old_t))
    removed = mgr.cleanup_stale(max_age_seconds=300)
    assert removed == 1
    assert not (tmp_path / "state" / "pending" / f"{old['id']}.json").exists()
    assert (tmp_path / "state" / "pending" / f"{fresh['id']}.json").exists()


async def test_gateway_cleans_stale_on_start(workdir):
    mgr = ApprovalManager(workdir / "state")
    stale = mgr.create_request("bot", "demo", "x", None, "r")
    old_t = time.time() - 10_000
    os.utime(workdir / "state" / "pending" / f"{stale['id']}.json", (old_t, old_t))
    cfg = write_config(workdir)
    async with open_session(workdir, cfg) as (session, init):
        assert not (workdir / "state" / "pending" / f"{stale['id']}.json").exists()
        events = [json.loads(l) for l in
                  (workdir / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "pending_cleanup" for e in events)


# ---- G3: denial reason ----

def test_decide_with_reason_and_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_APPROVAL_SECRET", "sec")
    mgr = ApprovalManager(tmp_path / "state")
    req = mgr.create_request("bot", "fs", "t", {"x": 1}, "rule")
    decision = mgr.decide(req["id"], allow=False, approver="alice", reason="not on fridays")
    assert decision["reason"] == "not on fridays"
    from agentgate.approvals import verify_decision
    assert verify_decision(req, decision, "sec")
    # tampering with the reason invalidates the signature
    tampered = {**decision, "reason": "something else"}
    assert not verify_decision(req, tampered, "sec")


async def test_denial_reason_reaches_agent(workdir):
    cfg = write_config(workdir)
    async with open_session(workdir, cfg) as (session, init):
        args = {"path": "sandbox/reason.txt", "content": "x"}
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
        mgr.decide(pending["id"], allow=False, approver="alice", reason="do it yourself")
        res = await call_task
        assert res.is_error
        assert "Reason: do it yourself" in res.content[0].text


def test_cli_approve_reason(tmp_path):
    state = str(tmp_path / "state")
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "t", None, "r")
    assert main(["approve", req["id"], "--deny", "--reason", "nope", "--state-dir", state]) == 0
    decision = json.loads((tmp_path / "state" / "decisions" / f"{req['id']}.json").read_text(encoding="utf-8"))
    assert decision["reason"] == "nope"


# ---- G4: health/status ----

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_health_status_endpoints(workdir):
    port = _free_port()
    cfg = write_config(workdir)
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "run", "--config", str(cfg), "--agent", "bot",
         "--http", f"127.0.0.1:{port}"],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        import httpx2

        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        health = status = None
        while time.monotonic() < deadline and (health is None or status is None):
            try:
                async with httpx2.AsyncClient(timeout=3) as client:
                    r1 = await client.get(f"{base}/healthz")
                    health = r1 if r1.status_code == 200 else None
                    r2 = await client.get(f"{base}/status")
                    status = r2 if r2.status_code == 200 else None
            except Exception:  # noqa: BLE001
                await asyncio.sleep(0.4)
        assert health and health.json()["ok"] is True
        body = status.json()
        assert body["agent"] == "bot" and body["upstreams"]["demo"] == "demo-server"
        assert body["on_ask"] == "pending"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
