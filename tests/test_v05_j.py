"""v0.5 J-batch tests: console session cookie (J1), log follow (J2)."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from agentgate.approvals import ApprovalManager
from agentgate.audit import AuditLog
from agentgate.cli import main

from tests.test_e2e import SRC


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http(method, url, **kw):
    import httpx2

    async with httpx2.AsyncClient(timeout=5) as client:
        return await client.request(method, url, follow_redirects=False, **kw)


async def test_console_session_login_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_UI_TOKEN", "tok-123")
    state = tmp_path / "state"
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "t", {}, "rule")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "ui", "--state-dir", str(state),
         "--port", str(port)],
        env={**os.environ, "PYTHONPATH": str(SRC), "AGENTGATE_UI_TOKEN": "tok-123"},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 20
        ready = False
        while time.monotonic() < deadline:
            try:
                r = await _http("GET", base + "/login")
                if r.status_code == 200:  # console ready (uvicorn lifespan settled)
                    ready = True
                    break
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.4)
        assert ready

        # unauthenticated / redirects to /login (browser-friendly)
        r = await _http("GET", base + "/")
        assert r.status_code == 303

        # wrong token -> back to /login, no cookie
        r = await _http("POST", base + "/login", data={"token": "wrong"})
        assert r.status_code == 303 and "agentgate_ui" not in r.cookies

        # correct token -> session cookie set
        r = await _http("POST", base + "/login", data={"token": "tok-123"})
        assert r.status_code == 303
        cookie = r.cookies.get("agentgate_ui")
        assert cookie == "tok-123"

        # cookie alone grants access (no URL token needed)
        r = await _http("GET", base + "/", cookies={"agentgate_ui": "tok-123"})
        assert r.status_code == 200 and req["id"] in r.text

        # POST forms work with cookie only
        r = await _http("POST", f"{base}/approve/{req['id']}",
                        cookies={"agentgate_ui": "tok-123"},
                        data={"action": "allow", "approver": "webby"})
        assert r.status_code in (303, 200)

        # logout clears the session
        r = await _http("GET", base + "/logout", cookies={"agentgate_ui": "tok-123"})
        assert r.status_code == 303
        r = await _http("GET", base + "/", cookies={"agentgate_ui": ""})
        assert r.status_code == 303  # back to login
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_log_follow_prints_new_records(tmp_path, capsys):
    """_follow prints records appended after startup (run it as a short task)."""
    import threading

    state = tmp_path / "state"
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", tool="t0", decision="allow")

    from agentgate.cli import _follow

    stop = threading.Event()
    original_sleep = time.sleep

    def sleeper(_):
        # after the first poll, append a new record then let the next poll see it;
        # second poll raises KeyboardInterrupt to end the follow loop
        if not stop.is_set():
            log.append("call", agent="bot", tool="t1", decision="allow")
            stop.set()
        else:
            raise KeyboardInterrupt
        original_sleep(0.01)

    import agentgate.cli as cli

    saved = cli.time if hasattr(cli, "time") else None
    # _follow uses time via its local import; patch module-level time.sleep used there
    import time as time_mod

    real_sleep = time_mod.sleep
    time_mod.sleep = sleeper
    try:
        _follow(state / "audit.jsonl", {}, None)
    finally:
        time_mod.sleep = real_sleep
    out = capsys.readouterr().out
    recs = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    assert any(r.get("tool") == "t1" for r in recs)  # appended record was followed
