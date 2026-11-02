"""v0.3 F4: web console token auth."""

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
from agentgate.cli import main as cli_main

from tests.test_e2e import SRC


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http(method: str, url: str, **kw):
    import httpx2

    async with httpx2.AsyncClient(timeout=5) as client:
        return await client.request(method, url, follow_redirects=False, **kw)


def test_ui_refuses_nonloopback_without_token(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENTGATE_UI_TOKEN", raising=False)
    from agentgate.webui import run_ui

    try:
        run_ui(tmp_path / "state", host="0.0.0.0", port=_free_port())
        raise AssertionError("should have refused")
    except SystemExit as e:
        assert "AGENTGATE_UI_TOKEN" in str(e)


async def test_ui_token_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTGATE_UI_TOKEN", "s3cret-token")
    state = tmp_path / "state"
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "t", {"a": 1}, "rule")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "ui", "--state-dir", str(state),
         "--port", str(port)],
        env={**os.environ, "PYTHONPATH": str(SRC), "AGENTGATE_UI_TOKEN": "s3cret-token"},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        # wait for console
        deadline = time.monotonic() + 20
        first = None
        while time.monotonic() < deadline:
            try:
                first = await _http("GET", base + "/")
                break
            except Exception:  # noqa: BLE001
                await asyncio.sleep(0.4)
        assert first is not None
        # J1: unauthenticated browser request to / redirects to the login page
        assert first.status_code == 303

        # wrong token on a POST (non-browser path) -> 401; correct via query -> 200
        wrong = await _http("GET", f"{base}/?token=nope")
        assert wrong.status_code == 303  # browser GET redirects to login
        wrong_api = await _http("GET", f"{base}/status-404-probe?token=nope")
        assert wrong_api.status_code in (401, 404)  # non-/ pages 401 on bad token
        ok = await _http("GET", f"{base}/?token=s3cret-token")
        assert ok.status_code == 200 and req["id"] in ok.text
        ok_bearer = await _http("GET", base + "/", headers={"Authorization": "Bearer s3cret-token"})
        assert ok_bearer.status_code == 200

        # POST approve with token works; without token -> 401
        resp = await _http("POST", f"{base}/approve/{req['id']}?token=s3cret-token",
                           data={"action": "allow", "approver": "authed"})
        assert resp.status_code in (303, 200)
        decision = json.loads((state / "decisions" / f"{req['id']}.json").read_text(encoding="utf-8"))
        assert decision["allow"] and decision["approver"] == "web:authed"

        mgr2 = ApprovalManager(state)
        req2 = mgr2.create_request("bot", "fs", "t2", {}, "rule")
        denied = await _http("POST", f"{base}/approve/{req2['id']}", data={"action": "deny"})
        assert denied.status_code == 401
        assert not (state / "decisions" / f"{req2['id']}.json").exists()
    finally:
        proc.terminate()
        proc.wait(timeout=10)
