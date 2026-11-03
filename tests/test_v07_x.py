"""v0.7 X: web console grant usage column."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from agentgate.audit import AuditLog
from agentgate.grants import GrantStore

from tests.test_e2e import SRC


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http(method, url, **kw):
    import httpx2

    async with httpx2.AsyncClient(timeout=5) as client:
        return await client.request(method, url, follow_redirects=False, **kw)


async def test_console_shows_grant_uses(tmp_path):
    state = tmp_path / "state"
    store = GrantStore(state / "grants.json")
    g = store.add("bot", "fs", "write_file", None, ttl_seconds=600, bind="tool")
    log = AuditLog(state / "audit.jsonl")
    for _ in range(3):
        log.append("call", agent="bot", server="fs", tool="write_file",
                   decision="grant", grant_id=g.id)
    # one call that didn't use the grant
    log.append("call", agent="bot", server="fs", tool="write_file", decision="ask_allowed")

    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentgate", "ui", "--state-dir", str(state),
         "--port", str(port)],
        env={**os.environ, "PYTHONPATH": str(SRC)},
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        page = None
        while time.monotonic() < deadline:
            try:
                resp = await _http("GET", base + "/")
                if resp.status_code == 200:  # console ready (uvicorn lifespan settled)
                    page = resp
                    break
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.4)
        assert page and page.status_code == 200
        body = page.text
        assert g.id in body
        # usage column present with the correct count (grants table region)
        assert "uses" in body
        # the grants table contains a row with the scope and a 3-use cell
        grants_table = body.split("Active grants")[1] if "Active grants" in body else body
        assert "<td>3</td>" in grants_table
        assert "bot@fs--write_file" in grants_table
    finally:
        proc.terminate()
        proc.wait(timeout=10)
