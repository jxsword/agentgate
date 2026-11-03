"""v0.8 T3: console pending 'requested' column (created time + wait duration)."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from agentgate.approvals import ApprovalManager

from tests.test_e2e import SRC


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _http(method, url, **kw):
    import httpx2

    async with httpx2.AsyncClient(timeout=5) as client:
        return await client.request(method, url, follow_redirects=False, **kw)


async def test_console_shows_wait_duration(tmp_path):
    state = tmp_path / "state"
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "write_file", {"path": "a"}, "rule")
    # age the pending file to 3 minutes ago
    p = state / "pending" / f"{req['id']}.json"
    stat = p.stat()
    old = time.time() - 180
    os.utime(p, (old, old))
    # note: wait duration uses the created_at string inside the file, not mtime;
    # rewrite created_at to 3 minutes ago
    import json as _json

    raw = _json.loads(p.read_text(encoding="utf-8"))
    raw["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(old))
    p.write_text(_json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

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
                if resp.status_code == 200:
                    page = resp.text
                    break
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.4)
        assert page, "console did not come up"
        assert "waiting 3m" in page or "waiting 2m" in page  # duration rendered
        assert "requested" in page  # column header
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_wait_duration_helper():
    from agentgate.webui import _wait_duration

    now = time.time()
    import datetime as _dt

    fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t))
    assert _wait_duration(fmt(now - 30)) == "waiting 30s"
    assert _wait_duration(fmt(now - 180)) == "waiting 3m00s"
    assert _wait_duration(fmt(now - 7200)) == "waiting 2h00m"
    assert _wait_duration("garbage") == ""
