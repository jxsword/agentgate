"""v0.7 Q+R batch tests: audit multi-writer safety, orphan cleanup,
Prometheus /metrics endpoint."""

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
from agentgate.approvals import ApprovalManager
from agentgate.cli import main
from agentgate.gateway import Gateway
from agentgate.config import Config
from agentgate.policy import PolicyEngine
from agentgate.approvals import ApprovalManager as _AM
from agentgate.grants import GrantStore

from tests.test_e2e import SRC, open_session, write_config


# Q1: rotation names unique (cross-process simulated via distinct suffixes)

def test_rotation_names_unique(tmp_path):
    log1 = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log1.append("e1")
    # second writer in the same process: force a distinct rotated name by
    # checking the rotate loop's collision counter path
    log2 = AuditLog(tmp_path / "audit.jsonl", max_bytes=1)
    log2.append("e2")
    names = [p.name for p in tmp_path.glob("audit-*.jsonl")]
    assert len(names) == len(set(names)), names  # no silent overwrite
    assert len(names) >= 1


# Q2: orphan decisions swept by cleanup_stale

def test_cleanup_sweeps_orphan_decisions(tmp_path):
    mgr = ApprovalManager(tmp_path / "state")
    req = mgr.create_request("bot", "fs", "t", None, "r")
    mgr.decide(req["id"], allow=True)  # decision written; pending removed by gateway later
    # simulate gateway already consumed: pending gone, decision lingers, aged
    d = tmp_path / "state" / "decisions" / f"{req['id']}.json"
    old = time.time() - 10_000
    os.utime(d, (old, old))
    removed = mgr.cleanup_stale(max_age_seconds=300)
    assert removed == 1
    assert not d.exists()


# R: /metrics

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_metrics_endpoint(workdir):
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
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client
        from contextlib import asynccontextmanager

        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        session = None
        while time.monotonic() < deadline and session is None:
            try:
                cm = streamable_http_client(f"{base}/mcp")
                read, write = await asyncio.wait_for(cm.__aenter__(), timeout=3)
                sm = ClientSession(read, write)
                await sm.__aenter__()
                await asyncio.wait_for(sm.initialize(), timeout=5)
                session = (cm, sm)
            except Exception:  # noqa: BLE001
                try:
                    if "sm" in dir() and sm:
                        await sm.__aexit__(None, None, None)
                except Exception:  # noqa: BLE001
                    pass
                session = None
                await asyncio.sleep(0.4)
        assert session, "gateway did not come up"
        cm, sm = session
        try:
            await sm.call_tool("demo--echo", {"text": "m1"})
            await sm.call_tool("demo--delete_file", {"path": "x"})  # denied
            metrics = None
            for _ in range(10):
                async with httpx2.AsyncClient(timeout=3) as client:
                    r = await client.get(f"{base}/metrics")
                if r.status_code == 200 and "agentgate_tool_calls_total" in r.text:
                    metrics = r.text
                    break
                await asyncio.sleep(0.3)
            assert metrics, "metrics endpoint did not return prometheus text"
            assert 'outcome="allowed"' in metrics
            assert 'outcome="denied"' in metrics
            assert 'agentgate_upstreams_up{server="demo"} 1' in metrics
        finally:
            await sm.__aexit__(None, None, None)
            await cm.__aexit__(None, None, None)
    finally:
        proc.terminate()
        proc.wait(timeout=10)
