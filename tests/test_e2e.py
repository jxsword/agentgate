"""End-to-end tests: real gateway subprocess (stdio) + real demo upstream.

Topology per test (matches docs/design.md §8):

    ClientSession --stdio--> agentgate run (subprocess) --stdio--> demo_server.py (subprocess)

Covers: namespaced aggregation, allow pass-through, deny fail-closed,
ask -> human approval -> scoped grant -> grant hit, on_ask=deny,
upstream fault isolation, audit reconciliation (NFR-SEC-002), perf smoke.
"""

from __future__ import annotations

import asyncio
import json
import os
import statistics
import sys
import time
from pathlib import Path

import mcp_types as types
import pytest
import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentgate.approvals import ApprovalManager

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"
DEMO_SERVER = PROJECT_ROOT / "examples" / "demo_server.py"


def write_config(workdir: Path, *, on_ask: str = "pending", broken_upstream: bool = False) -> Path:
    sandbox = workdir / "sandbox"
    sandbox.mkdir(exist_ok=True)
    servers: dict = {
        "demo": {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(DEMO_SERVER)],
            "env": {"DEMO_SANDBOX": str(sandbox)},
        }
    }
    if broken_upstream:
        servers["broken"] = {
            "transport": "stdio",
            "command": sys.executable,
            "args": ["-c", "import sys; sys.exit(3)"],  # dies immediately
        }
    doc = {
        "version": 1,
        "default_decision": "deny",
        "on_ask": on_ask,
        "ask_timeout_seconds": 60,
        "state_dir": str(workdir / "state"),
        "servers": servers,
        "agents": {
            "bot": {
                "servers": {
                    "demo": {
                        "default": "ask",
                        "tools": {
                            "echo": "allow",
                            "write_file": {
                                "decision": "ask",
                                "args_match": {"path": "*sandbox*"},
                                "delegation": {"ttl_seconds": 600, "bind": "tool+args"},
                            },
                            "delete_file": "deny",
                        },
                    }
                }
            }
        },
    }
    cfg = workdir / "policy.yaml"
    cfg.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return cfg


def gateway_params(cfg: Path) -> StdioServerParameters:
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentgate", "run", "--config", str(cfg), "--agent", "bot",
              "--ask-timeout", "60"],
        env=env,
    )


def text_of(result: types.CallToolResult) -> str:
    return "\n".join(getattr(c, "text", "") for c in result.content)


async def decide_when_pending(workdir: Path, allow: bool, timeout: float = 20.0) -> str:
    """Wait for the gateway to file a pending approval, then decide it via the
    same code path as `agentgate approve`."""
    state = workdir / "state"
    mgr = ApprovalManager(state)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = mgr.list_pending()
        if pending and "id" in pending[0]:
            req_id = pending[0]["id"]
            mgr.decide(req_id, allow=allow, approver="tester")
            return req_id
        await asyncio.sleep(0.1)
    raise TimeoutError("no pending approval request appeared")


from contextlib import asynccontextmanager


@asynccontextmanager
async def open_session(workdir: Path, cfg: Path):
    async with stdio_client(gateway_params(cfg)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await asyncio.wait_for(session.initialize(), timeout=30)
            yield session, init


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """Per-test workspace (defined in conftest.py; kept for direct imports)."""
    return tmp_path


async def test_full_flow(workdir: Path):
    cfg = write_config(workdir)
    started = time.monotonic()
    async with open_session(workdir, cfg) as (session, init):
        init_elapsed = time.monotonic() - started
        assert init.server_info.name == "agentgate-bot"

        # NFR-PERF-001 smoke (measured, generous bound to stay CI-safe)
        assert init_elapsed < 15, f"gateway took {init_elapsed:.1f}s to become ready"

        # FR-GW-002/003: namespaced aggregation
        tools = await session.list_tools()
        names = [t.name for t in tools.tools]
        assert "demo--echo" in names and "demo--write_file" in names
        assert all(n.startswith("demo--") for n in names)

        # FR-GW-004 allow: pass-through
        res = await session.call_tool("demo--echo", {"text": "hello"})
        assert not res.is_error
        assert "echo: hello" in text_of(res)

        # FR-GW-005 deny: fail-closed with readable reason
        res = await session.call_tool("demo--delete_file", {"path": "x.txt"})
        assert res.is_error
        assert "denied by policy" in text_of(res)
        assert "delete_file" in text_of(res)  # names the matched rule pattern

        # FR-AP-001/002/003: ask -> human approve -> grant -> proxy
        args = {"path": "sandbox/notes/todo.txt", "content": "hello agentgate"}
        call_task = asyncio.create_task(session.call_tool("demo--write_file", args))
        req_id = await decide_when_pending(workdir, allow=True)
        res = await call_task
        assert not res.is_error, text_of(res)
        assert "wrote" in text_of(res)

        state = workdir / "state"
        audit_lines = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        events = [json.loads(l) for l in audit_lines]
        assert any(e["event"] == "grant_created" for e in events)
        grant_id = next(e["grant_id"] for e in events if e["event"] == "grant_created")
        assert any(e["event"] == "call" and e.get("decision") == "ask_allowed" for e in events)

        # FR-AP-003: identical repeat call hits the grant (no new pending)
        res = await session.call_tool("demo--write_file", args)
        assert not res.is_error, text_of(res)
        events = [json.loads(l) for l in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "call" and e.get("decision") == "grant"
                   and e.get("grant_id") == grant_id for e in events)
        assert not (state / "pending").exists() or not list((state / "pending").glob("*.json"))

        # different args with bind=tool+args -> new ask; human denies this time
        call_task = asyncio.create_task(
            session.call_tool("demo--write_file", {**args, "content": "evil"})
        )
        req_id2 = await decide_when_pending(workdir, allow=False)
        assert req_id2 != req_id
        res = await call_task
        assert res.is_error
        assert "denied" in text_of(res)

        # NFR-SEC-002: every tool call left >= 1 decision audit record
        calls_made = 5  # echo, delete, write(allow), write(grant), write(denied)
        events = [json.loads(l) for l in (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        decision_events = [e for e in events if e["event"] in ("call", "call_denied", "ask_denied")]
        assert len(decision_events) >= calls_made

        # FR-GW-005: unknown tool / unknown namespace fail closed
        res = await session.call_tool("no_such_tool", {})
        assert res.is_error
        res = await session.call_tool("echo", {})  # missing namespace
        assert res.is_error


async def test_on_ask_deny_unattended(workdir: Path):
    cfg = write_config(workdir, on_ask="deny")
    async with open_session(workdir, cfg) as (session, init):
        # FR-AP-005: unattended mode fails closed without pending files
        res = await session.call_tool("demo--write_file", {"path": "sandbox/a.txt", "content": "x"})
        assert res.is_error
        assert "unattended" in text_of(res) or "on_ask" in text_of(res)
        state = workdir / "state"
        assert not list((state / "pending").glob("*.json"))


async def test_upstream_fault_isolation(workdir: Path):
    cfg = write_config(workdir, broken_upstream=True)
    async with open_session(workdir, cfg) as (session, init):
        # FR-GW-006: broken upstream does not kill gateway; healthy one still serves
        tools = await session.list_tools()
        names = [t.name for t in tools.tools]
        assert "demo--echo" in names
        res = await session.call_tool("demo--echo", {"text": "still-alive"})
        assert not res.is_error
        events = [json.loads(l) for l in
                  (workdir / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "upstream_error" and e.get("server") == "broken" for e in events)


async def test_perf_smoke(workdir: Path):
    """NFR-PERF-002 smoke: 100 echoed calls, report P95 (bound includes the
    upstream subprocess round-trip; gateway-only overhead is smaller)."""
    cfg = write_config(workdir)
    async with open_session(workdir, cfg) as (session, init):
        latencies = []
        for i in range(100):
            t0 = time.monotonic()
            res = await session.call_tool("demo--echo", {"text": f"m{i}"})
            latencies.append(time.monotonic() - t0)
            assert not res.is_error
        p95 = statistics.quantiles(latencies, n=20)[-1]
        print(f"\n[perf] 100 calls: mean={statistics.mean(latencies)*1000:.1f}ms "
              f"p95={p95*1000:.1f}ms max={max(latencies)*1000:.1f}ms")
        assert p95 < 0.5, f"p95 {p95*1000:.0f}ms exceeds 500ms smoke bound"
