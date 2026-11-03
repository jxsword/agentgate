"""v0.6 R-batch: regression tests for the independent code review findings."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml

from agentgate.cli import main
from agentgate.approvals import ApprovalManager
from agentgate.audit import AuditLog
from agentgate.config import Config
from agentgate.config import load_config
from agentgate.grants import GrantStore
from agentgate.policy import PolicyEngine
from agentgate.ratelimit import RateLimiter

from tests.test_e2e import open_session, write_config


# P1-2: retire on hot-reload is fail-closed

def test_reload_retires_removed_agent(tmp_path):
    cfg_path = tmp_path / "p.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "allow"}}}},
                   "gone": {"servers": {"fs": {"tools": {"echo": "allow"}}}}},
    }), encoding="utf-8")
    from agentgate.gateway import Gateway

    def mk(agent):
        cfg = load_config(cfg_path)
        return Gateway(cfg, agent, PolicyEngine(cfg),
                       ApprovalManager(tmp_path / "state"),
                       GrantStore(tmp_path / "state" / "g.json"),
                       AuditLog(tmp_path / "state" / "a.jsonl"),
                       config_path=str(cfg_path), watch_policy=True)

    gw_gone = mk("gone")
    gw_bot = mk("bot")
    # rewrite: "gone" agent removed
    cfg_path.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "allow"}}}}},
    }), encoding="utf-8")
    import os

    mtime = cfg_path.stat().st_mtime
    os.utime(cfg_path, (mtime + 10, mtime + 10))
    gw_gone._reload_policy_once(cfg_path, mtime - 5)
    gw_bot._reload_policy_once(cfg_path, mtime - 5)
    assert gw_gone.retired is True
    assert gw_bot.retired is False


# P1-3: truncated decision file is retried, not fatal

async def test_wait_tolerates_truncated_decision(tmp_path):
    mgr = ApprovalManager(tmp_path / "state")
    req = mgr.create_request("bot", "fs", "t", None, "rule")

    async def flaky_writer():
        await asyncio.sleep(0.3)
        d = tmp_path / "state" / "decisions" / f"{req['id']}.json"
        d.write_text("{truncat", encoding="utf-8")  # first poll sees garbage
        await asyncio.sleep(0.3)
        d.write_text(json.dumps({"id": req["id"], "allow": True, "approver": "x"}), encoding="utf-8")

    task = asyncio.create_task(flaky_writer())
    decision = await mgr.wait(req["id"], timeout_seconds=5)
    await task
    assert decision["allow"] is True


# P2-7: rate limit hot-reload applies new config

def test_rate_limiter_uses_current_config():
    from agentgate.config import RateLimit

    class FakePolicy:
        rate_limit = None

    configs = {"v1": RateLimit(calls=2, window_seconds=60)}
    pol = FakePolicy()
    pol.rate_limit = configs["v1"]
    limiter = RateLimiter()
    limiter.bind(lambda a, s: pol)
    limiter.check_and_record("bot", "fs", now=1000)
    limiter.check_and_record("bot", "fs", now=1000)
    assert limiter.check_and_record("bot", "fs", now=1001).limited
    # operator tightens the limit via hot-reload; same in-flight window now uses calls=1
    pol.rate_limit = RateLimit(calls=1, window_seconds=60)
    limiter.check_and_record("bot", "fs", now=1002)
    assert limiter.check_and_record("bot", "fs", now=1003).limited


# P2-13: grant matches tool name exactly (no glob widening)

def test_grant_exact_tool_match(tmp_path):
    store = GrantStore(tmp_path / "g.json")
    store.add("bot", "fs", "w*", None, ttl_seconds=60, bind="tool")
    engine = PolicyEngine(Config(default_decision="deny"), store)
    # an approval for literal tool "w*" must NOT widen to wild/whatever
    assert engine.evaluate("bot", "fs", "wild", {}).action == "deny"
    assert engine.evaluate("bot", "fs", "w*", {}).action == "grant"


# P2-14: redact recurses into lists

def test_redact_recurses_lists():
    from agentgate.config import ServerPolicy

    spol = ServerPolicy(default="ask", redact=["token"])
    out = spol.redact_arguments({"items": [{"token": "x"}, {"name": "n"}]})
    assert out["items"][0]["token"] == "***"
    assert out["items"][1]["name"] == "n"


# P2-11: naive --since doesn't crash

def test_log_since_naive_datetime(tmp_path, capsys):
    state = tmp_path / "state"
    AuditLog(state / "audit.jsonl").append("e1")
    rc = main(["log", "--since", "2020-01-01", "--state-dir", str(state)])
    assert rc == 0  # no TypeError traceback
    assert "e1" in capsys.readouterr().out
