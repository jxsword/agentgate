"""v0.3 F3: sliding-window rate limiting."""

from __future__ import annotations

import json

import pytest
import yaml

from agentgate.config import ConfigError, RateLimit, load_config
from agentgate.ratelimit import RateLimiter

from tests.test_e2e import open_session, write_config


class _FakePolicy:
    def __init__(self, rl):
        self.rate_limit = rl


def test_limiter_blocks_after_window_full():
    rl = RateLimit(calls=3, window_seconds=60)
    limiter = RateLimiter()
    limiter.bind(lambda a, s: _FakePolicy(rl) if s == "fs" else None)
    t0 = 1000.0
    assert not limiter.check_and_record("bot", "fs", now=t0).limited
    assert not limiter.check_and_record("bot", "fs", now=t0 + 1).limited
    assert not limiter.check_and_record("bot", "fs", now=t0 + 2).limited  # 3rd fills the window
    result = limiter.check_and_record("bot", "fs", now=t0 + 3)  # 4th is over
    assert result.limited, result
    assert result.limit == 3 and result.retry_after >= 1
    # different server unaffected
    assert not limiter.check_and_record("bot", "other", now=t0).limited


def test_limiter_window_slides():
    from agentgate.config import RateLimit

    limiter = RateLimiter()
    limiter.bind(lambda a, s: _FakePolicy(RateLimit(calls=1, window_seconds=10)) if s == "fs" else None)
    assert not limiter.check_and_record("bot", "fs", now=100).limited
    assert limiter.check_and_record("bot", "fs", now=105).limited
    # after the window slides, allowed again
    assert not limiter.check_and_record("bot", "fs", now=111).limited


def test_limiter_no_config_is_unlimited():
    limiter = RateLimiter()
    limiter.bind(lambda a, s: None)
    for _ in range(100):
        assert not limiter.check_and_record("bot", "fs").limited


def test_rate_limit_config_validation(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1,
        "agents": {"bot": {"servers": {"fs": {
            "rate_limit": {"calls": 5}}}}},  # missing window_seconds
    }), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)


async def test_rate_limit_e2e(workdir):
    cfg = write_config(workdir)
    doc = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    doc["agents"]["bot"]["servers"]["demo"]["rate_limit"] = {"calls": 2, "window_seconds": 60}
    cfg.write_text(yaml.safe_dump(doc), encoding="utf-8")

    async with open_session(workdir, cfg) as (session, init):
        for i in range(2):
            res = await session.call_tool("demo--echo", {"text": f"n{i}"})
            assert not res.is_error, res.content[0].text
        res = await session.call_tool("demo--echo", {"text": "n3"})
        assert res.is_error
        assert "rate limit" in res.content[0].text and "Retry after" in res.content[0].text
        # explicit deny is unaffected by the limiter (still policy-denied, not rate-limited)
        res = await session.call_tool("demo--delete_file", {"path": "x"})
        assert res.is_error and "denied by policy" in res.content[0].text
        events = [json.loads(l) for l in
                  (workdir / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "rate_limited" for e in events)
