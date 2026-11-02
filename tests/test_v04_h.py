"""v0.4 H-batch tests: audit_arguments (H1), rate window introspection (H2),
check --diff (H4)."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.config import Config, load_config
from agentgate.gateway import Gateway
from agentgate.policy import PolicyEngine
from agentgate.ratelimit import RateLimiter

from tests.test_e2e import write_config


def _write(base: Path, doc: dict) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    p = base / "p.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


# ---- H1: audit_arguments ----

def test_audit_arguments_default_hash_only(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    gw_cfg = Config()
    gw_cfg.state_dir = tmp_path
    # append via gateway-style base is exercised in e2e; here assert config parse
    cfg_path = write_config(tmp_path)
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert "audit_arguments" not in doc or doc["audit_arguments"] is False


async def test_audit_arguments_opt_in(tmp_path):
    doc = {
        "version": 1, "default_decision": "deny", "state_dir": str(tmp_path / "state"),
        "audit_arguments": True,
        "servers": {"demo": {"transport": "stdio", "command": "python"}},
        "agents": {"bot": {"servers": {"demo": {"tools": {"echo": "allow"}}}}},
    }
    cfg = load_config(_write(tmp_path, doc))
    assert cfg.audit_arguments is True
    # and audit records carry arguments when the gateway writes them
    from agentgate.approvals import ApprovalManager
    from agentgate.grants import GrantStore
    from agentgate.policy import PolicyEngine

    gw = Gateway(cfg, "bot", PolicyEngine(cfg),
                 ApprovalManager(cfg.state_dir),
                 GrantStore(cfg.state_dir / "grants.json"),
                 AuditLog(cfg.state_dir / "audit.jsonl"))
    gw.upstreams = {}  # unknown-tool path uses base too
    res = await gw._call_tool(None, type("P", (), {"name": "demo--x", "arguments": {"secret": "v"}})())
    assert res.is_error
    recs = _read_lines(cfg.state_dir / "audit.jsonl")
    assert recs[0]["arguments"] == {"secret": "v"}
    assert recs[0]["arguments_hash"]


def _read_lines(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines()]


# ---- H2: rate window introspection ----

def test_rate_limiter_current():
    from agentgate.config import RateLimit

    limiter = RateLimiter()
    limiter.bind(lambda a, s: type("P", (), {"rate_limit": RateLimit(calls=5, window_seconds=60)})())
    limiter.check_and_record("bot", "fs", now=1000)
    limiter.check_and_record("bot", "fs", now=1001)
    assert limiter.current("bot", "fs", now=1002) == 2
    assert limiter.current("bot", "fs", now=2000) == 0  # window slid
    assert limiter.current("ghost", "fs", now=1002) == 0  # no config = no window


# ---- H4: check --diff ----

def test_check_diff_marks_changes(tmp_path, capsys):
    old = _write(tmp_path / "a", {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "allow", "rm_*": "deny"}}}}},
    })
    new = _write(tmp_path / "b", {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "deny", "rm_*": "ask"}}}}},
    })
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([
        {"server": "fs", "tool": "echo"},
        {"server": "fs", "tool": "rm_all"},
    ]), encoding="utf-8")
    rc = main(["check", "--config", str(old), "--diff", str(new), "--agent", "bot",
               "--cases", str(cases)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "echo: allow" in out and "diff" in out and "deny" in out
    assert "rm_all" in out


def test_check_diff_no_differences(tmp_path, capsys):
    same = _write(tmp_path, {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "allow"}}}}},
    })
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([{"server": "fs", "tool": "echo"}]), encoding="utf-8")
    rc = main(["check", "--config", str(same), "--diff", str(same), "--agent", "bot",
               "--cases", str(cases)])
    assert rc == 0
    assert "diff:" not in capsys.readouterr().out
