"""v0.7 V: extends absolute paths + log --jsonl."""

from __future__ import annotations

import json

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.config import ConfigError, load_config


def test_extends_absolute_path(tmp_path):
    import yaml

    base = tmp_path / "base.yaml"
    base.write_text(yaml.safe_dump({
        "version": 1,
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "allow"}}}}},
    }), encoding="utf-8")
    child = tmp_path / "child.yaml"
    child.write_text(yaml.safe_dump({
        "extends": str(base),  # absolute
        "agents": {"bot": {"servers": {"fs": {"tools": {"echo": "deny"}}}}},
    }), encoding="utf-8")
    cfg = load_config(child)
    from agentgate.policy import PolicyEngine

    assert PolicyEngine(cfg).evaluate("bot", "fs", "echo", {}).action == "deny"


def test_extends_absolute_missing(tmp_path):
    import yaml

    child = tmp_path / "child.yaml"
    child.write_text(yaml.safe_dump({"version": 1, "extends": "/nope/base.yaml"}),
                     encoding="utf-8")
    try:
        load_config(child)
        raise AssertionError("should fail")
    except ConfigError as e:
        assert "not found" in str(e)


def test_log_jsonl_sorted_keys(tmp_path, capsys):
    state = tmp_path / "state"
    AuditLog(state / "audit.jsonl").append("call", agent="bot", tool="echo")
    rc = main(["log", "--jsonl", "--state-dir", str(state)])
    assert rc == 0
    line = capsys.readouterr().out.strip()
    rec = json.loads(line)
    assert rec["agent"] == "bot"
