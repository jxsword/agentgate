"""v0.7 U: policy-embedded self-tests + grant usage alert."""

from __future__ import annotations

import json
from pathlib import Path

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.config import load_config
from agentgate.policy import Decision


def _write_policy(tmp_path, extra: dict) -> Path:
    import yaml

    doc = {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {
            "default": "ask",
            "tools": {"echo": "allow", "rm_*": "deny"},
        }}}},
    }
    doc.update(extra)
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def test_check_selftest_passes(tmp_path, capsys):
    p = _write_policy(tmp_path, {
        "tests": [
            {"server": "fs", "tool": "echo", "expect": "allow"},
            {"server": "fs", "tool": "rm_all", "expect": "deny"},
        ],
    })
    rc = main(["check", "--config", str(p), "--agent", "bot", "--selftest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "echo: allow" in out and "rm_all: deny" in out


def test_check_selftest_fails_on_policy_drift(tmp_path, capsys):
    p = _write_policy(tmp_path, {
        "tests": [{"server": "fs", "tool": "echo", "expect": "deny"}],  # policy says allow
    })
    rc = main(["check", "--config", str(p), "--agent", "bot", "--selftest"])
    assert rc == 1
    assert "✗" in capsys.readouterr().out


def test_check_selftest_empty(tmp_path, capsys):
    p = _write_policy(tmp_path, {})
    rc = main(["check", "--config", str(p), "--agent", "bot", "--selftest"])
    assert rc == 2


# --- grant usage alert ---

async def test_grant_usage_alert_threshold(tmp_path):
    from agentgate.approvals import ApprovalManager
    from agentgate.gateway import Gateway
    from agentgate.grants import GrantStore
    from agentgate.policy import PolicyEngine

    cfg = _write_policy(tmp_path, {"grant_usage_alert": 3})
    config = load_config(cfg)
    log = AuditLog(tmp_path / "audit.jsonl")
    store = GrantStore(tmp_path / "grants.json")
    gw = Gateway(config, "bot", PolicyEngine(config, store),
                 ApprovalManager(tmp_path / "state"), store, log)
    g = store.add("bot", "fs", "rm_all", None, ttl_seconds=600, bind="tool")
    for _ in range(3):
        await gw._proxy("fs", "rm_all", {}, Decision(action="grant", rule=f"grant:{g.id}",
                                                     grant_id=g.id),
                        dict(agent="bot", server="fs", tool="rm_all"), "grant")
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    alerts = [json.loads(l) for l in lines if json.loads(l)["event"] == "grant_usage_alert"]
    assert len(alerts) == 1
    assert alerts[0]["threshold"] == 3 and alerts[0]["uses"] == 3


async def test_no_alert_when_threshold_zero(tmp_path):
    from agentgate.approvals import ApprovalManager
    from agentgate.gateway import Gateway
    from agentgate.grants import GrantStore
    from agentgate.policy import Decision, PolicyEngine

    cfg = _write_policy(tmp_path, {})
    config = load_config(cfg)
    log = AuditLog(tmp_path / "audit.jsonl")
    store = GrantStore(tmp_path / "grants.json")
    gw = Gateway(config, "bot", PolicyEngine(config, store),
                 ApprovalManager(tmp_path / "state"), store, log)
    for _ in range(10):
        await gw._proxy("fs", "rm_all", {}, Decision(action="grant", rule="grant:x", grant_id="x"),
                        dict(agent="bot", server="fs", tool="rm_all"), "grant")
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert not any('"event": "grant_usage_alert"' in l for l in lines)
