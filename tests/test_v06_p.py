"""v0.6 P-batch: log --since, cross-agent grant isolation."""

from __future__ import annotations

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.config import Config
from agentgate.grants import GrantStore
from agentgate.policy import PolicyEngine


def test_log_since(tmp_path, capsys):
    state = tmp_path / "state"
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", tool="old", decision="allow")
    lines = (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    # rewrite the first record with an old timestamp
    import json as _json

    rec = _json.loads(lines[0])
    rec["ts"] = "2026-11-03T00:00:00+0800"
    lines[0] = _json.dumps(rec, ensure_ascii=False, sort_keys=True)
    (state / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log.append("call", agent="bot", tool="new", decision="allow")

    rc = main(["log", "--since", "2026-11-03T01:00:00+0800", "--state-dir", str(state)])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"tool": "new"' in out and '"tool": "old"' not in out


def test_grant_isolated_per_agent(tmp_path):
    """Security e2e at unit level: bot's grant must never authorize another agent."""
    cfg = Config(default_decision="deny")
    cfg.state_dir = tmp_path
    store = GrantStore(tmp_path / "grants.json")
    store.add("bot", "fs", "echo", None, ttl_seconds=600, bind="tool")
    engine = PolicyEngine(cfg, store)
    assert engine.evaluate("bot", "fs", "echo", {}).action == "grant"
    # same tool, different agent -> grant does not apply (falls to default deny)
    assert engine.evaluate("mallory", "fs", "echo", {}).action == "deny"
