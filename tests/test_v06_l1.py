"""v0.6 L1: report --grants delegation usage view."""

from __future__ import annotations

import json

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.grants import GrantStore


def test_grants_usage_view(tmp_path, capsys):
    state = tmp_path / "state"
    store = GrantStore(state / "grants.json")
    g1 = store.add("bot", "fs", "echo", None, ttl_seconds=600, bind="tool", approver="alice")
    store.add("bot", "fs", "rm", None, ttl_seconds=-1, bind="tool", approver="bob")  # expired
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="grant", grant_id=g1.id)
    log.append("call", agent="bot", server="fs", tool="echo", decision="grant", grant_id=g1.id)
    log.append("call", agent="bot", server="fs", tool="t", decision="grant", grant_id="gone00000000")

    rc = main(["report", "--grants", "--state-dir", str(state), "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    rows = {r["id"]: r for r in data["grants"]}
    assert rows[g1.id]["uses"] == 2 and rows[g1.id]["active"] is True
    expired = [r for r in data["grants"] if r["id"] != g1.id][0]
    assert expired["active"] is False and expired["uses"] == 0
    # the call referencing a revoked/vanished grant is reported
    assert data["unknown_grant_uses"] == 1


def test_grants_usage_table(tmp_path, capsys):
    state = tmp_path / "state"
    store = GrantStore(state / "grants.json")
    g1 = store.add("bot", "fs", "echo", None, ttl_seconds=600, bind="tool+args", approver="alice")
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="grant", grant_id=g1.id)
    rc = main(["report", "--grants", "--state-dir", str(state)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "bot@fs--echo (+args)" in out
    assert "active" in out and "alice" in out


def test_grants_view_empty(tmp_path, capsys):
    rc = main(["report", "--grants", "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    assert "no grants found" in capsys.readouterr().out
