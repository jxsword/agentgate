"""v0.7 Y: report --by-rule grouping."""

from __future__ import annotations

import json

from agentgate.audit import AuditLog
from agentgate.cli import main


def _seed(state):
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="allow",
               rule="agents.bot.servers.fs.tools.\"echo\"")
    log.append("call_denied", agent="bot", server="fs", tool="delete_file", decision="deny",
               rule="agents.bot.servers.fs.tools.\"delete_*\"")
    log.append("call_denied", agent="bot", server="fs", tool="delete_all", decision="deny",
               rule="agents.bot.servers.fs.tools.\"delete_*\"")
    log.append("call", agent="bot", server="fs", tool="write_file", decision="ask_allowed",
               rule="agents.bot.servers.fs.default")


def test_report_by_rule_table(tmp_path, capsys):
    state = str(tmp_path / "state")
    _seed(tmp_path / "state")
    rc = main(["report", "--by-rule", "--state-dir", state])
    assert rc == 0
    out = capsys.readouterr().out
    assert "delete_*" in out  # rule name, not tool name
    assert "total decisions: 4" in out


def test_report_by_rule_json(tmp_path, capsys):
    state = str(tmp_path / "state")
    _seed(tmp_path / "state")
    rc = main(["report", "--by-rule", "--state-dir", state, "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total_decisions"] == 4
    assert any("rule" in r and "delete_*" in r["rule"] for r in data["rows"])


def test_report_by_rule_csv(tmp_path, capsys):
    state = str(tmp_path / "state")
    _seed(tmp_path / "state")
    rc = main(["report", "--by-rule", "--state-dir", state, "--format", "csv"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("agent,rule,allowed,ask_allowed,denied,denial_rate")
