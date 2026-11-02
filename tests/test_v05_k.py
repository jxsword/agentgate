"""v0.5 K-batch: report agent/tool filters, pending --json."""

from __future__ import annotations

import json

from agentgate.audit import AuditLog
from agentgate.approvals import ApprovalManager
from agentgate.cli import main


def _seed(state):
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="allow")
    log.append("call", agent="bot", server="fs", tool="write_file", decision="grant")
    log.append("call", agent="alice", server="fs", tool="echo", decision="allow")


def test_report_agent_filter(tmp_path, capsys):
    _seed(tmp_path / "state")
    rc = main(["report", "--state-dir", str(tmp_path / "state"),
               "--format", "json", "--agent", "bot"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total_decisions"] == 2
    assert {r["agent"] for r in data["rows"]} == {"bot"}


def test_report_tool_filter(tmp_path, capsys):
    _seed(tmp_path / "state")
    rc = main(["report", "--state-dir", str(tmp_path / "state"),
               "--format", "json", "--tool", "echo"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total_decisions"] == 2
    assert {r["tool"] for r in data["rows"]} == {"echo"}


def test_pending_json_output(tmp_path, capsys):
    state = str(tmp_path / "state")
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "t", {"x": 1}, "rule")
    rc = main(["pending", "--json", "--state-dir", state])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list) and data[0]["id"] == req["id"]
    # empty state -> []
    rc = main(["pending", "--json", "--state-dir", str(tmp_path / "empty")])
    assert json.loads(capsys.readouterr().out) == []
