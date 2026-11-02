"""v0.3 F6: agentgate report - audit aggregation."""

from __future__ import annotations

import json

from agentgate.audit import AuditLog
from agentgate.cli import main


def _seed(state):
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="allow",
               ts="2026-11-03T01:00:00+0800")
    log.append("call", agent="bot", server="fs", tool="write_file", decision="grant",
               ts="2026-11-03T01:00:01+0800")
    log.append("call", agent="bot", server="fs", tool="write_file", decision="ask_allowed",
               ts="2026-11-03T01:00:02+0800")
    log.append("call_denied", agent="bot", server="fs", tool="delete_file", decision="deny",
               ts="2026-11-03T01:00:03+0800")
    log.append("ask_denied", agent="bot", server="fs", tool="risky", decision="deny",
               ts="2026-11-03T01:00:04+0800")
    log.append("call", agent="alice", server="fs", tool="echo", decision="allow",
               ts="2026-11-03T01:00:05+0800")


def test_report_table(tmp_path, capsys):
    state = str(tmp_path / "state")
    _seed(tmp_path / "state")
    rc = main(["report", "--state-dir", state])
    assert rc == 0
    out = capsys.readouterr().out
    assert "bot" in out and "write_file" in out
    assert "total decisions: 6" in out
    # denial rate row present
    assert "deny%" in out


def test_report_json(tmp_path, capsys):
    state = str(tmp_path / "state")
    _seed(tmp_path / "state")
    rc = main(["report", "--state-dir", state, "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["total_decisions"] == 6
    rows = {(r["agent"], r["tool"]): r for r in data["rows"]}
    assert rows[("bot", "echo")]["allowed"] == 1
    assert rows[("bot", "write_file")]["allowed"] == 1
    assert rows[("bot", "write_file")]["ask_allowed"] == 1
    assert rows[("bot", "delete_file")]["denied"] == 1
    assert rows[("bot", "delete_file")]["denial_rate"] == 1.0


def test_report_since_filters(tmp_path, capsys):
    state = str(tmp_path / "state")
    _seed(tmp_path / "state")
    rc = main(["report", "--state-dir", state, "--format", "json",
               "--since", "2026-11-03T01:00:04+0800"])
    data = json.loads(capsys.readouterr().out)
    assert data["total_decisions"] == 2  # ask_denied + alice echo
    assert [r["agent"] for r in data["rows"]] == ["alice", "bot"]


def test_report_rotated_files_included(tmp_path, capsys):
    state = tmp_path / "state"
    state.mkdir(parents=True)
    rotated = state / "audit-20261103000000.jsonl"
    rotated.write_text(json.dumps({
        "ts": "2026-11-03T00:00:00+0800", "event": "call", "agent": "old",
        "server": "fs", "tool": "echo", "decision": "allow",
    }) + "\n", encoding="utf-8")
    rc = main(["report", "--state-dir", str(state), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["total_decisions"] == 1
    assert rc == 0


def test_report_empty(tmp_path, capsys):
    rc = main(["report", "--state-dir", str(tmp_path / "state")])
    assert rc == 0
    assert "no tool decisions" in capsys.readouterr().out
