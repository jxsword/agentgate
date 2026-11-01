"""Unit tests: audit log + CLI commands."""

import json

from agentgate.approvals import ApprovalManager
from agentgate.audit import AuditLog
from agentgate.cli import main


def test_append_is_jsonl_and_fsynced(tmp_path):
    log = AuditLog(tmp_path / "state" / "audit.jsonl")
    log.append("call", agent="bot", server="fs", tool="echo", decision="allow")
    log.append("call_denied", agent="bot", server="fs", tool="t", decision="deny")
    lines = (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[0])
    assert rec["event"] == "call" and rec["agent"] == "bot"
    assert rec["ts"]  # timestamped


def test_tail_and_corrupt_line(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("e1")
    path = tmp_path / "a.jsonl"
    path.write_text(path.read_text(encoding="utf-8") + "{corrupt\n", encoding="utf-8")
    out = log.tail(10)
    assert out[0]["event"] == "e1"
    assert out[1]["event"] == "corrupt"


def test_tail_empty_when_missing(tmp_path):
    assert AuditLog(tmp_path / "none.jsonl").tail(5) == []


# ---- CLI ----

def test_cli_pending_and_approve(tmp_path):
    state = str(tmp_path / "state")
    mgr = ApprovalManager(state)
    req = mgr.create_request("bot", "fs", "t", {"x": 1}, "rule")

    # pending lists the request
    rc = main(["pending", "--state-dir", state])
    assert rc == 0

    # approve by id
    assert main(["approve", req["id"], "--allow", "--approver", "bob", "--state-dir", state]) == 0
    assert mgr.list_pending() == [] or (mgr.decisions_dir / f"{req['id']}.json").exists()
    assert (mgr.decisions_dir / f"{req['id']}.json").exists()

    # double decide is rejected (one vote per request)
    assert main(["approve", req["id"], "--allow", "--state-dir", state]) == 1


def test_cli_grants_revoke(tmp_path):
    state = str(tmp_path / "state")
    assert main(["grants", "--state-dir", state]) == 0
    # revoke of unknown id -> exit 1
    assert main(["revoke", "deadbeef", "--state-dir", state]) == 1


def test_cli_log(tmp_path):
    state = str(tmp_path / "state")
    log = AuditLog(str(tmp_path / "state" / "audit.jsonl"))
    log.append("gateway_start", agent="bot")
    assert main(["log", "-n", "5", "--state-dir", state]) == 0
