"""v0.6 N: agentgate doctor diagnostics."""

from __future__ import annotations

import json

from agentgate.approvals import ApprovalManager
from agentgate.audit import AuditLog
from agentgate.cli import main

from tests.test_e2e import write_config


def test_doctor_all_ok(tmp_path, capsys):
    state = str(tmp_path / "state")
    AuditLog(tmp_path / "state" / "audit.jsonl").append("gateway_start", agent="bot")
    rc = main(["doctor", "--state-dir", state, "--config", str(write_config(tmp_path))])
    assert rc == 0
    out = capsys.readouterr().out
    assert "all checks passed" in out
    assert "python >= 3.11" in out and "✓" in out
    assert "audit chain (1 records)" in out


def test_doctor_detects_bad_policy(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nagents: {bot: {servers: {fs: {tools: {x: maybe}}}}}\n",
                   encoding="utf-8")
    rc = main(["doctor", "--state-dir", str(tmp_path / "state"), "--config", str(bad)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "✗ policy loads" in out and "FAILURES FOUND" in out


def test_doctor_detects_broken_chain(tmp_path, capsys):
    state = tmp_path / "state"
    log = AuditLog(state / "audit.jsonl")
    log.append("e1")
    log.append("e2")
    p = state / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["agent"] = "tamper"
    lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rc = main(["doctor", "--state-dir", str(state)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "chain broken" in out and "FAILURES FOUND" in out


def test_doctor_reach_probes_upstream(tmp_path, capsys):
    rc = main(["doctor", "--state-dir", str(tmp_path / "state"),
               "--config", str(write_config(tmp_path)), "--reach"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "upstream demo reachable" in out and "demo-server" in out
