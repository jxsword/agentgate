"""v0.7 T: agentgate incident forensics timeline."""

from __future__ import annotations

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.grants import GrantStore


def test_incident_full_timeline(tmp_path, capsys):
    state = tmp_path / "state"
    store = GrantStore(state / "grants.json")
    g = store.add("bot", "fs", "write_file", {"path": "a.txt"},
                  ttl_seconds=600, bind="tool+args", approver="alice")
    log = AuditLog(state / "audit.jsonl")
    log.append("approval_requested", agent="bot", server="fs", tool="write_file",
               decision="allow", rule="r1", request_id="req000000001")
    log.append("grant_created", agent="bot", server="fs", tool="write_file",
               decision="allow", rule="r1", grant_id=g.id, request_id="req000000001",
               ttl_seconds=600, bind="tool+args", approver="alice")
    log.append("call", agent="bot", server="fs", tool="write_file",
               decision="grant", rule=f"grant:{g.id}", grant_id=g.id)
    log.append("call_result", agent="bot", server="fs", tool="write_file",
               decision="grant", rule=f"grant:{g.id}", grant_id=g.id,
               is_error=False, n_content=1)

    rc = main(["incident", g.id, "--state-dir", str(state)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "4 records" in out
    assert "approval_requested" in out and "grant_created" in out
    assert "call_result" in out
    assert "approver: alice" in out
    assert "audit integrity: OK" in out


def test_incident_unknown_id(tmp_path, capsys):
    rc = main(["incident", "nope00000000", "--state-dir", str(tmp_path / "state")])
    assert rc == 1
    assert "no audit records" in capsys.readouterr().out


def test_incident_reports_broken_chain(tmp_path, capsys):
    state = tmp_path / "state"
    log = AuditLog(state / "audit.jsonl")
    log.append("call", agent="bot", grant_id="abc000000000")
    log.append("call", agent="bot", grant_id="abc000000000")
    p = state / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    import json as _json
    rec = _json.loads(lines[0])
    rec["agent"] = "tampered"
    lines[0] = _json.dumps(rec, ensure_ascii=False, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rc = main(["incident", "abc000000000", "--state-dir", str(state)])
    assert rc == 1
    assert "COMPROMISED" in capsys.readouterr().out
