"""v0.7 W: batch approve + policy lint."""

from __future__ import annotations

from agentgate.approvals import ApprovalManager
from agentgate.cli import main

from tests.test_e2e import write_config


# --- batch approve --all ---

def test_approve_all(tmp_path, capsys):
    state = str(tmp_path / "state")
    mgr = ApprovalManager(state)
    r1 = mgr.create_request("bot", "fs", "t1", {}, "rule")
    r2 = mgr.create_request("bot", "fs", "t2", {}, "rule")
    rc = main(["approve", "--all", "--allow", "--state-dir", state])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("APPROVED") == 2
    # pending files remain until the gateway consumes them; decisions are written
    from pathlib import Path

    assert len(list((Path(state) / "decisions").glob("*.json"))) == 2


def test_approve_all_empty(tmp_path, capsys):
    assert main(["approve", "--all", "--allow",
                 "--state-dir", str(tmp_path / "state")]) == 0
    assert "no pending" in capsys.readouterr().out


def test_approve_specific_still_works(tmp_path):
    state = str(tmp_path / "state")
    mgr = ApprovalManager(state)
    r1 = mgr.create_request("bot", "fs", "t1", {}, "rule")
    mgr.create_request("bot", "fs", "t2", {}, "rule")
    rc = main(["approve", r1["id"], "--deny", "--reason", "no", "--state-dir", state])
    assert rc == 0
    # only r1 was decided; its pending file remains until gateway consumption
    from pathlib import Path

    assert len(list((Path(state) / "decisions").glob("*.json"))) == 1
    assert len(mgr.list_pending()) == 2


# --- policy lint ---

def test_lint_clean_policy(tmp_path, capsys):
    p = write_config(tmp_path)
    rc = main(["lint", "--config", str(p)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "0 problem(s)" in out


def test_lint_flags_blanket_allow(tmp_path, capsys):
    import yaml

    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"*": "allow"}}}}},
    }), encoding="utf-8")
    rc = main(["lint", "--config", str(p)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "blanket allow" in out


def test_lint_flags_non_deny_default(tmp_path, capsys):
    import yaml

    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({"version": 1, "default_decision": "allow"}),
                 encoding="utf-8")
    rc = main(["lint", "--config", str(p)])
    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_lint_deny_rule_delegation_rejected_at_load(tmp_path, capsys):
    """delegation on a deny rule is rejected at parse time (fail-fast), so lint
    never sees it - the warning branch is a defense-in-depth guard."""
    import yaml

    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {
            "tools": {"x": {"decision": "deny", "delegation": {"ttl_seconds": 60}}}}}}},
    }), encoding="utf-8")
    rc = main(["lint", "--config", str(p)])
    assert rc == 2  # load_config raises first
