"""v0.7 Z: policy-export + check-fuzz."""

from __future__ import annotations

import json

from agentgate.cli import main

from tests.test_e2e import write_config


# --- policy-export ---

def test_policy_export_stable(tmp_path, capsys):
    cfg = write_config(tmp_path)
    rc = main(["policy-export", "--config", str(cfg)])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == 1
    assert data["agents"]["bot"]["servers"]["demo"]["tools"]["echo"] == "allow"
    assert data["default_decision"] == "deny"


# --- check-fuzz ---

def test_fuzz_detects_uncovered(tmp_path, capsys):
    cfg = tmp_path / "p.yaml"
    import yaml

    cfg.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {
            "tools": {"echo": "allow", "rm_*": "deny"}}}}},
    }), encoding="utf-8")
    rc = main(["check-fuzz", "--config", str(cfg), "--verbose"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "covered" in out and "falling to default" in out
    # unmapped names like "write_1234" should be listed
    assert "write_" in out


def test_fuzz_all_covered(tmp_path, capsys):
    cfg = tmp_path / "p.yaml"
    import yaml

    cfg.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"tools": {"*": "deny"}}}}},
    }), encoding="utf-8")
    rc = main(["check-fuzz", "--config", str(cfg), "--verbose"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "0 falling to default" in out


def test_fuzz_reproducible(tmp_path, capsys):
    cfg = write_config(tmp_path)
    rc = main(["check-fuzz", "--config", str(cfg), "--verbose"])
    out1 = capsys.readouterr().out
    rc = main(["check-fuzz", "--config", str(cfg), "--verbose"])
    out2 = capsys.readouterr().out
    assert out1 == out2  # deterministic seed
