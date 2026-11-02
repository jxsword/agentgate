"""v0.6 L2: policy `extends` composition + L3: grants show."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
import yaml

from agentgate.cli import main
from agentgate.config import ConfigError, load_config
from agentgate.grants import GrantStore


def _write(p: Path, doc: dict) -> Path:
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


# ---- L2: extends ----

def test_extends_merges_and_overrides(tmp_path):
    base = _write(tmp_path / "base.yaml", {
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {
            "default": "ask",
            "tools": {"echo": "allow", "rm_*": "deny"},
        }}}},
    })
    child = _write(tmp_path / "child.yaml", {
        "extends": "base.yaml",
        "agents": {"bot": {"servers": {"fs": {
            "tools": {"echo": "deny"},  # override one decision, keep the rest
        }}}},
    })
    cfg = load_config(child)
    eng = __import__("agentgate.policy", fromlist=["PolicyEngine"]).PolicyEngine(cfg)
    # overridden
    assert eng.evaluate("bot", "fs", "echo", {}).action == "deny"
    # inherited from base
    assert eng.evaluate("bot", "fs", "rm_all", {}).action == "deny"
    assert eng.evaluate("bot", "fs", "other", {}).action == "ask"  # default kept


def test_extends_chain_and_cycle_detection(tmp_path):
    a = _write(tmp_path / "a.yaml", {"version": 1, "extends": "b.yaml"})
    _write(tmp_path / "b.yaml", {"version": 1, "extends": "a.yaml"})
    with pytest.raises(ConfigError, match="cycle"):
        load_config(a)

    _write(tmp_path / "self.yaml", {"version": 1, "extends": "self.yaml"})
    with pytest.raises(ConfigError, match="cycle"):
        load_config(tmp_path / "self.yaml")


def test_extends_missing_base(tmp_path):
    _write(tmp_path / "c.yaml", {"version": 1, "extends": "nope.yaml"})
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "c.yaml")


# ---- L3: grants show ----

def test_grants_show(tmp_path, capsys):
    state = str(tmp_path / "state")
    store = GrantStore(Path(state) / "grants.json")
    g = store.add("bot", "fs", "write_file", {"path": "a.txt"},
                  ttl_seconds=600, bind="tool+args", approver="alice")
    rc = main(["grants", g.id, "--state-dir", state])
    assert rc == 0
    out = capsys.readouterr().out
    assert g.id in out and "write_file" in out and "alice" in out
    assert "args-bound" in out

    # unknown id -> exit 1
    assert main(["grants", "nope12345678", "--state-dir", state]) == 1


def test_grants_show_expired_flag(tmp_path, capsys):
    state = str(tmp_path / "state")
    store = GrantStore(Path(state) / "grants.json")
    g = store.add("bot", "fs", "t", None, ttl_seconds=-5, bind="tool")
    rc = main(["grants", g.id, "--state-dir", state])
    assert rc == 0
    assert "expired" in capsys.readouterr().out
