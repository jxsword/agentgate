"""Unit tests: config parsing + policy engine."""

from pathlib import Path

import pytest

from agentgate.config import Config, ConfigError, load_config
from agentgate.policy import PolicyEngine, args_match, canonical_args
from agentgate.grants import GrantStore


def make_config(**overrides) -> Config:
    cfg = Config(default_decision="deny")
    import yaml

    doc = {
        "version": 1,
        "default_decision": "deny",
        "agents": {
            "bot": {
                "servers": {
                    "fs": {
                        "default": "ask",
                        "tools": {
                            "echo": "allow",
                            "read_*": "allow",
                            "write_file": {
                                "decision": "ask",
                                "args_match": {"path": "*sandbox*"},
                                "delegation": {"ttl_seconds": 600, "bind": "tool+args"},
                            },
                            "risky_*": "deny",
                        },
                    }
                }
            }
        },
    }
    doc.update(overrides)
    return load_config_dict(doc)


def load_config_dict(doc) -> Config:
    import tempfile

    from agentgate.config import load_config

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        import yaml

        f.write(yaml.safe_dump(doc))
        path = f.name
    return load_config(path)


class TestConfig:
    def test_invalid_decision_rejected(self):
        with pytest.raises(ConfigError):
            load_config_dict({"agents": {"bot": {"servers": {"fs": {"tools": {"x": "maybe"}}}}}})

    def test_delegation_only_on_ask(self):
        with pytest.raises(ConfigError):
            load_config_dict(
                {
                    "agents": {
                        "bot": {
                            "servers": {
                                "fs": {
                                    "tools": {
                                        "x": {
                                            "decision": "allow",
                                            "delegation": {"ttl_seconds": 60},
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            )

    def test_stdio_server_requires_command(self):
        with pytest.raises(ConfigError):
            load_config_dict({"servers": {"fs": {"transport": "stdio"}}})

    def test_missing_file(self):
        with pytest.raises(ConfigError):
            load_config(Path("no/such/file.yaml"))


class TestArgsMatch:
    def test_simple_glob(self):
        assert args_match({"path": "/tmp/sandbox/a.txt"}, {"path": "*sandbox*"})

    def test_no_match_fails(self):
        assert not args_match({"path": "/etc/passwd"}, {"path": "*sandbox*"})

    def test_dotted_path(self):
        assert args_match({"a": {"b": "hello"}}, {"a.b": "hell*"})

    def test_missing_arg_fails_closed(self):
        assert not args_match({}, {"path": "*"})


class TestPolicyEngine:
    def test_allow_rule(self):
        cfg = make_config()
        engine = PolicyEngine(cfg)
        d = engine.evaluate("bot", "fs", "echo", {"text": "hi"})
        assert d.action == "allow"

    def test_glob_allow(self):
        cfg = make_config()
        engine = PolicyEngine(cfg)
        assert engine.evaluate("bot", "fs", "read_file", {}).action == "allow"

    def test_deny_rule(self):
        cfg = make_config()
        engine = PolicyEngine(cfg)
        assert engine.evaluate("bot", "fs", "risky_delete", {}).action == "deny"

    def test_args_match_gating(self):
        cfg = make_config()
        engine = PolicyEngine(cfg)
        # path inside sandbox -> ask (rule matches)
        assert engine.evaluate("bot", "fs", "write_file", {"path": "x/sandbox/y"}).action == "ask"
        # path outside sandbox -> rule skipped -> server default ask -> same, but different rule
        d = engine.evaluate("bot", "fs", "write_file", {"path": "/etc/passwd"})
        assert d.action == "ask"
        assert "default" in d.rule

    def test_unknown_agent_falls_to_global_default(self):
        cfg = make_config()
        engine = PolicyEngine(cfg)
        assert engine.evaluate("ghost", "fs", "echo", {}).action == "deny"

    def test_unknown_server_falls_to_global_default(self):
        cfg = make_config()
        engine = PolicyEngine(cfg)
        assert engine.evaluate("bot", "other", "echo", {}).action == "deny"

    def test_grant_wins_over_rules(self, tmp_path):
        cfg = make_config()
        store = GrantStore(tmp_path / "grants.json")
        engine = PolicyEngine(cfg, store)
        assert engine.evaluate("bot", "fs", "risky_delete", {}).action == "deny"
        store.add("bot", "fs", "risky_delete", {}, ttl_seconds=60, bind="tool")
        assert engine.evaluate("bot", "fs", "risky_delete", {}).action == "grant"


class TestGrants:
    def test_bind_tool_args(self, tmp_path):
        store = GrantStore(tmp_path / "g.json")
        store.add("bot", "fs", "write_file", {"path": "a.txt"}, ttl_seconds=60, bind="tool+args")
        assert store.match("bot", "fs", "write_file", {"path": "a.txt"})
        assert not store.match("bot", "fs", "write_file", {"path": "b.txt"})
        # bind=tool ignores args
        store.add("bot", "fs", "write_file", {"path": "a.txt"}, ttl_seconds=60, bind="tool")
        assert store.match("bot", "fs", "write_file", {"path": "anything"})

    def test_expiry(self, tmp_path):
        store = GrantStore(tmp_path / "g.json")
        g = store.add("bot", "fs", "t", None, ttl_seconds=-1, bind="tool")
        assert not g.active()
        assert store.match("bot", "fs", "t", None) is None
        assert store.list() == []
        assert store.list(include_expired=True)

    def test_revoke_and_persistence(self, tmp_path):
        path = tmp_path / "g.json"
        store = GrantStore(path)
        g = store.add("bot", "fs", "t", None, ttl_seconds=60, bind="tool")
        # separate instance reads persisted state
        store2 = GrantStore(path)
        assert store2.match("bot", "fs", "t", None)
        assert store2.revoke(g.id)
        assert not GrantStore(path).match("bot", "fs", "t", None)
        assert not store2.revoke(g.id)


def test_canonical_args_stable():
    assert canonical_args({"a": 1, "b": 2}) == canonical_args({"b": 2, "a": 1})
    assert canonical_args(None) == canonical_args({})
