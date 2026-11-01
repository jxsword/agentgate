"""Gateway-level unit tests with fakes: fail-closed on policy errors, audit on unknown tools."""

import json

from agentgate.approvals import ApprovalError, ApprovalManager
from agentgate.audit import AuditLog
from agentgate.config import Config
from agentgate.gateway import Gateway
from agentgate.policy import PolicyEngine


class FlakyEngine(PolicyEngine):
    """Engine that explodes - the gateway must still fail closed."""

    def evaluate(self, agent, server, tool, arguments):
        raise RuntimeError("boom")


class AllowEngine(PolicyEngine):
    def evaluate(self, agent, server, tool, arguments):
        from agentgate.policy import Decision

        return Decision(action="allow", rule="test:allow")


def make_gateway(tmp_path, engine) -> Gateway:
    from agentgate.config import ServerConfig
    from agentgate.upstream import Upstream

    audit = AuditLog(tmp_path / "state" / "audit.jsonl")
    grants = type("S", (), {"match": staticmethod(lambda *a, **k: None)})()
    cfg = Config()
    gw = Gateway(
        config=cfg,
        agent="bot",
        engine=engine,
        approvals=ApprovalManager(tmp_path / "state"),
        grants=grants,
        audit=audit,
    )
    # a configured-but-never-started upstream: call_tool raises UpstreamError
    gw.upstreams = {"demo": Upstream(ServerConfig(name="demo", command="noop"))}
    return gw


class Params:
    def __init__(self, name, arguments=None):
        self.name = name
        self.arguments = arguments


async def test_unknown_tool_is_audited_and_denied(tmp_path):
    gw = make_gateway(tmp_path, PolicyEngine(Config()))
    res = await gw._call_tool(None, Params("nope--x", {"a": 1}))
    assert res.is_error
    rec = json.loads((tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert rec["event"] == "call_denied" and rec["rule"] == "unknown_tool"


async def test_empty_tool_part_is_unknown(tmp_path):
    gw = make_gateway(tmp_path, PolicyEngine(Config()))
    res = await gw._call_tool(None, Params("demo--", {"a": 1}))
    assert res.is_error


async def test_policy_engine_exception_fails_closed(tmp_path):
    gw = make_gateway(tmp_path, FlakyEngine(Config()))
    res = await gw._call_tool(None, Params("demo--echo", {"t": "x"}))
    assert res.is_error
    assert "fail-closed" in res.content[0].text
    lines = (tmp_path / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert any(json.loads(l)["event"] == "policy_error" for l in lines)


async def test_allow_with_no_upstream_yields_upstream_error(tmp_path):
    gw = make_gateway(tmp_path, AllowEngine(Config()))
    res = await gw._call_tool(None, Params("demo--echo", {"t": "x"}))
    # decision allow is audited, then proxying fails because no upstream session
    assert res.is_error
    assert "upstream" in res.content[0].text.lower()


def test_request_id_validation(tmp_path):
    mgr = ApprovalManager(tmp_path / "state")
    for bad in ("../evil", "ABCDEF123456", "short", "a" * 13, "", "../../x"):
        try:
            mgr.decide(bad, allow=True)
            raise AssertionError(f"{bad!r} should have been rejected")
        except ApprovalError:
            pass
