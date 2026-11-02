"""v0.4 tests: audit hash chain (G5), list_tools cache (G6)."""

from __future__ import annotations

import json

from agentgate.audit import AuditLog
from agentgate.cli import main
from agentgate.gateway import Gateway
from agentgate.config import Config


def _read_lines(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]


def test_chain_links_records(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("e1", agent="bot")
    log.append("e2", agent="bot")
    log.append("e3", agent="bot")
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    recs = [json.loads(l) for l in lines]
    assert recs[0]["prev"] == "0" * 64
    import hashlib
    for i in range(1, len(recs)):
        expected = hashlib.sha256(lines[i - 1].encode("utf-8")).hexdigest()
        assert recs[i]["prev"] == expected


def test_verify_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(3):
        log.append("call", agent="bot", n=i)
    path = tmp_path / "a.jsonl"
    # tamper with the middle record in place
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["agent"] = "mallory"
    lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, bad_line, total, msg = AuditLog.verify_file(path)
    # modification of record N surfaces as a break at record N+1 (prev mismatch)
    assert not ok and bad_line == 3
    # deletion also breaks the chain
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    ok, bad_line, total, msg = AuditLog.verify_file(path)
    assert not ok


def test_verify_ok_and_missing(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("e1")
    log.append("e2")
    ok, _, total, msg = AuditLog.verify_file(tmp_path / "a.jsonl")
    assert ok and total == 2 and "intact" in msg
    ok, _, total, msg = AuditLog.verify_file(tmp_path / "none.jsonl")
    assert ok and total == 0


def test_verify_cli_exit_codes(tmp_path, capsys):
    log = AuditLog(tmp_path / "state" / "audit.jsonl")
    log.append("e1")
    log.append("e2")
    assert main(["log", "--verify", "--state-dir", str(tmp_path / "state")]) == 0
    # tamper with the first record (detected at the second)
    p = tmp_path / "state" / "audit.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["agent"] = "x"
    lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["log", "--verify", "--state-dir", str(tmp_path / "state")]) == 1
    assert "TAMPERED" in capsys.readouterr().out


def test_rotation_resets_chain_per_file(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", max_bytes=1)
    log.append("e1")
    log.append("e2")
    rotated = log.rotated_files()
    assert len(rotated) == 1
    assert AuditLog.verify_file(rotated[0])[0]
    assert AuditLog.verify_file(tmp_path / "a.jsonl")[0]


# ---- G6: list cache ----

class CountingUpstream:
    def __init__(self, tools):
        self.tools = tools
        self.calls = 0
        self.name = "demo"

    async def list_tools(self):
        self.calls += 1
        import mcp_types as types

        return [
            types.Tool(name=n, input_schema={"type": "object"})
            for n in self.tools
        ]


def _mk_gateway(cfg, upstream):
    from agentgate.approvals import ApprovalManager
    from agentgate.audit import AuditLog
    from agentgate.grants import GrantStore
    from agentgate.policy import PolicyEngine

    gw = Gateway(cfg, "bot", PolicyEngine(cfg),
                 ApprovalManager(cfg.state_dir), GrantStore(cfg.state_dir / "grants.json"),
                 AuditLog(cfg.state_dir / "audit.jsonl"))
    gw.upstreams = {"demo": upstream}
    return gw


async def test_list_cache_hits(tmp_path):
    cfg = Config()
    cfg.list_cache_seconds = 60
    cfg.state_dir = tmp_path  # keep scratch files inside tmp
    up = CountingUpstream(["a", "b"])
    gw = _mk_gateway(cfg, up)
    r1 = await gw._list_tools(None, None)
    r2 = await gw._list_tools(None, None)
    assert up.calls == 1  # second call served from cache
    assert [t.name for t in r1.tools] == [t.name for t in r2.tools] == ["demo--a", "demo--b"]
    # cache disabled -> every call hits upstream
    cfg.list_cache_seconds = 0
    await gw._list_tools(None, None)
    await gw._list_tools(None, None)
    assert up.calls == 3
