"""Unit tests: approval file protocol."""

import pytest

from agentgate.approvals import ApprovalError, ApprovalManager


def make_mgr(tmp_path) -> ApprovalManager:
    return ApprovalManager(tmp_path / "state")


async def test_create_and_list(tmp_path):
    mgr = make_mgr(tmp_path)
    req = mgr.create_request("bot", "fs", "write_file", {"path": "a.txt"}, "rule:1",
                             delegation={"ttl_seconds": 60, "bind": "tool"})
    pending = mgr.list_pending()
    assert len(pending) == 1
    assert pending[0]["id"] == req["id"]
    assert pending[0]["tool"] == "fs--write_file"
    assert pending[0]["arguments"] == {"path": "a.txt"}


async def test_decide_and_wait_allow(tmp_path):
    import asyncio

    mgr = make_mgr(tmp_path)
    req = mgr.create_request("bot", "fs", "t", None, "rule")

    async def human():
        await asyncio.sleep(0.3)
        mgr.decide(req["id"], allow=True, approver="alice")

    task = asyncio.create_task(human())
    decision = await mgr.wait(req["id"], timeout_seconds=5)
    await task
    assert decision["allow"] is True
    assert decision["approver"] == "alice"
    # consumed: pending + decision files cleaned up
    assert mgr.list_pending() == []
    assert not list((tmp_path / "state" / "decisions").glob("*.json"))


async def test_wait_timeout_fail_closed(tmp_path):
    mgr = make_mgr(tmp_path)
    req = mgr.create_request("bot", "fs", "t", None, "rule")
    with pytest.raises(TimeoutError):
        await mgr.wait(req["id"], timeout_seconds=0.4)


def test_decide_unknown_id(tmp_path):
    mgr = make_mgr(tmp_path)
    with pytest.raises(ApprovalError):
        mgr.decide("nope", allow=True)


def test_corrupt_pending_tolerated(tmp_path):
    mgr = make_mgr(tmp_path)
    (mgr.pending_dir / "bad.json").write_text("{not json", encoding="utf-8")
    items = mgr.list_pending()
    assert items == [{"id": "bad", "error": "corrupt pending file"}]
