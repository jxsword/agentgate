"""v0.3 F5: cross-process grants locking."""

from __future__ import annotations

import concurrent.futures
import json
import sys
from pathlib import Path

from agentgate.grants import GrantStore
from agentgate.locking import LockTimeout, exclusive_lock


def test_exclusive_lock_mutual_exclusion(tmp_path):
    lock_path = tmp_path / "x.json"
    events = []

    def worker(name: str):
        with exclusive_lock(lock_path, timeout=5):
            events.append(f"{name}:enter")
            import time

            time.sleep(0.15)
            events.append(f"{name}:exit")

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        list(pool.map(worker, ["a", "b"]))

    # enters/exits must strictly alternate - no overlapping critical sections
    assert events in (
        ["a:enter", "a:exit", "b:enter", "b:exit"],
        ["b:enter", "b:exit", "a:enter", "a:exit"],
    ), events


def test_lock_timeout_raises(tmp_path):
    lock_path = tmp_path / "y.json"
    with exclusive_lock(lock_path):
        try:
            with exclusive_lock(lock_path, timeout=0.2):
                raise AssertionError("second acquire should have timed out")
        except LockTimeout:
            pass
    # lock released: now acquirable
    with exclusive_lock(lock_path):
        pass


def test_concurrent_adds_do_not_lose_updates(tmp_path):
    """The original race: two processes adding grants concurrently must both persist."""
    path = tmp_path / "grants.json"

    def add_many(prefix: str):
        store = GrantStore(path)
        for i in range(20):
            store.add(prefix, "fs", "t", None, ttl_seconds=600, bind="tool")

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        list(pool.map(add_many, ["a", "b"]))

    final = json.loads(path.read_text(encoding="utf-8"))
    agents = {g["agent"] for g in final}
    assert agents == {"a", "b"}
    assert len(final) == 40  # nothing lost
    # a fresh store sees all 40
    assert len(GrantStore(path).list()) == 40


def test_cli_revoke_visible_to_gateway_store(tmp_path):
    """Gateway-held store sees a revoke made through a separate store instance."""
    path = tmp_path / "grants.json"
    gw_store = GrantStore(path)
    grant = gw_store.add("bot", "fs", "t", None, ttl_seconds=600, bind="tool")

    cli_store = GrantStore(path)
    assert cli_store.revoke(grant.id)

    # gateway-side match must now miss (reload-on-read)
    assert gw_store.match("bot", "fs", "t", None) is None
