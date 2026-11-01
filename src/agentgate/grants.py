"""Delegation grants: human approvals converted into scoped, expiring grants.

A grant binds (agent, server, tool[, exact arguments]) and expires after a
TTL. Grants live in state_dir/grants.json and are the cryptographic-free
v0.1 form of "scoped delegation": a human approved this call once, the agent
may repeat exactly that call until expiry.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .policy import Grant, canonical_args


class GrantStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._grants: list[Grant] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            # A corrupt grants file must never block the gateway; losing grants
            # only makes the gateway stricter (every grant becomes deny/ask).
            print(f"[agentgate] WARNING: corrupt grants file {self.path}, starting empty",
                  file=sys.stderr)
            self._grants = []
            return
        self._grants = [Grant(**g) for g in raw]

    def _save(self) -> None:
        payload = [
            {
                "id": g.id,
                "agent": g.agent,
                "server": g.server,
                "tool": g.tool,
                "args_hash": g.args_hash,
                "created_at": g.created_at,
                "expires_at": g.expires_at,
                "approver": g.approver,
            }
            for g in self._grants
        ]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def add(
        self,
        agent: str,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None,
        ttl_seconds: int,
        bind: str = "tool",
        approver: str = "human",
    ) -> Grant:
        now = time.time()
        grant = Grant(
            id=uuid.uuid4().hex[:12],
            agent=agent,
            server=server,
            tool=tool,
            args_hash=canonical_args(arguments) if bind == "tool+args" else None,
            created_at=now,
            expires_at=now + ttl_seconds,
            approver=approver,
        )
        self._grants.append(grant)
        self._save()
        return grant

    def match(self, agent: str, server: str, tool: str, arguments: dict[str, Any] | None) -> Grant | None:
        for grant in reversed(self._grants):
            if grant.matches(agent, server, tool, arguments):
                return grant
        return None

    def revoke(self, grant_id: str) -> bool:
        before = len(self._grants)
        self._grants = [g for g in self._grants if g.id != grant_id]
        changed = len(self._grants) != before
        if changed:
            self._save()
        return changed

    def list(self, include_expired: bool = False) -> list[Grant]:
        now = time.time()
        return [g for g in self._grants if include_expired or g.active(now)]
