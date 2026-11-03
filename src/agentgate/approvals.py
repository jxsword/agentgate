"""Human approval flow, file-based so it works with any MCP client.

When policy says `ask`, the gateway writes `pending/<id>.json` describing the
blocked call and blocks the tool call (asyncio, other calls keep flowing).
A human runs `agentgate approve <id> --allow|--deny` in another terminal,
which writes `decisions/<id>.json`; the gateway polls for it.

Fail-closed: if no decision arrives within ask_timeout_seconds, the call is
denied and the timeout is audited.

Security note: request ids are strictly validated (12 lowercase hex chars)
before being used in file paths, so a crafted CLI argument cannot traverse
out of the state directory.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .policy import canonical_args

REQUEST_ID_RE = re.compile(r"^[0-9a-f]{12}$")

SECRET_ENV = "AGENTGATE_APPROVAL_SECRET"


def approval_secret() -> str | None:
    """Shared approval-signing secret; empty/unset means signatures are off.

    v0.2 (EX-3): when set, `decide` signs and the gateway verifies the human
    decision (HMAC-SHA256), so a rogue local process cannot forge approvals.
    The secret only ever comes from the environment - never from files or code.
    """
    secret = os.environ.get(SECRET_ENV, "")
    return secret or None


def _signature(request_id: str, allow: bool, approver: str, decided_at: str,
               arguments_hash: str, secret: str, reason: str = "") -> str:
    payload = f"{request_id}|{allow}|{approver}|{decided_at}|{arguments_hash}|{reason}"
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_decision(request: dict[str, Any], decision: dict[str, Any], secret: str) -> bool:
    """Verify a decision's HMAC against its pending request. Unsigned -> invalid."""
    sig = decision.get("sig")
    if not sig:
        return False
    expected = _signature(
        str(decision.get("id")), bool(decision.get("allow")), str(decision.get("approver")),
        str(decision.get("decided_at")), str(request.get("arguments_hash")), secret,
        str(decision.get("reason", "")),
    )
    return hmac.compare_digest(sig, expected)


class ApprovalError(RuntimeError):
    pass


def _validate_request_id(request_id: str) -> str:
    if not REQUEST_ID_RE.match(request_id or ""):
        raise ApprovalError(f"invalid request id {request_id!r}")
    return request_id


class ApprovalManager:
    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir)
        self.pending_dir = self.state_dir / "pending"
        self.decisions_dir = self.state_dir / "decisions"
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.decisions_dir.mkdir(parents=True, exist_ok=True)

    def create_request(
        self,
        agent: str,
        server: str,
        tool: str,
        arguments: dict[str, Any] | None,
        rule: str,
        delegation: dict[str, Any] | None = None,
        arguments_hash: str | None = None,
    ) -> dict[str, Any]:
        # arguments here are the DISPLAY copy (possibly redacted by policy);
        # arguments_hash must be computed from the real arguments by the caller
        # so grant binding (tool+args) still matches the original call
        request = {
            "id": uuid.uuid4().hex[:12],
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "agent": agent,
            "server": server,
            "tool": f"{server}--{tool}",
            "arguments": arguments or {},
            "arguments_hash": arguments_hash or canonical_args(arguments),
            "rule": rule,
            "delegation": delegation,
        }
        path = self.pending_dir / f"{request['id']}.json"
        path.write_text(json.dumps(request, ensure_ascii=False, indent=2), encoding="utf-8")
        return request

    def remove_request(self, request_id: str) -> None:
        _validate_request_id(request_id)
        path = self.pending_dir / f"{request_id}.json"
        if path.exists():
            path.unlink()

    async def wait(self, request_id: str, timeout_seconds: float) -> dict[str, Any]:
        """Poll for a human decision. Returns {"allow": bool, "approver": str}.

        Raises TimeoutError if no decision arrives in time.
        """
        _validate_request_id(request_id)
        path = self.decisions_dir / f"{request_id}.json"
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if path.exists():
                try:
                    decision = json.loads(path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    # P1-3: writer may be mid-replace on some filesystems; keep polling
                    await asyncio.sleep(0.2)
                    continue
                path.unlink()
                self.remove_request(request_id)
                return decision
            await asyncio.sleep(0.2)
        raise TimeoutError(f"no approval decision for {request_id} within {timeout_seconds}s")

    def cleanup_stale(self, max_age_seconds: float) -> int:
        """G2 (v0.4): remove pending files older than max_age (crash leftovers).

        A live approval request can never be older than the gateway's ask
        timeout (the waiter fails-closed at that point), so anything older is
        garbage. Returns the number removed. Also sweeps orphan decision files
        (Q2 v0.7: decided but never consumed - e.g. approved at timeout edge).
        """
        now = time.time()
        removed = 0
        for p in self.pending_dir.glob("*.json"):
            try:
                if now - p.stat().st_mtime > max_age_seconds:
                    p.unlink()
                    removed += 1
            except OSError:
                pass
        # orphan decisions: decision files whose pending request is long gone
        import json as _json

        for d in self.decisions_dir.glob("*.json"):
            try:
                if now - d.stat().st_mtime > max_age_seconds:
                    d.unlink()
                    removed += 1
            except OSError:
                pass
        return removed

    # ---- CLI side (synchronous) ----

    def list_pending(self) -> list[dict[str, Any]]:
        out = []
        for p in sorted(self.pending_dir.glob("*.json")):
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                out.append({"id": p.stem, "error": "corrupt pending file"})
        return out

    def decide(self, request_id: str, allow: bool, approver: str = "human",
               reason: str | None = None) -> dict[str, Any]:
        _validate_request_id(request_id)
        pending_path = self.pending_dir / f"{request_id}.json"
        if not pending_path.exists():
            raise ApprovalError(f"no pending approval request {request_id!r}")
        decision_path = self.decisions_dir / f"{request_id}.json"
        if decision_path.exists():
            # one vote per request: never let a second write flip an existing decision
            raise ApprovalError(f"request {request_id!r} was already decided")
        decision = {
            "id": request_id,
            "allow": allow,
            "approver": approver,
            "decided_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        if reason:
            decision["reason"] = reason
        secret = approval_secret()
        if secret:
            request = json.loads(pending_path.read_text(encoding="utf-8"))
            decision["sig"] = _signature(
                request_id, allow, approver, decision["decided_at"],
                str(request.get("arguments_hash")), secret, reason or "",
            )
        # P1-3 (v0.6 review): atomic write - the gateway polls this file every
        # 0.2s and must never read a truncated decision
        tmp = decision_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(decision, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(decision_path)
        return decision
