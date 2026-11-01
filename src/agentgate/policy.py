"""Policy engine: maps (agent, server, tool, arguments) to a decision.

Evaluation order (fail-closed):
1. Active, non-expired delegation grants matching the request -> "grant".
2. The agent's per-server tool rules, in file order; first pattern match wins
   (glob on tool name via fnmatch). A rule with args_match only applies when
   every listed argument path glob-matches; otherwise evaluation continues.
3. The agent's per-server default.
4. The global default_decision (deny unless configured otherwise).
"""

from __future__ import annotations

import fnmatch
import json
import time
from dataclasses import dataclass
from typing import Any

from .config import ASK, ALLOW, Config, DENY


def _arg_at(arguments: dict[str, Any], dotted: str) -> str | None:
    """Fetch a value at a dotted path; returns str(value) or None if absent."""
    cur: Any = arguments
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    if isinstance(cur, str):
        return cur
    if cur is None or isinstance(cur, (bool, int, float)):
        return str(cur).lower() if isinstance(cur, bool) else str(cur)
    return json.dumps(cur, sort_keys=True)


def args_match(arguments: dict[str, Any], conditions: dict[str, str]) -> bool:
    for path, glob in conditions.items():
        value = _arg_at(arguments, path)
        if value is None or not fnmatch.fnmatchcase(value, glob):
            return False
    return True


def canonical_args(arguments: dict[str, Any] | None) -> str:
    """Stable serialization used for tool+args grant binding."""
    return json.dumps(arguments or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Decision:
    action: str  # allow | deny | ask | grant
    rule: str  # human-readable matched rule, e.g. 'agents.claude-code.servers.fs.tools."write_*"'
    grant_id: str | None = None
    delegation_ttl: int | None = None
    delegation_bind: str | None = None


@dataclass
class Grant:
    id: str
    agent: str
    server: str
    tool: str  # exact tool name
    args_hash: str | None  # set when bind == tool+args
    created_at: float
    expires_at: float
    approver: str = "human"

    def active(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) < self.expires_at

    def matches(self, agent: str, server: str, tool: str, arguments: dict[str, Any] | None) -> bool:
        if not self.active():
            return False
        if agent != self.agent or server != self.server or not fnmatch.fnmatchcase(tool, self.tool):
            return False
        if self.args_hash is not None and self.args_hash != canonical_args(arguments):
            return False
        return True


class PolicyEngine:
    def __init__(self, config: Config, grant_store=None) -> None:
        self.config = config
        self.grants = grant_store

    def evaluate(
        self, agent: str, server: str, tool: str, arguments: dict[str, Any] | None
    ) -> Decision:
        if self.grants is not None:
            grant = self.grants.match(agent, server, tool, arguments)
            if grant is not None:
                return Decision(action="grant", rule=f"grant:{grant.id}", grant_id=grant.id)

        apol = self.config.agents.get(agent)
        if apol is not None:
            spol = apol.servers.get(server)
            if spol is not None:
                for rule in spol.rules:
                    if not fnmatch.fnmatchcase(tool, rule.pattern):
                        continue
                    if rule.args_match is not None and not args_match(arguments or {}, rule.args_match):
                        continue
                    return Decision(
                        action=rule.decision,
                        rule=f'agents.{agent}.servers.{server}.tools."{rule.pattern}"',
                        delegation_ttl=rule.delegation.ttl_seconds if rule.delegation else None,
                        delegation_bind=rule.delegation.bind if rule.delegation else None,
                    )
                return Decision(
                    action=spol.default,
                    rule=f"agents.{agent}.servers.{server}.default",
                )
        return Decision(action=self.config.default_decision, rule="default_decision")

    def check_capability(self, agent: str, server: str, kind: str) -> tuple[bool, str]:
        """Non-tool capability check (prompts/resources). Returns (allowed, rule).

        Fail-closed: unknown agent/server -> deny; only explicit allow opens it.
        """
        rule_name = f"agents.{agent}.servers.{server}.{kind}"
        apol = self.config.agents.get(agent)
        if apol is None:
            return False, "default_decision"
        spol = apol.servers.get(server)
        if spol is None:
            return False, "default_decision"
        value = getattr(spol, kind)
        return (value == ALLOW), rule_name
