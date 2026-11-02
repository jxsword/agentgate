"""External policy-backend adapters (V1.2, EX-5).

OpaPolicyEngine: local rules are authoritative for explicit decisions; when
evaluation falls through to the *defaults* (no rule matched, or no local
policy for the agent/server), the decision is delegated to an OPA-style HTTP
policy endpoint:

    POST <url>  {"input": {"agent", "server", "tool", "arguments"}}
    200 {"result": {"decision": "allow" | "deny" | "ask"}}   # or {"decision": ...}

Fail-closed: transport errors, non-2xx, unknown decision words and timeouts
all become deny. The adapter ships with httpx2 (already an mcp dependency);
tests inject a MockTransport.
"""

from __future__ import annotations

from typing import Any

from .config import Config
from .policy import Decision, PolicyEngine


class OpaPolicyEngine(PolicyEngine):
    def __init__(self, config: Config, grant_store, url: str, timeout: float = 2.0,
                 client=None) -> None:
        super().__init__(config, grant_store)
        self.url = url
        self.timeout = timeout
        self._client = client  # injection point for tests (httpx2.MockTransport)

    def _is_local_explicit(self, decision: Decision) -> bool:
        """True when local rules made an explicit decision (not a default)."""
        if decision.action in ("allow", "grant"):
            return not decision.rule.startswith("default")
        if decision.action == "ask":
            return not (decision.rule == "default_decision" or decision.rule.endswith(".default"))
        return decision.rule != "default_decision"

    async def _query(self, agent: str, server: str, tool: str,
                     arguments: dict[str, Any] | None) -> dict[str, Any]:
        import httpx2

        if self._client is not None:
            client = self._client
            own = False
        else:
            client = httpx2.AsyncClient(timeout=self.timeout)
            own = True
        try:
            resp = await client.post(
                self.url,
                json={"input": {"agent": agent, "server": server, "tool": tool,
                                "arguments": arguments or {}}},
            )
            resp.raise_for_status()
            data = resp.json()
        finally:
            if own:
                await client.aclose()
        # OPA wraps the document in {"result": ...}; accept both shapes
        if isinstance(data, dict) and "result" in data and isinstance(data["result"], dict):
            return data["result"]
        return data if isinstance(data, dict) else {}

    async def evaluate_async(self, agent: str, server: str, tool: str,
                             arguments: dict[str, Any] | None) -> Decision:
        # NOTE: call the base implementation explicitly - self.evaluate is
        # overridden below to return a coroutine for the gateway's await path
        local = PolicyEngine.evaluate(self, agent, server, tool, arguments)
        if self._is_local_explicit(local):
            return local
        try:
            body = await self._query(agent, server, tool, arguments)
        except Exception:  # noqa: BLE001 - fail-closed on any backend failure
            return Decision(action="deny", rule=f"opa:error({self.url})")
        action = str(body.get("decision", "deny"))
        if action not in ("allow", "deny", "ask"):
            return Decision(action="deny", rule=f"opa:invalid({action!r})")
        return Decision(action=action, rule=f"opa:{self.url}")

    def evaluate(self, agent, server, tool, arguments):  # type: ignore[override]
        # sync call sites get a local-only answer; the gateway awaits
        # evaluate_async when the engine provides it (see Gateway._call_tool)
        return self.evaluate_async(agent, server, tool, arguments)
