"""The MCP gateway: one stdio MCP server in front of N upstream MCP servers.

Tool namespace: upstream tools are exposed as "<server>--<tool>" so multiple
servers can be aggregated without collisions. Every tools/call passes through
the policy engine; allow/grant calls are proxied, deny calls fail closed with
an explanatory error result, ask calls wait for a human decision via the
file-based approval flow. Every decision is appended to the audit log.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import AsyncExitStack
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .approvals import ApprovalManager
from .audit import AuditLog
from .config import Config
from .grants import GrantStore
from .policy import Decision, PolicyEngine, canonical_args
from .upstream import Upstream

NS_SEP = "--"


def split_tool_name(name: str) -> tuple[str, str] | None:
    """Split '<server>--<tool>' -> (server, tool); None if not namespaced."""
    if NS_SEP not in name:
        return None
    server, tool = name.split(NS_SEP, 1)
    return (server, tool) if server and tool else None


def error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], is_error=True)


class Gateway:
    def __init__(
        self,
        config: Config,
        agent: str,
        engine: PolicyEngine,
        approvals: ApprovalManager,
        grants: GrantStore,
        audit: AuditLog,
    ) -> None:
        self.config = config
        self.agent = agent
        self.engine = engine
        self.approvals = approvals
        self.grants = grants
        self.audit = audit
        self.upstreams: dict[str, Upstream] = {}

    async def _start_upstreams(self, stack: AsyncExitStack) -> None:
        for name, scfg in self.config.servers.items():
            upstream = Upstream(scfg)
            try:
                await upstream.start(stack)
                self.upstreams[name] = upstream
            except Exception as e:  # noqa: BLE001 - one bad upstream must not kill the gateway
                print(f"[agentgate] FAILED to start upstream '{name}': {e}", file=sys.stderr)
                self.audit.append(
                    "upstream_error", server=name, error=str(e), agent=self.agent
                )
        if not self.upstreams and self.config.servers:
            raise RuntimeError("no upstream MCP server could be started")

    # ---- MCP handlers ----

    async def _list_tools(self, ctx, params) -> types.ListToolsResult:
        merged: list[types.Tool] = []
        for name, upstream in self.upstreams.items():
            try:
                for tool in await upstream.list_tools():
                    merged.append(
                        types.Tool(
                            name=f"{name}{NS_SEP}{tool.name}",
                            description=tool.description,
                            input_schema=tool.input_schema,
                            title=tool.title,
                        )
                    )
            except Exception as e:  # noqa: BLE001
                print(f"[agentgate] list_tools failed for '{name}': {e}", file=sys.stderr)
        return types.ListToolsResult(tools=merged)

    async def _call_tool(self, ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name = params.name
        arguments = dict(params.arguments or {})
        parsed = split_tool_name(name)
        if parsed is None or not parsed[1] or parsed[0] not in self.upstreams:
            self.audit.append(
                "call_denied",
                agent=self.agent,
                server=parsed[0] if parsed else "(none)",
                tool=parsed[1] if parsed else name,
                arguments_hash=canonical_args(arguments),
                rule="unknown_tool",
                decision="deny",
            )
            return error_result(
                f"agentgate: unknown tool {name!r}. Tools are namespaced '<server>--<tool>'; "
                f"call tools/list to discover what this gateway exposes."
            )
        server, tool = parsed

        try:
            decision = self.engine.evaluate(self.agent, server, tool, arguments)
        except Exception as e:  # noqa: BLE001 - policy engine bugs must never open the gate
            self.audit.append(
                "policy_error",
                agent=self.agent,
                server=server,
                tool=tool,
                arguments_hash=canonical_args(arguments),
                error=str(e),
            )
            return error_result(
                f"agentgate: policy evaluation failed ({e}); call denied (fail-closed)."
            )
        base = dict(
            agent=self.agent,
            server=server,
            tool=tool,
            arguments_hash=canonical_args(arguments),
            rule=decision.rule,
        )

        if decision.action in ("allow", "grant"):
            return await self._proxy(server, tool, arguments, decision, base, decision.action)

        if decision.action == "deny":
            self.audit.append("call_denied", decision="deny", **base)
            return error_result(
                f"agentgate: tool {name!r} denied by policy (matched rule: {decision.rule}). "
                f"If you believe this is wrong, ask the human operator to update the agentgate policy."
            )

        # decision.action == "ask"
        return await self._ask_and_proxy(server, tool, arguments, decision, base)

    async def _proxy(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        decision: Decision,
        base: dict[str, Any],
        decision_label: str,
    ) -> types.CallToolResult:
        self.audit.append(
            "call", decision=decision_label, grant_id=decision.grant_id, **base
        )
        try:
            result = await self.upstreams[server].call_tool(tool, arguments)
        except Exception as e:  # noqa: BLE001
            self.audit.append("upstream_error", error=str(e), **base)
            return error_result(f"agentgate: upstream '{server}' failed: {e}")
        self.audit.append(
            "call_result",
            decision=decision_label,
            is_error=bool(result.is_error),
            n_content=len(result.content),
            **base,
        )
        return result

    async def _ask_and_proxy(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        decision: Decision,
        base: dict[str, Any],
    ) -> types.CallToolResult:
        full_name = f"{server}{NS_SEP}{tool}"
        if self.config.on_ask == "deny":
            self.audit.append("ask_denied", reason="on_ask=deny (unattended mode)", **base)
            return error_result(
                f"agentgate: tool {full_name!r} requires human approval but the gateway "
                f"is running unattended (on_ask=deny). Denied."
            )

        delegation = (
            {"ttl_seconds": decision.delegation_ttl, "bind": decision.delegation_bind}
            if decision.delegation_ttl
            else None
        )
        request = self.approvals.create_request(
            self.agent, server, tool, arguments, decision.rule, delegation
        )
        self.audit.append("approval_requested", request_id=request["id"], **base)
        print(
            f"\n[agentgate] APPROVAL NEEDED id={request['id']} agent={self.agent} "
            f"tool={full_name}\n[agentgate]   arguments: {canonical_args(arguments)}\n"
            f"[agentgate]   rule: {decision.rule}\n"
            f"[agentgate]   approve with: agentgate approve {request['id']} --allow\n"
            f"[agentgate]   waiting up to {self.config.ask_timeout_seconds}s ...\n",
            file=sys.stderr,
        )
        try:
            human = await self.approvals.wait(request["id"], self.config.ask_timeout_seconds)
        except TimeoutError:
            self.approvals.remove_request(request["id"])  # FR-AP-006: clean up on timeout
            self.audit.append("ask_denied", reason="approval timeout", request_id=request["id"], **base)
            return error_result(
                f"agentgate: approval for {full_name!r} timed out "
                f"({self.config.ask_timeout_seconds}s). Denied (fail-closed)."
            )

        if not human.get("allow"):
            self.audit.append(
                "ask_denied", request_id=request["id"], approver=human.get("approver"), **base
            )
            return error_result(
                f"agentgate: human '{human.get('approver')}' denied tool {full_name!r}."
            )

        grant_id = None
        if delegation:
            grant = self.grants.add(
                agent=self.agent,
                server=server,
                tool=tool,
                arguments=arguments,
                ttl_seconds=int(delegation["ttl_seconds"]),
                bind=str(delegation["bind"]),
                approver=human.get("approver", "human"),
            )
            grant_id = grant.id
            self.audit.append(
                "grant_created",
                request_id=request["id"],
                grant_id=grant.id,
                ttl_seconds=delegation["ttl_seconds"],
                bind=delegation["bind"],
                approver=human.get("approver"),
                **base,
            )
        proxied = Decision(
            action="ask_allowed", rule=decision.rule, grant_id=grant_id
        )
        return await self._proxy(server, tool, arguments, proxied, base, "ask_allowed")

    # ---- lifecycle ----

    def build_server(self) -> Server:
        server = Server(
            f"agentgate-{self.agent}",
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )
        return server

    async def run_stdio(self) -> None:
        async with AsyncExitStack() as stack:
            await self._start_upstreams(stack)
            server = self.build_server()
            self.audit.append(
                "gateway_start",
                agent=self.agent,
                servers=sorted(self.upstreams),
                on_ask=self.config.on_ask,
            )
            try:
                async with stdio_server() as (read, write):
                    await server.run(read, write, server.create_initialization_options())
            finally:
                self.audit.append("gateway_stop", agent=self.agent)


async def serve(config: Config, agent: str, state_dir: str | None = None) -> None:
    from pathlib import Path

    state = Path(state_dir) if state_dir is not None else config.state_dir
    state.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(state / "audit.jsonl")
    grants = GrantStore(state / "grants.json")
    approvals = ApprovalManager(state)
    engine = PolicyEngine(config, grants)
    gateway = Gateway(config, agent, engine, approvals, grants, audit)
    await gateway.run_stdio()


def serve_sync(config: Config, agent: str, state_dir: str | None = None) -> None:
    asyncio.run(serve(config, agent, state_dir))
