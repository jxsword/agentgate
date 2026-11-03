"""The MCP gateway: one stdio MCP server in front of N upstream MCP servers.

Tool namespace: upstream tools are exposed as "<server>--<tool>" so multiple
servers can be aggregated without collisions. Every tools/call passes through
the policy engine; allow/grant calls are proxied, deny calls fail closed with
an explanatory error result, ask calls wait for a human decision via the
file-based approval flow. Every decision is appended to the audit log.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import sys
from contextlib import AsyncExitStack
from typing import Any

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .approvals import ApprovalManager, approval_secret, verify_decision
from .audit import AuditLog
from .config import AgentPolicy, Config
from .grants import GrantStore
from .policy import Decision, PolicyEngine, canonical_args
from .ratelimit import RateLimiter
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
        config_path: str | None = None,
        watch_policy: bool = True,
    ) -> None:
        self.config = config
        self.agent = agent
        self.engine = engine
        self.approvals = approvals
        self.grants = grants
        self.audit = audit
        self.config_path = config_path
        self.watch_policy = watch_policy
        self.upstreams: dict[str, Upstream] = {}
        self.rate_limiter = RateLimiter()
        self.rate_limiter.bind(lambda a, s: self.config.agents.get(a, AgentPolicy()).servers.get(s))
        self._tools_cache: tuple[float, types.ListToolsResult] | None = None
        # P1-2 (v0.6 review): hot-reload must fail CLOSED for retired identities —
        # an agent/server removed from the policy keeps serving only if we let it
        self.retired = False
        self.retired_servers: set[str] = set()

    def _reload_policy_once(self, path, last_mtime) -> float | None:
        """One hot-reload step; returns the mtime to remember (None on stat error)."""
        from pathlib import Path

        path = Path(path)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return last_mtime
        if mtime == last_mtime:
            return mtime
        from .config import ConfigError, load_config

        try:
            new_config = load_config(path)
        except Exception as e:  # noqa: BLE001 - ANY reload failure keeps the old policy
            self.audit.append("policy_reload_failed", agent=self.agent, error=str(e))
            print(f"[agentgate] policy reload FAILED (keeping old policy): {e}", file=sys.stderr)
            return mtime
        # P1-2: retire identities/servers that the new policy removed (fail-closed)
        if self.agent not in new_config.agents:
            self.retired = True
            self.audit.append("policy_reload_failed", agent=self.agent,
                              error="agent removed from policy; identity retired (deny-all)")
            print(f"[agentgate] agent '{self.agent}' removed from policy -> retired (deny-all)",
                  file=sys.stderr)
        else:
            self.retired_servers |= (set(self.config.servers) - set(new_config.servers)) \
                if self.agent in self.config.agents else set()
            if self.retired_servers & set(self.upstreams):
                print(f"[agentgate] servers retired after reload: "
                      f"{sorted(self.retired_servers & set(self.upstreams))}", file=sys.stderr)
        self.config = new_config
        self.engine.config = new_config
        self.audit.append("policy_reloaded", agent=self.agent,
                          agents=sorted(new_config.agents), servers=sorted(new_config.servers))
        print(f"[agentgate] policy reloaded from {path}", file=sys.stderr)
        return mtime

    async def _watch_policy(self) -> None:
        """V1.2: hot-reload the policy file (atomic swap; errors keep the old policy)."""
        import asyncio
        from pathlib import Path

        if not self.config_path:
            return
        path = Path(self.config_path)
        try:
            last_mtime: float | None = path.stat().st_mtime
        except OSError:
            return
        while True:
            await asyncio.sleep(2.0)
            last_mtime = self._reload_policy_once(path, last_mtime)

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
        # G6: short-TTL cache - clients poll tools/list aggressively; the merged
        # snapshot is reused for list_cache_seconds (0 = off)
        ttl = self.config.list_cache_seconds
        if ttl:
            import time as _time

            now = _time.monotonic()
            if self._tools_cache and now - self._tools_cache[0] < ttl:
                return self._tools_cache[1]
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
        result = types.ListToolsResult(tools=merged)
        if ttl:
            import time as _time

            self._tools_cache = (_time.monotonic(), result)
        return result

    def _server_policy(self, server: str):
        return self.config.agents.get(self.agent, AgentPolicy()).servers.get(server)

    def _redact(self, server: str, arguments: dict[str, Any]) -> dict[str, Any]:
        spol = self._server_policy(server)
        return spol.redact_arguments(arguments) if spol else arguments

    async def _call_tool(self, ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name = params.name
        arguments = dict(params.arguments or {})
        # P1-2: hot-reload retirement gate - an identity/server removed from the
        # policy must deny everything, regardless of leftover rules
        if self.retired:
            self.audit.append("call_denied", agent=self.agent, server="(retired)",
                              tool=name, arguments_hash=canonical_args(arguments),
                              rule="retired_identity", decision="deny")
            return error_result(
                f"agentgate: agent identity {self.agent!r} was retired from the policy "
                f"(hot-reload). All calls denied."
            )
        parsed = split_tool_name(name)
        if parsed is None or not parsed[1] or parsed[0] not in self.upstreams:
            unknown: dict[str, Any] = dict(
                agent=self.agent,
                server=parsed[0] if parsed else "(none)",
                tool=parsed[1] if parsed else name,
                arguments_hash=canonical_args(arguments),
                rule="unknown_tool",
                decision="deny",
            )
            if self.config.audit_arguments:
                # P2-8: redact whenever the server is identifiable, even on unknown-tool
                if parsed and parsed[0] in self.upstreams:
                    unknown["arguments"] = self._redact(parsed[0], arguments)
                else:
                    unknown["arguments"] = arguments
            self.audit.append("call_denied", **unknown)
            return error_result(
                f"agentgate: unknown tool {name!r}. Tools are namespaced '<server>--<tool>'; "
                f"call tools/list to discover what this gateway exposes."
            )
        server, tool = parsed
        if server in self.retired_servers:
            self.audit.append("call_denied", agent=self.agent, server=server,
                              tool=tool, arguments_hash=canonical_args(arguments),
                              rule="retired_server", decision="deny")
            return error_result(
                f"agentgate: upstream '{server}' was removed from the policy "
                f"(hot-reload). Denied (fail-closed)."
            )

        try:
            maybe = self.engine.evaluate(self.agent, server, tool, arguments)
            decision = await maybe if inspect.isawaitable(maybe) else maybe
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
        if self.config.audit_arguments:  # H1: opt-in debug aid (default: hash only)
            base["arguments"] = self._redact(server, arguments)

        # F3: rate limit gates calls the policy would let through (allow/grant/ask);
        # explicit denies are unaffected. Fail-closed on exceed.
        if decision.action in ("allow", "grant", "ask"):
            limiter_result = self.rate_limiter.check_and_record(self.agent, server)
            if limiter_result.limited:
                self.audit.append(
                    "rate_limited", decision="deny", retry_after=limiter_result.retry_after,
                    limit=limiter_result.limit, **base,
                )
                return error_result(
                    f"agentgate: rate limit reached for {self.agent}@{server} "
                    f"({limiter_result.limit} calls/window). Retry after "
                    f"{limiter_result.retry_after}s (fail-closed)."
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
            # F2: the SDK wraps read-deadline expiry in various shapes (TimeoutError,
            # McpError("Request 'tools/call' timed out"), ExceptionGroup) - match both
            timed_out = isinstance(e, (asyncio.TimeoutError, TimeoutError)) or \
                "timed out" in str(e).lower()
            if timed_out:
                self.audit.append("upstream_timeout", error=str(e), **base)
                return error_result(
                    f"agentgate: upstream '{server}' did not answer tool {tool!r} within "
                    f"{self.config.servers[server].call_timeout_seconds}s (call_timeout_seconds)."
                )
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
            self.agent, server, tool, self._redact(server, arguments),
            decision.rule, delegation,
            arguments_hash=canonical_args(arguments),
        )
        self.audit.append("approval_requested", request_id=request["id"], **base)
        print(
            f"\n[agentgate] APPROVAL NEEDED id={request['id']} agent={self.agent} "
            f"tool={full_name}\n[agentgate]   arguments: {canonical_args(self._redact(server, arguments))}\n"
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

        # EX-3: when AGENTGATE_APPROVAL_SECRET is set, decisions must carry a
        # valid HMAC. An invalid/unsigned decision counts as denial (fail-closed).
        secret = approval_secret()
        if secret is not None and not verify_decision(request, human, secret):
            self.approvals.remove_request(request["id"])
            self.audit.append(
                "approval_signature_invalid", request_id=request["id"], approver=human.get("approver"),
                **base,
            )
            return error_result(
                f"agentgate: approval decision for {full_name!r} failed signature "
                f"verification. Denied (fail-closed)."
            )

        if not human.get("allow"):
            reason = human.get("reason")
            self.audit.append(
                "ask_denied", request_id=request["id"], approver=human.get("approver"),
                reason=reason, **base,
            )
            return error_result(
                f"agentgate: human '{human.get('approver')}' denied tool {full_name!r}."
                + (f" Reason: {reason}" if reason else "")
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

    # ---- non-tool capability handlers (V1.1, EX-4) ----

    def _allowed_servers(self, kind: str) -> list[str]:
        return [
            name for name in self.upstreams
            if self.engine.check_capability(self.agent, name, kind)[0]
        ]

    def _deny_capability(self, kind: str, detail: dict[str, Any], text: str) -> types.CallToolResult:
        self.audit.append(f"{kind}_denied", decision="deny", **detail)
        return error_result(text)

    @staticmethod
    def _denial_message(text: str) -> list[types.PromptMessage]:
        return [types.PromptMessage(
            role="user", content=types.TextContent(type="text", text=text)
        )]

    async def _list_prompts(self, ctx, params) -> types.ListPromptsResult:
        merged: list[types.Prompt] = []
        for name in self._allowed_servers("prompts"):
            try:
                for prompt in await self.upstreams[name].list_prompts():
                    merged.append(
                        types.Prompt(
                            name=f"{name}{NS_SEP}{prompt.name}",
                            description=prompt.description,
                            arguments=list(prompt.arguments or []),
                        )
                    )
            except Exception as e:  # noqa: BLE001
                print(f"[agentgate] list_prompts failed for '{name}': {e}", file=sys.stderr)
        return types.ListPromptsResult(prompts=merged)

    async def _get_prompt(self, ctx, params: types.GetPromptRequestParams) -> types.GetPromptResult:
        parsed = split_tool_name(params.name)
        detail = dict(agent=self.agent, prompt=params.name, rule="unknown_prompt")
        if parsed is None or parsed[0] not in self.upstreams:
            self.audit.append("prompt_denied", decision="deny", **detail)
            return types.GetPromptResult(messages=self._denial_message(
                f"agentgate: unknown prompt {params.name!r} (namespaced '<server>--<prompt>')"
            ))
        server, prompt_name = parsed
        allowed, rule = self.engine.check_capability(self.agent, server, "prompts")
        detail.update(server=server, prompt=prompt_name, rule=rule)
        if not allowed:
            self.audit.append("prompt_denied", decision="deny", **detail)
            return types.GetPromptResult(messages=self._denial_message(
                f"agentgate: prompts on server '{server}' denied by policy (rule: {rule})."
            ))
        self.audit.append("prompt_call", decision="allow", **detail)
        try:
            return await self.upstreams[server].get_prompt(prompt_name, dict(params.arguments or {}))
        except Exception as e:  # noqa: BLE001
            self.audit.append("upstream_error", error=str(e), **detail)
            return error_result(f"agentgate: upstream '{server}' failed: {e}")

    async def _list_resources(self, ctx, params) -> types.ListResourcesResult:
        merged: list[types.Resource] = []
        seen: set[str] = set()
        for name in self._allowed_servers("resources"):
            try:
                for resource in await self.upstreams[name].list_resources():
                    if resource.uri in seen:  # first allowed server wins on URI collision
                        continue
                    seen.add(resource.uri)
                    merged.append(resource)
            except Exception as e:  # noqa: BLE001
                print(f"[agentgate] list_resources failed for '{name}': {e}", file=sys.stderr)
        return types.ListResourcesResult(resources=merged)

    async def _list_resource_templates(self, ctx, params) -> types.ListResourceTemplatesResult:
        merged: list[types.ResourceTemplate] = []
        for name in self._allowed_servers("resources"):
            try:
                for template in await self.upstreams[name].list_resource_templates():
                    merged.append(
                        types.ResourceTemplate(
                            uri_template=template.uri_template,
                            name=f"{name}{NS_SEP}{template.name}" if template.name else template.name,
                            description=template.description,
                            mime_type=template.mime_type,
                        )
                    )
            except Exception as e:  # noqa: BLE001
                print(f"[agentgate] list_resource_templates failed for '{name}': {e}", file=sys.stderr)
        return types.ListResourceTemplatesResult(resource_templates=merged)

    async def _read_resource(self, ctx, params: types.ReadResourceRequestParams) -> types.ReadResourceResult:
        uri = str(params.uri)
        detail = dict(agent=self.agent, uri=uri)
        allowed = self._allowed_servers("resources")
        # 1) try servers that advertised this URI; 2) otherwise probe allowed servers in order
        candidates: list[str] = []
        for name in allowed:
            try:
                resources = await self.upstreams[name].list_resources()
            except Exception:  # noqa: BLE001 - listing failure must not block read probing
                continue
            if any(str(r.uri) == uri for r in resources):
                candidates.append(name)
        candidates += [n for n in allowed if n not in candidates]

        last_error: Exception | None = None
        for server in candidates:
            probe = dict(detail, server=server)
            allowed_rule = self.engine.check_capability(self.agent, server, "resources")
            if not allowed_rule[0]:
                continue
            try:
                result = await self.upstreams[server].read_resource(uri)
            except Exception as e:  # noqa: BLE001 - not found on this server: try next
                last_error = e
                continue
            self.audit.append(
                "resource_call", decision="allow", server=server,
                rule=f"agents.{self.agent}.servers.{server}.resources", **detail,
            )
            return result
        self.audit.append(
            "resource_denied", decision="deny", server=",".join(allowed) or "(none)",
            rule="agents.*.servers.*.resources", error=str(last_error) if last_error else None,
            **detail,
        )
        return types.ReadResourceResult(
            contents=[types.TextResourceContents(
                uri=uri, mime_type="text/plain",
                text=f"agentgate: resource {uri!r} not reachable: not allowed by policy "
                     f"or not found on any allowed server.",
            )]
        )

    # ---- lifecycle ----

    def _startup_cleanup(self) -> None:
        """G2: crash leftovers older than the ask timeout cannot belong to a live waiter."""
        removed = self.approvals.cleanup_stale(self.config.ask_timeout_seconds)
        if removed:
            self.audit.append("pending_cleanup", agent=self.agent, removed=removed)
            print(f"[agentgate] removed {removed} stale pending approval file(s)", file=sys.stderr)

    # ---- ops endpoints (G4) ----

    def _status_payload(self) -> dict[str, Any]:
        payload = {
            "agent": self.agent,
            "upstreams": {
                name: (u.server_info.name if u.server_info else "?")
                for name, u in self.upstreams.items()
            },
            "on_ask": self.config.on_ask,
            "ask_timeout_seconds": self.config.ask_timeout_seconds,
            "policy_backend": getattr(self.config, "policy_backend_url", None),
        }
        # H2: rate-limit window occupancy for this agent
        limits = {}
        for server in self.upstreams:
            n = self.rate_limiter.current(self.agent, server)
            if n:
                limits[server] = n
        payload["rate_windows"] = limits
        return payload

    async def _healthz(self, request):
        from starlette.responses import JSONResponse

        return JSONResponse({"ok": True})

    async def _status(self, request):
        from starlette.responses import JSONResponse

        return JSONResponse(self._status_payload())

    def build_server(self) -> Server:
        server = Server(
            f"agentgate-{self.agent}",
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
            on_list_prompts=self._list_prompts,
            on_get_prompt=self._get_prompt,
            on_list_resources=self._list_resources,
            on_list_resource_templates=self._list_resource_templates,
            on_read_resource=self._read_resource,
        )
        return server

    async def run_stdio(self) -> None:
        async with AsyncExitStack() as stack:
            await self._start_upstreams(stack)
            self._startup_cleanup()
            watcher = None
            if self.watch_policy and self.config_path:
                watcher = asyncio.create_task(self._watch_policy())
            server = self.build_server()
            self.audit.append(
                "gateway_start",
                agent=self.agent,
                servers=sorted(self.upstreams),
                on_ask=self.config.on_ask,
                transport="stdio",
            )
            try:
                async with stdio_server() as (read, write):
                    await server.run(read, write, server.create_initialization_options())
            finally:
                if watcher:
                    watcher.cancel()
                self.audit.append("gateway_stop", agent=self.agent)

    async def run_http(self, host: str, port: int) -> None:
        """Serve the same gateway over streamable HTTP (V1.1, EX-1).

        Multiple clients can share one gateway process; the agent identity is
        the --agent flag, applied to every connection.
        """
        import uvicorn

        # P1-4 (v0.6 review): a non-loopbind HTTP gateway exposes the agent's
        # entire policy surface unauthenticated - refuse unless the operator
        # explicitly opts in via the same env gate the console uses
        if host not in ("127.0.0.1", "localhost", "::1") and not os.environ.get("AGENTGATE_HTTP_EXPOSE_OK"):
            raise SystemExit(
                f"agentgate run --http {host}:{port}: refusing unauthenticated non-loopback "
                f"bind. Set AGENTGATE_HTTP_EXPOSE_OK=1 to accept the risk (prefer putting "
                f"an authenticating reverse proxy in front, or keep 127.0.0.1)."
            )
        async with AsyncExitStack() as stack:
            await self._start_upstreams(stack)
            self._startup_cleanup()
            watcher = None
            if self.watch_policy and self.config_path:
                watcher = asyncio.create_task(self._watch_policy())
            server = self.build_server()
            from starlette.routing import Route as _Route

            app = server.streamable_http_app(
                host=host,
                custom_starlette_routes=[
                    _Route("/healthz", self._healthz),
                    _Route("/status", self._status),
                ],
            )
            self.audit.append(
                "gateway_start",
                agent=self.agent,
                servers=sorted(self.upstreams),
                on_ask=self.config.on_ask,
                transport="http",
                http=f"{host}:{port}",
            )
            config = uvicorn.Config(app, host=host, port=port, log_level="warning")
            uvicorn_server = uvicorn.Server(config)
            try:
                await uvicorn_server.serve()
            finally:
                if watcher:
                    watcher.cancel()
                self.audit.append("gateway_stop", agent=self.agent)


async def serve(config: Config, agent: str, state_dir: str | None = None,
                http: str | None = None, config_path: str | None = None,
                watch_policy: bool = True, trust_agent_header: bool = False) -> None:
    from pathlib import Path

    state = Path(state_dir) if state_dir is not None else config.state_dir
    state.mkdir(parents=True, exist_ok=True)
    if http and agent.lower() == "all":
        host, _, port = http.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"--http expects HOST:PORT, got {http!r}")
        await serve_multi_http(config, state_dir, host, int(port),
                               config_path=config_path, watch_policy=watch_policy,
                               trust_agent_header=trust_agent_header)
        return
    if trust_agent_header:
        raise ValueError("--trust-agent-header requires --agent all together with --http")
    if agent.lower() == "all":
        raise ValueError("--agent all is only valid together with --http")
    audit = AuditLog(state / "audit.jsonl")
    grants = GrantStore(state / "grants.json")
    approvals = ApprovalManager(state)
    engine = PolicyEngine(config, grants)
    if getattr(config, "policy_backend_url", None):
        from .policy_backends import OpaPolicyEngine

        engine = OpaPolicyEngine(config, grants, url=config.policy_backend_url)
    gateway = Gateway(config, agent, engine, approvals, grants, audit,
                      config_path=config_path, watch_policy=watch_policy)
    if http:
        host, _, port = http.rpartition(":")
        if not host or not port.isdigit():
            raise ValueError(f"--http expects HOST:PORT, got {http!r}")
        await gateway.run_http(host, int(port))
    else:
        await gateway.run_stdio()


def serve_sync(config: Config, agent: str, state_dir: str | None = None,
               http: str | None = None, config_path: str | None = None,
               watch_policy: bool = True, trust_agent_header: bool = False) -> None:
    asyncio.run(serve(config, agent, state_dir, http, config_path, watch_policy,
                      trust_agent_header))


class AgentHeaderRouter:
    """I2 (v0.5): route one /mcp endpoint to per-agent upstreams by the
    X-Agentgate-Agent request header. Fail-closed: a missing or unknown
    identity is rejected - there is no default agent on this path."""

    HEADER = "x-agentgate-agent"

    def __init__(self, apps: dict[str, Any]) -> None:
        self.apps = apps  # agent -> StreamableHTTPASGIApp

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._respond(send, 404, "not found")
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        agent = headers.get(self.HEADER, "").strip()
        app = self.apps.get(agent)
        if app is None:
            await self._respond(
                send, 401,
                f"agentgate: missing or unknown {self.HEADER} header "
                f"(known: {', '.join(sorted(self.apps))})",)
            return
        await app(scope, receive, send)

    async def _respond(self, send, status: int, text: str) -> None:
        body = text.encode("utf-8")
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


async def serve_multi_http(config: Config, state_dir: str | None, host: str, port: int,
                           config_path: str | None = None, watch_policy: bool = True,
                           trust_agent_header: bool = False) -> None:
    """V1.2: one HTTP process serving every agent in the policy.

    Each agent gets its own Gateway (own upstream connections, own namespace)
    mounted at /<agent>/mcp. Grants/audit/approvals share the state directory
    (grants are agent-scoped records, so sharing the store is safe).
    """
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Route

    from mcp.server.streamable_http_manager import (
        StreamableHTTPASGIApp,
        StreamableHTTPSessionManager,
    )
    from mcp.server.transport_security import TransportSecuritySettings

    from pathlib import Path

    state = Path(state_dir) if state_dir is not None else config.state_dir
    state.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(state / "audit.jsonl")
    grants = GrantStore(state / "grants.json")
    approvals = ApprovalManager(state)

    security = TransportSecuritySettings(
        allowed_hosts=[f"{host}:*", "127.0.0.1:*", "localhost:*", "[::1]:*"],
        allowed_origins=["null"],
    ) if host in ("127.0.0.1", "localhost", "::1") else None

    units: list[tuple[Gateway, StreamableHTTPSessionManager]] = []
    core = AsyncExitStack()
    try:
        # one shared set of upstream connections; MCP sessions handle concurrent
        # requests, so N gateways can share M upstreams safely
        shared: dict[str, Upstream] = {}
        for name, scfg in config.servers.items():
            upstream = Upstream(scfg)
            try:
                await upstream.start(core)
                shared[name] = upstream
            except Exception as e:  # noqa: BLE001
                print(f"[agentgate] FAILED to start upstream '{name}': {e}", file=sys.stderr)
                audit.append("upstream_error", server=name, error=str(e), agent="(multi)")
        if not shared and config.servers:
            raise RuntimeError("no upstream MCP server could be started")

        for agent in sorted(config.agents):
            engine = PolicyEngine(config, grants)
            if getattr(config, "policy_backend_url", None):
                from .policy_backends import OpaPolicyEngine

                engine = OpaPolicyEngine(config, grants, url=config.policy_backend_url)
            gw = Gateway(config, agent, engine, approvals, grants, audit,
                         config_path=config_path, watch_policy=False)
            gw.upstreams = shared
            server = gw.build_server()
            manager = StreamableHTTPSessionManager(
                app=server, security_settings=security,
            )
            units.append((agent, gw, manager))
            audit.append("gateway_start", agent=agent, servers=sorted(gw.upstreams),
                         on_ask=config.on_ask, transport="http", http=f"{host}:{port}")

        async def _lifespan(app):
            async with AsyncExitStack() as lstack:
                for _, _, manager in units:
                    await lstack.enter_async_context(manager.run())
                yield

        async def _healthz(request):
            from starlette.responses import JSONResponse

            return JSONResponse({"ok": True, "agents": sorted(config.agents)})

        async def _status(request):
            from starlette.responses import JSONResponse

            return JSONResponse({
                "agents": sorted(config.agents),
                "upstreams": {n: (u.server_info.name if u.server_info else "?")
                              for n, u in shared.items()},
                "on_ask": config.on_ask,
                "ask_timeout_seconds": config.ask_timeout_seconds,
            })

        routes = [Route(f"/{agent}/mcp", StreamableHTTPASGIApp(manager),
                        methods=["GET", "POST", "DELETE"])
                  for agent, _, manager in units]
        routes += [Route("/healthz", _healthz), Route("/status", _status)]
        if trust_agent_header:
            # I2: one endpoint for all agents; identity comes per-request from
            # the X-Agentgate-Agent header (fail-closed on missing/unknown)
            header_apps = {agent: StreamableHTTPASGIApp(manager)
                           for agent, _, manager in units}
            routes.append(Route("/mcp", AgentHeaderRouter(header_apps),
                                methods=["GET", "POST", "DELETE"]))
        app = Starlette(routes=routes, lifespan=_lifespan)

        watcher = None
        if watch_policy and config_path:
            async def _watch_all():
                from .config import load_config

                path = Path(config_path)
                try:
                    last = path.stat().st_mtime
                except OSError:
                    last = 0.0
                while True:
                    await asyncio.sleep(2.0)
                    try:
                        mtime = path.stat().st_mtime
                    except OSError:
                        continue  # transient fs error: keep watching
                    if mtime == last:
                        continue
                    last = mtime
                    try:
                        new_config = load_config(path)
                    except Exception as e:  # noqa: BLE001 - P1-5: any reload failure keeps old policy
                        audit.append("policy_reload_failed", error=str(e))
                        print(f"[agentgate] policy reload FAILED (keeping old policy): {e}",
                              file=sys.stderr)
                        continue
                    # P1-2: retire agents/servers the new policy removed (fail-closed)
                    for agent, gw, _ in units:
                        if agent not in new_config.agents:
                            gw.retired = True
                            audit.append("policy_reload_failed", agent=agent,
                                         error="agent removed from policy; identity retired (deny-all)")
                        else:
                            gw.config = new_config
                            gw.engine.config = new_config
                            gw.retired_servers |= (set(gw.config.servers) - set(new_config.servers))
                    audit.append("policy_reloaded", agents=sorted(new_config.agents))
            watcher = asyncio.create_task(_watch_all())

        audit.append("gateway_start", agent="(multi)", agents=sorted(config.agents),
                     servers=sorted(config.servers), transport="http", http=f"{host}:{port}")
        uvicorn_server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
        try:
            await uvicorn_server.serve()
        finally:
            if watcher:
                watcher.cancel()
            await core.aclose()
            audit.append("gateway_stop", agent="(multi)")
    except BaseException:
        await core.aclose()
        raise
