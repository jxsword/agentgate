"""Upstream MCP server connections managed by the gateway."""

from __future__ import annotations

import sys
from typing import Any

import mcp_types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.client.streamable_http import streamable_http_client

from .config import ServerConfig


class UpstreamError(RuntimeError):
    pass


class Upstream:
    """A single upstream MCP server. Lifecycle: started via an AsyncExitStack
    owned by the gateway, so transports/sessions are cleaned up together."""

    def __init__(self, cfg: ServerConfig) -> None:
        self.cfg = cfg
        self.name = cfg.name
        self.session: ClientSession | None = None
        self.server_info: types.Implementation | None = None

    async def start(self, stack) -> None:
        if self.cfg.transport == "stdio":
            env = None
            if self.cfg.env:
                env = {**get_default_environment(), **self.cfg.env}
            params = StdioServerParameters(
                command=self.cfg.command, args=self.cfg.args, env=env
            )
            read, write = await stack.enter_async_context(stdio_client(params))
        else:
            # HTTP headers (e.g. auth) are supplied via a pre-configured httpx client;
            # v0.1 keeps header config out of the stdio path to avoid credential sprawl.
            if self.cfg.headers:
                raise UpstreamError(
                    f"upstream '{self.name}': http headers are not supported in v0.1; "
                    f"use an env-injected proxy or extend streamable_http_client wiring"
                )
            read, write = await stack.enter_async_context(
                streamable_http_client(self.cfg.url or "")
            )
        session = ClientSession(read, write)
        await stack.enter_async_context(session)
        init = await session.initialize()
        self.session = session
        self.server_info = init.server_info
        print(
            f"[agentgate] upstream '{self.name}' connected: {init.server_info.name} "
            f"v{init.server_info.version} (protocol {init.protocol_version})",
            file=sys.stderr,
        )

    async def list_tools(self) -> list[types.Tool]:
        if self.session is None:
            raise UpstreamError(f"upstream '{self.name}' not started")
        tools: list[types.Tool] = []
        cursor: str | None = None
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            result = await self.session.list_tools(params=params)
            tools.extend(result.tools)
            cursor = result.next_cursor
            if not cursor:
                break
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        if self.session is None:
            raise UpstreamError(f"upstream '{self.name}' not started")
        return await self.session.call_tool(name, arguments or {})

    # ---- non-tool capabilities (V1.1, EX-4) ----

    async def _paged(self, fetch, key: str) -> list[Any]:
        if self.session is None:
            raise UpstreamError(f"upstream '{self.name}' not started")
        out: list[Any] = []
        cursor: str | None = None
        while True:
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            result = await fetch(params=params)
            out.extend(getattr(result, key))
            cursor = result.next_cursor
            if not cursor:
                return out

    async def list_prompts(self) -> list[types.Prompt]:
        return await self._paged(self.session.list_prompts, "prompts")

    async def get_prompt(self, name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
        if self.session is None:
            raise UpstreamError(f"upstream '{self.name}' not started")
        return await self.session.get_prompt(name, arguments)

    async def list_resources(self) -> list[types.Resource]:
        return await self._paged(self.session.list_resources, "resources")

    async def read_resource(self, uri: str) -> types.ReadResourceResult:
        if self.session is None:
            raise UpstreamError(f"upstream '{self.name}' not started")
        return await self.session.read_resource(uri)

    async def list_resource_templates(self) -> list[types.ResourceTemplate]:
        return await self._paged(self.session.list_resource_templates, "resource_templates")
