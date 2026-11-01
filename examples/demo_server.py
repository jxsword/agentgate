"""Demo upstream MCP server used by agentgate examples and tests.

Exposes deliberately mixed-risk tools so the policy in policies/example.yaml
has something to bite on:

  echo(text)                      -> harmless
  read_file(path)                 -> harmless within sandbox
  write_file(path, content)       -> risky: gated by `ask` + delegation grant
  delete_file(path)               -> always denied by policy

Run standalone:  python examples/demo_server.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

SANDBOX = Path(os.environ.get("DEMO_SANDBOX", Path(__file__).parent / "demo_sandbox")).resolve()


def _resolve(path: str) -> Path:
    p = (SANDBOX / path).resolve()
    if not p.is_relative_to(SANDBOX):
        raise ValueError(f"path escapes sandbox: {path}")
    return p


def text(s: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=s)])


async def main() -> None:
    sandbox = str(SANDBOX)

    async def list_tools(ctx, params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="echo",
                    description="Echo the given text back. Harmless.",
                    input_schema={
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"],
                    },
                ),
                types.Tool(
                    name="read_file",
                    description=f"Read a text file inside the sandbox ({sandbox}).",
                    input_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                ),
                types.Tool(
                    name="write_file",
                    description=f"Write a text file inside the sandbox ({sandbox}). Risky.",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                        },
                        "required": ["path", "content"],
                    },
                ),
                types.Tool(
                    name="delete_file",
                    description="Delete a file inside the sandbox. Very risky.",
                    input_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                ),
            ]
        )

    async def call_tool(ctx, params: types.CallToolRequestParams):
        args = params.arguments or {}
        try:
            if params.name == "echo":
                return text(f"echo: {args.get('text', '')}")
            if params.name == "read_file":
                p = _resolve(str(args["path"]))
                return text(p.read_text(encoding="utf-8") if p.exists() else f"(missing) {p}")
            if params.name == "write_file":
                p = _resolve(str(args["path"]))
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(str(args["content"]), encoding="utf-8")
                return text(f"wrote {p} ({len(args['content'])} bytes)")
            if params.name == "delete_file":
                p = _resolve(str(args["path"]))
                if p.exists():
                    p.unlink()
                return text(f"deleted {p}")
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"unknown tool {params.name}")],
                is_error=True,
            )
        except Exception as e:  # noqa: BLE001
            return text(f"error: {e}")

    # ---- prompts & resources (V1.1 demo) ----

    async def list_prompts(ctx, params):
        return types.ListPromptsResult(
            prompts=[
                types.Prompt(
                    name="greet",
                    description="Build a greeting message for a named user.",
                    arguments=[
                        types.PromptArgument(
                            name="user", description="who to greet", required=True
                        )
                    ],
                )
            ]
        )

    async def get_prompt(ctx, params: types.GetPromptRequestParams):
        if params.name != "greet":
            return types.GetPromptResult(
                description="unknown prompt",
                messages=[types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=f"unknown prompt {params.name}"),
                )],
            )
        user = (params.arguments or {}).get("user", "world")
        return types.GetPromptResult(
            description="greeting",
            messages=[types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=f"Hello, {user}!"),
            )],
        )

    def _sandbox_files() -> list[Path]:
        if not SANDBOX.exists():
            return []
        return [p for p in SANDBOX.rglob("*") if p.is_file()]

    async def list_resources(ctx, params):
        return types.ListResourcesResult(
            resources=[
                types.Resource(
                    uri=f"demo://file/{p.relative_to(SANDBOX).as_posix()}",
                    name=p.name,
                    mime_type="text/plain",
                    description="sandbox file",
                )
                for p in _sandbox_files()
            ]
        )

    async def read_resource(ctx, params: types.ReadResourceRequestParams):
        uri = str(params.uri)
        if not uri.startswith("demo://file/"):
            raise ValueError(f"unsupported resource uri: {uri}")
        rel = uri.removeprefix("demo://file/")
        p = _resolve(rel)
        if not p.exists():
            raise ValueError(f"resource not found: {uri}")
        content = p.read_text(encoding="utf-8")
        return types.ReadResourceResult(
            contents=[types.TextResourceContents(
                uri=uri, mime_type="text/plain", text=content,
            )]
        )

    server = Server(
        "demo-server",
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        on_list_prompts=list_prompts,
        on_get_prompt=get_prompt,
        on_list_resources=list_resources,
        on_read_resource=read_resource,
    )

    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    print(f"[demo-server] sandbox={SANDBOX}", file=sys.stderr)
    import asyncio

    asyncio.run(main())
