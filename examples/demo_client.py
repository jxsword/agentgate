"""Demo MCP client: reproduces the documented agentgate workflow end to end.

Topology (same as Claude Code would create):

    demo_client.py --stdio--> agentgate run --config policies/example.yaml --agent claude-code
                              --stdio--> examples/demo_server.py

Run from the agentgate project root:

    # terminal 1 (implicit: this script spawns the gateway itself)
    python examples/demo_client.py            # interactive: follow approval prompts
    python examples/demo_client.py --yes      # auto-approve (demo shortcut only)

`python` on PATH must be the interpreter that has `mcp` installed
(e.g. the project venv).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentgate.approvals import ApprovalManager  # noqa: E402


def text_of(result) -> str:
    return "\n".join(getattr(c, "text", "") for c in result.content)


async def auto_approve_when_pending(state_dir: Path) -> None:
    """Demo shortcut: approve the next pending request (never do this in prod)."""
    import time

    mgr = ApprovalManager(state_dir)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        pending = mgr.list_pending()
        if pending and "id" in pending[0]:
            mgr.decide(pending[0]["id"], allow=True, approver="demo-auto")
            print(f"[demo] auto-approved {pending[0]['id']} (demo shortcut)")
            return
        await asyncio.sleep(0.2)
    print("[demo] no pending request appeared")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "policies" / "example.yaml"))
    ap.add_argument("--yes", action="store_true", help="auto-approve asks (demo shortcut)")
    args = ap.parse_args()

    env = {"AGENTGATE_DEMO": "1"}  # marker; gateway merges with inherited env
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentgate", "run", "--config", args.config,
              "--agent", "claude-code", "--ask-timeout", "120"],
        env=env,
    )
    state_dir = ROOT / ".agentgate"

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(f"[demo] connected: {init.server_info.name}")

            tools = await session.list_tools()
            print(f"[demo] tools: {[t.name for t in tools.tools]}")

            print("\n--- 1. allow (echo) ---")
            res = await session.call_tool("demo--echo", {"text": "hello agentgate"})
            print(f"    is_error={res.is_error}  {text_of(res)}")

            print("\n--- 2. ask -> approval -> delegation grant (write_file) ---")
            write_args = {"path": "sandbox/demo/hello.txt", "content": "written by agentgate demo"}
            if args.yes:
                approver = asyncio.create_task(auto_approve_when_pending(state_dir))
            else:
                print("    >> run in another terminal: agentgate pending && agentgate approve <id> --allow")
                approver = None
            res = await session.call_tool("demo--write_file", write_args)
            if approver:
                await approver
            print(f"    is_error={res.is_error}  {text_of(res)}")

            print("\n--- 3. same call again: should hit the grant (no approval) ---")
            res = await session.call_tool("demo--write_file", write_args)
            print(f"    is_error={res.is_error}  {text_of(res)}")

            print("\n--- 4. deny (delete_file) ---")
            res = await session.call_tool("demo--delete_file", {"path": "sandbox/demo/hello.txt"})
            print(f"    is_error={res.is_error}  {text_of(res)}")

            print("\n--- 5. prompts & resources (V1.1) ---")
            prompts = await session.list_prompts()
            print(f"    prompts: {[p.name for p in prompts.prompts]}")
            got = await session.get_prompt("demo--greet", {"user": "agentgate"})
            print(f"    prompt result: {got.messages[0].content.text}")
            resources = await session.list_resources()
            print(f"    resources: {[str(r.uri) for r in resources.resources]}")
            if resources.resources:
                read = await session.read_resource(str(resources.resources[0].uri))
                print(f"    resource body: {read.contents[0].text[:60]!r}")

    print("\n--- audit tail (agentgate log -n 12) ---")
    audit = state_dir / "audit.jsonl"
    if audit.exists():
        for line in audit.read_text(encoding="utf-8").splitlines()[-12:]:
            print("   ", line)
    print("\n[demo] done. grants: agentgate grants | revoke: agentgate revoke <id>")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
