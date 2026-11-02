"""v0.3 tests: agentgate check simulator (F1) + upstream call timeout (F2)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from agentgate.cli import main
from tests.test_e2e import SRC, open_session, write_config


def _write_policy(tmp_path: Path, tools: dict) -> Path:
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({
        "version": 1, "default_decision": "deny",
        "agents": {"bot": {"servers": {"fs": {"default": "ask", "tools": tools}}}},
    }), encoding="utf-8")
    return p


def test_check_single_case(tmp_path, capsys):
    cfg = _write_policy(tmp_path, {"echo": "allow", "delete_*": "deny"})
    rc = main(["check", "--config", str(cfg), "--agent", "bot",
               "--server", "fs", "--tool", "echo", "--args", '{"x": 1}'])
    assert rc == 0
    out = capsys.readouterr().out
    assert "echo: allow" in out and "agents.bot.servers.fs.tools.\"echo\"" in out

    rc = main(["check", "--config", str(cfg), "--agent", "bot",
               "--server", "fs", "--tool", "delete_all"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "delete_all: deny" in out
    # unmapped tool -> server default ask
    main(["check", "--config", str(cfg), "--agent", "bot",
          "--server", "fs", "--tool", "other"])
    assert "other: ask" in capsys.readouterr().out


def test_check_batch_with_expect(tmp_path, capsys):
    cfg = _write_policy(tmp_path, {"echo": "allow", "delete_*": "deny"})
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([
        {"server": "fs", "tool": "echo", "arguments": {}, "expect": "allow"},
        {"server": "fs", "tool": "delete_all", "expect": "deny"},
        {"server": "fs", "tool": "delete_all", "expect": "ask"},  # wrong on purpose
    ]), encoding="utf-8")
    rc = main(["check", "--config", str(cfg), "--agent", "bot", "--cases", str(cases)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "✗ (expected ask)" in out and "1 case(s) did not match" in out


def test_check_bad_config_and_bad_args(tmp_path, capsys):
    rc = main(["check", "--config", str(tmp_path / "nope.yaml"),
               "--agent", "b", "--server", "s", "--tool", "t"])
    assert rc == 2
    cfg = _write_policy(tmp_path, {"echo": "allow"})
    rc = main(["check", "--config", str(cfg), "--agent", "b",
               "--server", "s", "--tool", "t", "--args", "{not json"])
    assert rc == 2


# ---- F2: call timeout ----

def test_call_timeout_config_default_and_validation(tmp_path):
    cfg_path = write_config(tmp_path)
    doc = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert doc["servers"]["demo"].get("call_timeout_seconds", 120)  # default documented

    doc["servers"]["demo"]["call_timeout_seconds"] = -1
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(doc), encoding="utf-8")
    from agentgate.config import ConfigError, load_config
    with pytest.raises(ConfigError):
        load_config(bad)


async def test_call_timeout_enforced_e2e(workdir):
    """A hung upstream tool call is converted into a readable isError result."""
    hung = workdir / "hung_server.py"
    hung.write_text(
        "import asyncio, mcp_types as types\n"
        "from mcp.server.lowlevel import Server\n"
        "from mcp.server.stdio import stdio_server\n"
        "async def lt(ctx, params):\n"
        "    return types.ListToolsResult(tools=[types.Tool(name='sleep',\n"
        "        input_schema={'type':'object','properties':{}})])\n"
        "async def ct(ctx, params):\n"
        "    await asyncio.sleep(30)\n"
        "    return types.CallToolResult(content=[])  # never reached in test\n"
        "async def main():\n"
        "    srv = Server('hung', on_list_tools=lt, on_call_tool=ct)\n"
        "    async with stdio_server() as (r, w):\n"
        "        await srv.run(r, w, srv.create_initialization_options())\n"
        "asyncio.run(main())\n",
        encoding="utf-8",
    )
    cfg = write_config(workdir)
    doc = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    doc["servers"]["hung"] = {
        "transport": "stdio", "command": sys.executable, "args": [str(hung)],
        "call_timeout_seconds": 2,
    }
    doc["agents"]["bot"]["servers"]["hung"] = {
        "default": "deny", "tools": {"sleep": "allow"},
    }
    cfg.write_text(yaml.safe_dump(doc), encoding="utf-8")

    async with open_session(workdir, cfg) as (session, init):
        import time
        t0 = time.monotonic()
        res = await session.call_tool("hung--sleep", {})
        elapsed = time.monotonic() - t0
        assert res.is_error
        assert "did not answer" in res.content[0].text
        assert elapsed < 10, f"timeout took {elapsed:.1f}s - deadline not enforced"
        # healthy upstream still works after the timeout
        res = await session.call_tool("demo--echo", {"text": "alive"})
        assert not res.is_error
        import json as _json
        events = [_json.loads(l) for l in
                  (workdir / "state" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert any(e["event"] == "upstream_timeout" for e in events)
