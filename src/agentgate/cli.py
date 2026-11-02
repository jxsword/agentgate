"""agentgate CLI: run the gateway, approve requests, inspect grants and audit log."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .approvals import ApprovalError, ApprovalManager
from .audit import AuditLog
from .config import Config, load_config
from .gateway import serve_sync
from .grants import GrantStore

DEFAULT_STATE_DIR = ".agentgate"


def _state_dir(args) -> Path:
    return Path(getattr(args, "state_dir", None) or DEFAULT_STATE_DIR)


def cmd_run(args) -> int:
    try:
        config: Config = load_config(args.config)
    except Exception as e:
        print(f"agentgate: {e}", file=sys.stderr)
        return 2
    if args.state_dir:
        config.state_dir = Path(args.state_dir)
    if args.on_ask:
        config.on_ask = args.on_ask
    if args.ask_timeout:
        config.ask_timeout_seconds = args.ask_timeout

    logging.basicConfig(
        level=logging.INFO,
        format="[agentgate] %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    serve_sync(config, agent=args.agent, state_dir=args.state_dir, http=args.http,
               config_path=args.config, watch_policy=not args.no_watch)
    return 0


def cmd_pending(args) -> int:
    mgr = ApprovalManager(_state_dir(args))
    pending = mgr.list_pending()
    if not pending:
        print("no pending approval requests")
        return 0
    for r in pending:
        print(f"{r.get('id')}  agent={r.get('agent')} tool={r.get('tool')} rule={r.get('rule')}")
        print(f"    arguments: {json.dumps(r.get('arguments'), ensure_ascii=False)}")
        if r.get("delegation"):
            print(f"    delegation on approve: {r['delegation']}")
    return 0


def cmd_approve(args) -> int:
    mgr = ApprovalManager(_state_dir(args))
    try:
        decision = mgr.decide(args.request_id, allow=args.allow, approver=args.approver,
                              reason=args.reason)
    except ApprovalError as e:
        print(f"agentgate: {e}", file=sys.stderr)
        return 1
    verb = "APPROVED" if args.allow else "DENIED"
    print(f"{verb} {decision['id']} (approver={decision['approver']})")
    return 0


def cmd_log(args) -> int:
    log = AuditLog(_state_dir(args) / "audit.jsonl")
    records = log.tail(args.n)
    for r in records:
        print(json.dumps(r, ensure_ascii=False))
    return 0


def cmd_grants(args) -> int:
    store = GrantStore(_state_dir(args) / "grants.json")
    grants = store.list(include_expired=args.all)
    if not grants:
        print("no active grants")
        return 0
    for g in grants:
        scope = f"{g.agent}@{g.server}--{g.tool}"
        if g.args_hash:
            scope += " (bound to exact args)"
        print(f"{g.id}  {scope}  expires={g.expires_at:.0f} approver={g.approver}")
    return 0


def cmd_revoke(args) -> int:
    store = GrantStore(_state_dir(args) / "grants.json")
    if store.revoke(args.grant_id):
        print(f"revoked {args.grant_id}")
        return 0
    print(f"grant {args.grant_id!r} not found", file=sys.stderr)
    return 1


def cmd_ui(args) -> int:
    from .webui import run_ui

    run_ui(args.state_dir, args.host, args.port)
    return 0


def cmd_check(args) -> int:
    """F1 (v0.3): policy simulator - print decisions without running upstreams."""
    import asyncio
    import inspect
    import json as _json

    from .config import ConfigError
    from .policy import PolicyEngine

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"agentgate: {e}", file=sys.stderr)
        return 2
    engine = PolicyEngine(config)

    cases = []
    if args.cases:
        try:
            cases = _json.loads(Path(args.cases).read_text(encoding="utf-8"))
        except (OSError, _json.JSONDecodeError) as e:
            print(f"agentgate: cannot read cases file: {e}", file=sys.stderr)
            return 2
        if not isinstance(cases, list):
            print("agentgate: cases file must be a JSON array", file=sys.stderr)
            return 2
    else:
        try:
            arguments = _json.loads(args.arguments) if args.arguments else None
        except _json.JSONDecodeError as e:
            print(f"agentgate: --args must be valid JSON: {e}", file=sys.stderr)
            return 2
        cases = [{"server": args.server, "tool": args.tool, "arguments": arguments}]

    failures = 0
    for case in cases:
        try:
            server = case["server"]
            tool = case["tool"]
        except KeyError as e:
            print(f"agentgate: case missing field {e}", file=sys.stderr)
            return 2
        arguments = case.get("arguments")
        decision = engine.evaluate(args.agent, server, tool, arguments)
        if inspect.isawaitable(decision):  # OPA-backed engine
            decision = asyncio.run(decision)
        label = decision.action
        expect = case.get("expect")
        marker = ""
        if expect is not None:
            ok = expect == decision.action
            marker = "  ✓" if ok else f"  ✗ (expected {expect})"
            failures += 0 if ok else 1
        print(f"{args.agent}@{server}--{tool}: {label:<6} rule={decision.rule}{marker}")
        if arguments is not None:
            print(f"    args: {_json.dumps(arguments, ensure_ascii=False)}")
    if failures:
        print(f"\n{failures} case(s) did not match expectations")
        return 1
    return 0


def cmd_report(args) -> int:
    """F6 (v0.3): aggregate the audit log into a per agent/tool decision report."""
    import datetime as _dt

    state = _state_dir(args)
    log_path = state / "audit.jsonl"
    sources = sorted(state.glob("audit-*.jsonl")) + ([log_path] if log_path.exists() else [])
    since = None
    if args.since:
        try:
            since = _dt.datetime.fromisoformat(args.since)
        except ValueError:
            print(f"agentgate: --since must be ISO 8601, got {args.since!r}", file=sys.stderr)
            return 2

    rows: dict[tuple[str, str], dict[str, int]] = {}
    total_decisions = 0
    for src in sources:
        for line in src.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event") not in ("call", "call_denied", "ask_denied", "rate_limited"):
                continue
            if since is not None:
                try:
                    ts = _dt.datetime.strptime(rec.get("ts", ""), "%Y-%m-%dT%H:%M:%S%z")
                    if ts < since:
                        continue
                except ValueError:
                    pass
            key = (str(rec.get("agent")), str(rec.get("tool")))
            row = rows.setdefault(key, {"allowed": 0, "denied": 0, "ask_allowed": 0})
            total_decisions += 1
            if rec.get("event") == "call":
                if rec.get("decision") in ("allow", "grant"):
                    row["allowed"] += 1
                else:  # ask_allowed
                    row["ask_allowed"] += 1
            else:  # call_denied / ask_denied / rate_limited
                row["denied"] += 1

    if args.format == "json":
        print(json.dumps({
            "total_decisions": total_decisions,
            "rows": [
                {"agent": a, "tool": t, **counts,
                 "denial_rate": round(counts["denied"] / max(sum(counts.values()), 1), 3)}
                for (a, t), counts in sorted(rows.items())
            ],
        }, ensure_ascii=False, indent=2))
        return 0
    if args.format == "csv":
        import csv as _csv

        writer = _csv.writer(sys.stdout, lineterminator="\n")
        writer.writerow(["agent", "tool", "allowed", "ask_allowed", "denied", "denial_rate"])
        for (agent, tool), c in sorted(rows.items()):
            writer.writerow([agent, tool, c["allowed"], c["ask_allowed"], c["denied"],
                             round(c["denied"] / max(sum(c.values()), 1), 3)])
        return 0

    if not rows:
        print("no tool decisions found in audit")
        return 0
    print(f"{'agent':<16} {'tool':<28} {'allow/grant':>11} {'ask->ok':>8} {'denied':>7} {'deny%':>6}")
    for (agent, tool), c in sorted(rows.items()):
        n = sum(c.values())
        print(f"{agent:<16.16} {tool:<28.28} {c['allowed']:>11} {c['ask_allowed']:>8} "
              f"{c['denied']:>7} {round(100 * c['denied'] / n):>5}%")
    print(f"\ntotal decisions: {total_decisions} (sources: {len(sources)} file(s))")
    return 0


def cmd_validate(args) -> int:
    """G1 (v0.4): load and validate a policy without starting anything."""
    from .config import ConfigError

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"agentgate: INVALID - {e}", file=sys.stderr)
        return 1
    print(f"OK: {len(config.servers)} server(s), {len(config.agents)} agent(s), "
          f"default={config.default_decision}, on_ask={config.on_ask}")
    for server, scfg in config.servers.items():
        detail = scfg.command or scfg.url or "?"
        timeout = f" timeout={scfg.call_timeout_seconds}s" if scfg.call_timeout_seconds else ""
        print(f"  server {server}: {scfg.transport} {detail}{timeout}")
    for agent, apol in config.agents.items():
        for server, spol in apol.servers.items():
            extras = []
            if spol.rate_limit:
                extras.append(f"rate={spol.rate_limit.calls}/{spol.rate_limit.window_seconds}s")
            if spol.prompts == "allow":
                extras.append("prompts=allow")
            if spol.resources == "allow":
                extras.append("resources=allow")
            print(f"  agent {agent}@{server}: {len(spol.rules)} rule(s), "
                  f"default={spol.default}" + (f", {', '.join(extras)}" if extras else ""))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentgate",
        description="Agent-native authorization gateway for MCP: per-tool-call policy, "
        "scoped human delegation, append-only audit.",
    )
    parser.add_argument("--version", action="version", version=f"agentgate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run the gateway (stdio by default, or --http)")
    p_run.add_argument("--config", required=True, help="path to policy YAML")
    p_run.add_argument("--agent", required=True,
                       help="agent identity name; 'all' (with --http) serves every agent at /<agent>/mcp")
    p_run.add_argument("--state-dir", default=None, help="state directory (default .agentgate or policy state_dir)")
    p_run.add_argument("--on-ask", choices=["pending", "deny"], help="override on_ask behaviour")
    p_run.add_argument("--ask-timeout", type=int, help="override ask timeout seconds")
    p_run.add_argument("--http", default=None, metavar="HOST:PORT",
                       help="serve streamable HTTP instead of stdio (EX-1)")
    p_run.add_argument("--no-watch", action="store_true",
                       help="disable policy hot-reload (default: reload on file change)")
    p_run.set_defaults(func=cmd_run)

    p_pending = sub.add_parser("pending", help="list pending approval requests")
    p_pending.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_pending.set_defaults(func=cmd_pending)

    p_approve = sub.add_parser("approve", help="approve or deny a pending request")
    p_approve.add_argument("request_id")
    g = p_approve.add_mutually_exclusive_group(required=True)
    g.add_argument("--allow", dest="allow", action="store_true")
    g.add_argument("--deny", dest="allow", action="store_false")
    p_approve.add_argument("--approver", default="human")
    p_approve.add_argument("--reason", default=None, help="why (passed back to the agent on denial)")
    p_approve.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_approve.set_defaults(func=cmd_approve)

    p_log = sub.add_parser("log", help="show recent audit records")
    p_log.add_argument("-n", type=int, default=20)
    p_log.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_log.set_defaults(func=cmd_log)

    p_grants = sub.add_parser("grants", help="list active delegation grants")
    p_grants.add_argument("--all", action="store_true", help="include expired")
    p_grants.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_grants.set_defaults(func=cmd_grants)

    p_revoke = sub.add_parser("revoke", help="revoke a delegation grant")
    p_revoke.add_argument("grant_id")
    p_revoke.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_revoke.set_defaults(func=cmd_revoke)

    p_ui = sub.add_parser("ui", help="web approval console (pending/grants/audit)")
    p_ui.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_ui.add_argument("--host", default="127.0.0.1")
    p_ui.add_argument("--port", type=int, default=8756)
    p_ui.set_defaults(func=cmd_ui)

    p_check = sub.add_parser("check", help="policy simulator: print decisions without running upstreams")
    p_check.add_argument("--config", required=True)
    p_check.add_argument("--agent", required=True)
    p_check.add_argument("--server", help="upstream server name (single-case mode)")
    p_check.add_argument("--tool", help="tool name, namespaced '<server>--<tool>' NOT needed here (single-case mode)")
    p_check.add_argument("--args", dest="arguments", help="JSON object of tool arguments (single-case mode)")
    p_check.add_argument("--cases", help="JSON array of {server, tool, arguments, expect?} for batch mode")
    p_check.set_defaults(func=cmd_check)

    p_validate = sub.add_parser("validate", help="validate a policy file without starting the gateway")
    p_validate.add_argument("--config", required=True)
    p_validate.set_defaults(func=cmd_validate)

    p_report = sub.add_parser("report", help="aggregate audit into a per agent/tool decision report")
    p_report.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_report.add_argument("--since", help="only decisions after this ISO 8601 timestamp")
    p_report.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
