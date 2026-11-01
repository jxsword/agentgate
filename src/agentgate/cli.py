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
    serve_sync(config, agent=args.agent, state_dir=args.state_dir, http=args.http)
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
        decision = mgr.decide(args.request_id, allow=args.allow, approver=args.approver)
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
    p_run.add_argument("--agent", required=True, help="agent identity name (policy key under agents:)")
    p_run.add_argument("--state-dir", default=None, help="state directory (default .agentgate or policy state_dir)")
    p_run.add_argument("--on-ask", choices=["pending", "deny"], help="override on_ask behaviour")
    p_run.add_argument("--ask-timeout", type=int, help="override ask timeout seconds")
    p_run.add_argument("--http", default=None, metavar="HOST:PORT",
                       help="serve streamable HTTP instead of stdio (EX-1)")
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
