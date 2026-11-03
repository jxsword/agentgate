"""agentgate CLI: run the gateway, approve requests, inspect grants and audit log."""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
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
               config_path=args.config, watch_policy=not args.no_watch,
               trust_agent_header=args.trust_agent_header)
    return 0


def cmd_pending(args) -> int:
    mgr = ApprovalManager(_state_dir(args))
    pending = mgr.list_pending()
    if getattr(args, "json", False):
        print(json.dumps(pending, ensure_ascii=False, indent=2))
        return 0
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
    if getattr(args, "verify", False):
        ok_all = True
        for src in log.rotated_files() + [log.path]:
            ok, bad_line, total, msg = AuditLog.verify_file(src)
            print(f"{src.name}: {'OK' if ok else 'TAMPERED'} - {msg}")
            if not ok:
                ok_all = False
        return 0 if ok_all else 1
    # I1 (v0.5): --filter key=value (repeatable) and --grep substring
    filters: dict[str, str] = {}
    for f in args.filter or []:
        if "=" not in f:
            print(f"agentgate: --filter expects key=value, got {f!r}", file=sys.stderr)
            return 2
        k, v = f.split("=", 1)
        filters[k] = v
    since_ok = None
    if getattr(args, "since", None):
        import datetime as _dt

        try:
            since_ok = _dt.datetime.fromisoformat(args.since)
            if since_ok.tzinfo is None:
                # naive input: interpret as local time (P2-11: avoids aware<naive TypeError)
                since_ok = since_ok.astimezone()
        except ValueError:
            print(f"agentgate: --since must be ISO 8601, got {args.since!r}", file=sys.stderr)
            return 2
    records = log.tail(100_000)  # full file scan; tail caps memory
    matches = 0
    for r in records:
        if since_ok is not None:
            try:
                import datetime as _dt

                if _dt.datetime.strptime(r.get("ts", ""), "%Y-%m-%dT%H:%M:%S%z") < since_ok:
                    continue
            except ValueError:
                pass
        if args.grep and args.grep.lower() not in json.dumps(r, ensure_ascii=False).lower():
            continue
        if any(str(r.get(k)) != v for k, v in filters.items()):
            continue
        print(json.dumps(r, ensure_ascii=False))
        matches += 1
        if matches >= args.n:
            break
    if args.follow:
        _follow(log.path, filters, args.grep)
    return 0


def _follow(path, filters: dict[str, str], grep: str | None) -> None:
    """J2 (v0.5): tail -f for the audit log (Ctrl+C to stop)."""
    import time as _time

    offset = path.stat().st_size if path.exists() else 0
    print(f"[agentgate] following {path} (Ctrl+C to stop)", file=sys.stderr)
    try:
        while True:
            if path.exists():
                size = path.stat().st_size
                if size < offset:  # rotated: restart from genesis of new file
                    offset = 0
                if size > offset:
                    with open(path, "r", encoding="utf-8") as f:
                        f.seek(offset)
                        for line in f:
                            line = line.rstrip("\n")
                            if not line:
                                continue
                            try:
                                rec = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if grep and grep.lower() not in line.lower():
                                continue
                            if any(str(rec.get(k)) != v for k, v in filters.items()):
                                continue
                            print(json.dumps(rec, ensure_ascii=False))
                    offset = size
            _time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[agentgate] follow stopped", file=sys.stderr)


def cmd_grants(args) -> int:
    store = GrantStore(_state_dir(args) / "grants.json")
    if getattr(args, "grant_id", None):
        # L3 (v0.6): single grant detail
        matches = [g for g in store.list(include_expired=True) if g.id == args.grant_id]
        if not matches:
            print(f"grant {args.grant_id!r} not found", file=sys.stderr)
            return 1
        g = matches[0]
        print(f"id:       {g.id}")
        print(f"scope:    {g.agent}@{g.server}--{g.tool}" + (" (args-bound)" if g.args_hash else ""))
        print(f"created:  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(g.created_at))}")
        print(f"expires:  {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(g.expires_at))}"
              f" ({'active' if g.active() else 'expired'})")
        print(f"approver: {g.approver}")
        return 0
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
    diff_engine = None
    if args.diff:
        try:
            diff_engine = PolicyEngine(load_config(args.diff))
        except ConfigError as e:
            print(f"agentgate: --diff config invalid: {e}", file=sys.stderr)
            return 2

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
        # U (v0.7): --selftest runs the policy's embedded `tests:` cases
        if args.selftest:
            cases = config.tests
            if not cases:
                print("agentgate: policy has no embedded `tests:` cases", file=sys.stderr)
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
        marker = ""
        if diff_engine is not None:
            other = diff_engine.evaluate(args.agent, server, tool, arguments)
            if inspect.isawaitable(other):
                other = asyncio.run(other)
            if other.action != decision.action:
                marker = f"  ~ diff: {args.config}={decision.action} vs {args.diff}={other.action}"
        expect = case.get("expect")
        note = ""
        if expect is not None:
            ok = expect == decision.action
            note = "  ✓" if ok else f"  ✗ (expected {expect})"
            failures += 0 if ok else 1
        print(f"{args.agent}@{server}--{tool}: {label:<6} rule={decision.rule}{marker}{note}")
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
        import datetime as _dt

        try:
            since = _dt.datetime.fromisoformat(args.since)
            if since.tzinfo is None:
                since = since.astimezone()  # P2-11: naive -> local time
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
            if args.agent and rec.get("agent") != args.agent:
                continue
            if args.tool and rec.get("tool") != args.tool:
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

    if args.grants:
        # L1 (v0.6): delegation usage view - join call records (grant_id) with grants.json
        grant_calls: dict[str, int] = {}
        for src in sources:
            for line in src.read_text(encoding="utf-8").splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                gid = rec.get("grant_id")
                if rec.get("event") == "call" and rec.get("decision") == "grant" and gid:
                    grant_calls[gid] = grant_calls.get(gid, 0) + 1
        from .grants import GrantStore as _GS

        store = _GS(state / "grants.json")
        known = {g.id for g in store.list(include_expired=True)}
        if args.format == "json":
            print(json.dumps({
                "grants": [
                    {"id": g.id, "agent": g.agent, "server": g.server, "tool": g.tool,
                     "args_bound": bool(g.args_hash), "approver": g.approver,
                     "uses": grant_calls.get(g.id, 0), "active": g.active(),
                     "expires_at": g.expires_at}
                    for g in store.list(include_expired=True)
                ],
                "unknown_grant_uses": sum(c for gid, c in grant_calls.items()
                                          if gid not in known),
            }, ensure_ascii=False, indent=2))
            return 0
        if not known and not grant_calls:
            print("no grants found")
            return 0
        print(f"{'id':<14} {'scope':<36} {'uses':>5} {'state':<8} approver")
        for g in store.list(include_expired=True):
            scope = f"{g.agent}@{g.server}--{g.tool}" + (" (+args)" if g.args_hash else "")
            st = "active" if g.active() else "expired"
            print(f"{g.id:<14.14} {scope:<36.36} {grant_calls.get(g.id, 0):>5} {st:<8} {g.approver}")
        orphan = sum(c for gid, c in grant_calls.items() if gid not in known)
        if orphan:
            print(f"(+{orphan} uses from grants no longer in grants.json)")
        return 0

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


def cmd_demo(args) -> int:
    """I4 (v0.5): one-command demo - gateway + demo upstream + scripted client."""
    root = Path(__file__).resolve().parents[2]
    client = (root / "examples" / "demo_client.py").resolve()
    # strict allowlist: only the bundled demo client, located inside the project root
    if client.parent != (root / "examples").resolve() or not client.exists():
        print("agentgate demo: examples/demo_client.py not found - run from a source checkout",
              file=sys.stderr)
        return 2
    completed = subprocess.run([sys.executable, str(client), "--yes"],
                               cwd=str(root), shell=False)
    print("\nNext steps:")
    print("  agentgate run --config policies/example.yaml --agent claude-code   # terminal 1")
    print("  agentgate ui                                                        # terminal 2 (browser)")
    print("  agentgate report --state-dir .agentgate                             # after some calls")
    return completed.returncode


def cmd_doctor(args) -> int:
    """N (v0.6): environment and configuration diagnostics."""
    checks: list[tuple[str, bool, str]] = []
    ok_all = True

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal ok_all
        ok_all = ok_all and ok
        checks.append((name, ok, detail))

    v = sys.version_info
    check(f"python >= 3.11 ({v.major}.{v.minor}.{v.micro})",
          (v.major, v.minor) >= (3, 11))
    try:
        import mcp as _mcp

        check(f"mcp SDK installed ({getattr(_mcp, '__version__', '?')})", True)
    except ImportError as e:
        check("mcp SDK installed", False, str(e))
    try:
        import yaml  # noqa: F401

        check("pyyaml installed", True)
    except ImportError as e:
        check("pyyaml installed", False, str(e))

    state = _state_dir(args)
    state.mkdir(parents=True, exist_ok=True)  # the gateway creates it at runtime too
    try:
        probe = state / ".doctor-probe"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        check(f"state dir writable ({state})", True)
    except OSError as e:
        check(f"state dir writable ({state})", False, str(e))

    audit = state / "audit.jsonl"
    if audit.exists():
        ok, bad_line, total, msg = AuditLog.verify_file(audit)
        check(f"audit chain ({total} records)", ok, msg)
    else:
        check("audit chain (no audit yet)", True, "no audit file")
    for rotated in sorted(state.glob("audit-*.jsonl")):
        ok, _, total, msg = AuditLog.verify_file(rotated)
        check(f"audit chain ({rotated.name})", ok, msg)

    if args.config:
        from .config import ConfigError

        try:
            config = load_config(args.config)
            check(f"policy loads ({len(config.servers)} servers, {len(config.agents)} agents)",
                  True, str(args.config))
            if args.reach:
                # best-effort upstream reachability: start & stop each upstream
                import asyncio
                from contextlib import AsyncExitStack

                from .upstream import Upstream

                async def probe_upstreams() -> list[tuple[str, bool, str]]:
                    out = []
                    async with AsyncExitStack() as stack:
                        for name, scfg in config.servers.items():
                            up = Upstream(scfg)
                            try:
                                await asyncio.wait_for(up.start(stack), timeout=10)
                                out.append((f"upstream {name} reachable", True,
                                            up.server_info.name if up.server_info else ""))
                            except Exception as e:  # noqa: BLE001
                                out.append((f"upstream {name} reachable", False, str(e)))
                    return out

                for name, ok, detail in asyncio.run(probe_upstreams()):
                    check(name, ok, detail)
        except ConfigError as e:
            check("policy loads", False, str(e))

    for name, ok, detail in checks:
        mark = "✓" if ok else "✗"
        print(f"{mark} {name}" + (f"  ({detail})" if detail else ""))
    print("\ndoctor:", "all checks passed" if ok_all else "FAILURES FOUND")
    return 0 if ok_all else 1


def cmd_incident(args) -> int:
    """T (v0.7): forensics timeline for one delegation grant (or approval request)."""
    state = _state_dir(args)
    sources = sorted(state.glob("audit-*.jsonl")) + \
        ([state / "audit.jsonl"] if (state / "audit.jsonl").exists() else [])
    records = []
    for src in sources:
        for line in src.read_text(encoding="utf-8").splitlines():
            try:
                records.append((src.name, json.loads(line)))
            except json.JSONDecodeError:
                continue

    # two-hop join: direct id hits, then any request_id referenced by them
    hits = [(s, r) for s, r in records
            if args.grant_id in (r.get("grant_id"), r.get("request_id"), r.get("id"))]
    related_request_ids = {r.get("request_id") for _, r in hits if r.get("request_id")}
    extra = [(s, r) for s, r in records
             if (s, r) not in hits and r.get("request_id") in related_request_ids]
    hits = sorted(hits + extra, key=lambda x: str(x[1].get("ts", "")))
    if not hits:
        print(f"no audit records reference {args.grant_id!r}")
        return 1
    print(f"timeline for {args.grant_id} ({len(hits)} records, oldest first):\n")
    for src_name, rec in hits:
        print(f"[{rec.get('ts')}] {rec.get('event')} ({src_name})")
        for k in ("agent", "server", "tool", "rule", "decision", "approver", "reason",
                  "ttl_seconds", "bind", "error"):
            if rec.get(k) is not None:
                print(f"    {k}: {rec[k]}")
        print()
    # chain integrity of every touched file
    ok_all = True
    for src in sources:
        ok, _, _, msg = AuditLog.verify_file(src)
        if not ok:
            ok_all = False
            print(f"WARNING: audit file {src.name} failed verification: {msg}")
    print("audit integrity:", "OK" if ok_all else "COMPROMISED (see warnings)")
    return 0 if ok_all else 1


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
    p_run.add_argument("--trust-agent-header", action="store_true",
                       help="with '--agent all --http': route /mcp by the "
                            "X-Agentgate-Agent request header (fail-closed)")
    p_run.set_defaults(func=cmd_run)

    p_pending = sub.add_parser("pending", help="list pending approval requests")
    p_pending.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_pending.add_argument("--json", action="store_true", help="machine-readable output")
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
    p_log.add_argument("--verify", action="store_true",
                       help="verify the tamper-evident hash chain of all audit files")
    p_log.add_argument("--filter", action="append", metavar="KEY=VALUE",
                       help="only records where rec[key] == value (repeatable)")
    p_log.add_argument("--grep", help="substring match on the serialized record")
    p_log.add_argument("--since", help="only records at/after this ISO 8601 timestamp")
    p_log.add_argument("-f", "--follow", action="store_true",
                       help="keep the log open and print new records (Ctrl+C to stop)")
    p_log.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_log.set_defaults(func=cmd_log)

    p_grants = sub.add_parser("grants", help="list active delegation grants (or show one by id)")
    p_grants.add_argument("grant_id", nargs="?", default=None, help="show this grant's details")
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
    p_check.add_argument("--diff", help="second policy file: mark cases whose decision differs")
    p_check.add_argument("--selftest", action="store_true",
                         help="run the policy's embedded `tests:` cases (CI gate)")
    p_check.set_defaults(func=cmd_check)

    p_validate = sub.add_parser("validate", help="validate a policy file without starting the gateway")
    p_validate.add_argument("--config", required=True)
    p_validate.set_defaults(func=cmd_validate)

    p_report = sub.add_parser("report", help="aggregate audit into a per agent/tool decision report")
    p_report.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_report.add_argument("--since", help="only decisions after this ISO 8601 timestamp")
    p_report.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p_report.add_argument("--agent", help="only decisions by this agent")
    p_report.add_argument("--tool", help="only decisions for this tool (bare name)")
    p_report.add_argument("--grants", action="store_true",
                          help="delegation usage view (grant_id -> call count)")
    p_report.set_defaults(func=cmd_report)

    p_demo = sub.add_parser("demo", help="one-command demo (gateway + demo upstream + scripted client)")
    p_demo.set_defaults(func=cmd_demo)

    p_doctor = sub.add_parser("doctor", help="environment and configuration diagnostics")
    p_doctor.add_argument("--config", help="also validate this policy file")
    p_doctor.add_argument("--reach", action="store_true",
                          help="also probe upstream reachability (starts/stops each)")
    p_doctor.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_doctor.set_defaults(func=cmd_doctor)

    p_incident = sub.add_parser("incident", help="forensics timeline for a grant/request id")
    p_incident.add_argument("grant_id")
    p_incident.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    p_incident.set_defaults(func=cmd_incident)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a legacy codepage (e.g. GBK/cp1252) that cannot
    # encode ✓/✗ - force UTF-8 with a lossy fallback so output never crashes
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
