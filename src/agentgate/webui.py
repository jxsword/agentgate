"""Web approval console (V1.2, EX-2).

`agentgate ui --port 8756` serves a small server-rendered console over the
SAME file protocol the gateway uses:

  GET  /                     pending approvals + active grants + audit tail
  POST /approve/<id>         action=allow|deny, approver=<name>  (one vote, HMAC-signed if secret set)
  POST /revoke/<grant_id>    revoke a delegation grant

Trust model: bind 127.0.0.1 by default - anyone who can reach the console can
approve; put it behind your own auth if you expose it. No client-side JS.
"""

from __future__ import annotations

import argparse
import html
import sys
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from .approvals import ApprovalManager
from .audit import AuditLog
from .grants import GrantStore

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>agentgate console</title>
<style>
 body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #1a1a2e; }}
 h2 {{ border-bottom: 2px solid #eee; padding-bottom: .3rem; margin-top: 2rem; }}
 table {{ border-collapse: collapse; width: 100%; }}
 td, th {{ border: 1px solid #ddd; padding: .45rem .6rem; text-align: left; vertical-align: top; }}
 th {{ background: #f6f6f8; }}
 code, pre {{ background: #f4f4f6; padding: .1rem .3rem; font-size: .9em; }}
 button {{ cursor: pointer; padding: .25rem .8rem; border: 1px solid #999; border-radius: 4px; }}
 .allow {{ background: #e6f6e6; }} .deny {{ background: #fde8e8; }}
 .muted {{ color: #777; }}
 form {{ display: inline; margin-right: .4rem; }}
</style></head><body>
<h1>agentgate console <span class="muted">(state: {state_dir})</span></h1>

<h2>Pending approvals ({n_pending})</h2>
{pending_table}

<h2>Active grants ({n_grants})</h2>
{grants_table}

<h2>Audit tail</h2>
<pre>{audit}</pre>
</body></html>"""


def _esc(v: object) -> str:
    return html.escape(str(v))


def build_app(state_dir: str | Path) -> Starlette:
    state = Path(state_dir)
    mgr = ApprovalManager(state)
    audit = AuditLog(state / "audit.jsonl")

    def fresh_grants() -> GrantStore:
        # re-read from disk per request so grants created after console startup
        # (by the gateway or CLI) are visible immediately
        return GrantStore(state / "grants.json")

    async def index(request: Request) -> HTMLResponse:
        pending = mgr.list_pending()
        grants = fresh_grants()
        active = grants.list()
        audit_rows = "\n".join(_esc(r) for r in
                               (state / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-30:]) \
            if (state / "audit.jsonl").exists() else "(no audit yet)"
        if pending:
            rows = []
            for r in pending:
                if "error" in r:
                    rows.append(f"<tr><td>{_esc(r.get('id'))}</td><td>corrupt pending file</td></tr>")
                    continue
                delegation = r.get("delegation") or {}
                rows.append(
                    f"<tr><td><code>{_esc(r.get('id'))}</code></td>"
                    f"<td>{_esc(r.get('agent'))}</td>"
                    f"<td><code>{_esc(r.get('tool'))}</code></td>"
                    f"<td><pre>{_esc(json_pretty(r.get('arguments')))}</pre></td>"
                    f"<td>{_esc(r.get('rule'))}</td>"
                    f"<td>{_esc(delegation) if delegation else '<span class=muted>none</span>'}</td>"
                    f"<td>"
                    f"<form method='post' action='/approve/{_esc(r.get('id'))}'>"
                    f"<input type='hidden' name='action' value='allow'>"
                    f"approver <input name='approver' value='human' size='8'>"
                    f"<button class='allow'>allow</button></form>"
                    f"<form method='post' action='/approve/{_esc(r.get('id'))}'>"
                    f"<input type='hidden' name='action' value='deny'>"
                    f"<button class='deny'>deny</button></form>"
                    f"</td></tr>"
                )
            pending_table = ("<table><tr><th>id</th><th>agent</th><th>tool</th><th>arguments</th>"
                             "<th>rule</th><th>delegation</th><th>decision</th></tr>"
                             + "".join(rows) + "</table>")
        else:
            pending_table = "<p class='muted'>nothing pending</p>"
        if active:
            grows = "".join(
                f"<tr><td><code>{_esc(g.id)}</code></td><td>{_esc(g.agent)}@{_esc(g.server)}--{_esc(g.tool)}"
                f"{' (args-bound)' if g.args_hash else ''}</td>"
                f"<td>{_esc(_remaining(g))}</td><td>{_esc(g.approver)}</td>"
                f"<td><form method='post' action='/revoke/{_esc(g.id)}'>"
                f"<button class='deny'>revoke</button></form></td></tr>"
                for g in active
            )
            grants_table = ("<table><tr><th>id</th><th>scope</th><th>expires</th><th>approver</th>"
                            "<th></th></tr>" + grows + "</table>")
        else:
            grants_table = "<p class='muted'>no active grants</p>"

        return HTMLResponse(_PAGE.format(
            state_dir=_esc(state), n_pending=len(pending), pending_table=pending_table,
            n_grants=len(active), grants_table=grants_table, audit=audit_rows,
        ))

    async def approve(request: Request) -> RedirectResponse:
        request_id = request.path_params["request_id"]
        form = await request.form()
        allow = form.get("action") == "allow"
        approver = str(form.get("approver") or "web-console")
        try:
            mgr.decide(request_id, allow=allow, approver=f"web:{approver}")
        except Exception as e:  # noqa: BLE001 - surface as flash via query param
            return RedirectResponse(f"/?error={_esc(e)}", status_code=303)
        return RedirectResponse("/", status_code=303)

    async def revoke(request: Request) -> RedirectResponse:
        grant_id = request.path_params["grant_id"]
        fresh_grants().revoke(grant_id)
        return RedirectResponse("/", status_code=303)

    return Starlette(routes=[
        Route("/", index),
        Route("/approve/{request_id}", approve, methods=["POST"]),
        Route("/revoke/{grant_id}", revoke, methods=["POST"]),
    ])


def json_pretty(value: object) -> str:
    import json

    try:
        return json.dumps(value, ensure_ascii=False, indent=1)
    except (TypeError, ValueError):
        return str(value)


def _remaining(grant) -> str:
    import time

    secs = int(grant.expires_at - time.time())
    if secs <= 0:
        return "expired"
    if secs >= 3600:
        return f"in {secs // 3600}h{(secs % 3600) // 60:02d}m"
    return f"in {secs // 60}m{secs % 60:02d}s"


def run_ui(state_dir: str | Path, host: str, port: int) -> None:
    import uvicorn

    print(f"[agentgate] console on http://{host}:{port}/ (state: {state_dir})", file=sys.stderr)
    uvicorn.run(build_app(state_dir), host=host, port=port, log_level="warning")


def main_ui(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentgate ui", description="Web approval console")
    ap.add_argument("--state-dir", default=".agentgate")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8756)
    args = ap.parse_args(argv)
    run_ui(args.state_dir, args.host, args.port)
    return 0


if __name__ == "__main__":
    main_ui()
