"""v0.8 T2: agentgate export-audit - audit to structured SQLite."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def _run(*args: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-m", "agentgate", *args],
                       capture_output=True, text=True, shell=False)
    return r.returncode, r.stdout + r.stderr


def _seed(state: Path):
    log = AuditLog(state / "audit.jsonl")
    for i in range(5):
        log.append("call", agent="bot", server="fs", tool="echo", decision="allow",
                   rule="r1", grant_id=None)
    log.append("call_denied", agent="bot", server="fs", tool="rm", decision="deny",
               rule="r2")
    return log


from agentgate.audit import AuditLog


def test_export_creates_queryable_db(tmp_path):
    state = tmp_path / "state"
    _seed(state)
    db = tmp_path / "out" / "audit.db"
    rc, out = _run("export-audit", "--state-dir", str(state), "--out", str(db))
    assert rc == 0, out
    conn = sqlite3.connect(db)
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert n == 6
    denied = conn.execute(
        "SELECT tool FROM events WHERE event='call_denied'").fetchall()
    assert denied == [("rm",)]
    rows = conn.execute(
        "SELECT ts, event, agent, tool, decision, rule, grant_id, error FROM events "
        "ORDER BY ts").fetchall()
    assert all(r[1] in ("call", "call_denied") for r in rows)
    conn.close()


def test_export_includes_rotated_files(tmp_path):
    state = tmp_path / "state"
    log = AuditLog(state / "audit.jsonl", max_bytes=1)
    log.append("e1")
    log.append("e2")  # rotated
    db = tmp_path / "audit.db"
    rc, _ = _run("export-audit", "--state-dir", str(state), "--out", str(db))
    assert rc == 0
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
    conn.close()


def test_export_idempotent_replace(tmp_path):
    state = tmp_path / "state"
    _seed(state)
    db = tmp_path / "audit.db"
    assert _run("export-audit", "--state-dir", str(state), "--out", str(db))[0] == 0
    # export again after more events: full replace, no duplicates
    _seed(state)
    rc, _ = _run("export-audit", "--state-dir", str(state), "--out", str(db))
    assert rc == 0
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 12
    conn.close()


def test_export_bad_state_dir(tmp_path):
    rc, out = _run("export-audit", "--state-dir", str(tmp_path / "nope"),
                   "--out", str(tmp_path / "x.db"))
    assert rc == 1 and "no audit" in out.lower()
