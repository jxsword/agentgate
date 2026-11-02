"""Append-only JSONL audit log with tamper-evident hash chaining (G5).

One JSON object per line, fsynced. Each record carries `prev` = sha256 of the
previous record's exact line (genesis: 64 zeros), so any in-place edit or
deletion breaks the chain - verifiable offline with `agentgate log --verify`.

Rotation (V1.2): at max_bytes the file is renamed to `audit-<ts>.jsonl`; each
file is an independent chain (genesis restarts), histories are never truncated.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
GENESIS = "0" * 64


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = GENESIS

    def _rotate_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size < self.max_bytes:
            return
        stamp = time.strftime("%Y%m%d%H%M%S")
        self.path.rename(self.path.with_name(f"{self.path.stem}-{stamp}{self.path.suffix}"))
        # each file is an independent chain
        self._last_hash = GENESIS

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        self._rotate_if_needed()
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event,
                  "prev": self._last_hash, **fields}
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self._last_hash = _line_hash(line)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        return record

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"event": "corrupt", "raw": line})
        return out

    def rotated_files(self) -> list[Path]:
        return sorted(self.path.parent.glob(f"{self.path.stem}-*{self.path.suffix}"))

    @staticmethod
    def verify_file(path: str | Path) -> tuple[bool, int, int, str]:
        """Verify one audit file's hash chain.

        Returns (ok, first_bad_line_no, total, message). Legacy records without
        a `prev` field are skipped (v0.2 files predate the chain).
        """
        path = Path(path)
        if not path.exists():
            return True, 0, 0, "missing file (nothing to verify)"
        expected_prev = GENESIS
        total = checked = 0
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            total += 1
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, i, total, f"line {i}: not valid JSON"
            if "prev" not in rec:
                continue  # legacy record
            checked += 1
            if rec["prev"] != expected_prev:
                return False, i, total, f"line {i}: chain broken (expected prev {expected_prev[:12]}...)"
            canonical = json.dumps(rec, ensure_ascii=False, sort_keys=True)
            expected_prev = _line_hash(canonical)
        return True, 0, total, f"chain intact ({checked}/{total} records chained)"
