"""Append-only JSONL audit log.

One JSON object per line. Records are appended with fsync so that an
`agentgate incident` review can replay exactly what happened and why.

Size-based rotation (V1.2): when the file exceeds max_bytes it is renamed to
`audit-<timestamp>.jsonl` and a fresh file starts - audit history is kept,
never truncated.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 10 * 1024 * 1024


class AuditLog:
    def __init__(self, path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _rotate_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            return
        if size < self.max_bytes:
            return
        stamp = time.strftime("%Y%m%d%H%M%S")
        self.path.rename(self.path.with_name(f"{self.path.stem}-{stamp}{self.path.suffix}"))

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        self._rotate_if_needed()
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
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
