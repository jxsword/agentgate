"""Cross-process exclusive file locking (v0.3, F5).

msvcrt.locking on Windows, fcntl.flock on POSIX, with bounded retry so a
contending writer waits instead of corrupting state. Used by GrantStore to
make gateway writes and CLI grants/revoke safe against read-modify-write
races on grants.json.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path
from typing import Iterator


class LockTimeout(RuntimeError):
    pass


@contextlib.contextmanager
def exclusive_lock(path: str | Path, timeout: float = 5.0) -> Iterator[None]:
    """Hold an exclusive advisory lock on <path>.lock for the block duration."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "a+")
    acquired = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise LockTimeout(
                        f"could not acquire lock {lock_path} within {timeout}s"
                    ) from None
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        f.close()
