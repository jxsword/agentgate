"""Micro-benchmark: tools/call throughput through the agentgate gateway.

Usage (from the project root, venv active):
    python scripts/bench.py [-n 500] [--config policies/example.yaml]

Spawns the gateway + demo upstream exactly like tests do and reports
latency percentiles for allowed calls. The number includes the full
client -> gateway -> upstream -> gateway -> client round trip.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from tests.test_e2e import write_config  # noqa: E402  (harness re-use)


async def bench(n: int, workdir: Path) -> None:
    cfg = write_config(workdir)
    import os

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentgate", "run", "--config", str(cfg), "--agent", "bot"],
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=30)
            lat = []
            for i in range(n):
                t0 = time.perf_counter()
                res = await session.call_tool("demo--echo", {"text": f"b{i}"})
                lat.append(time.perf_counter() - t0)
                assert not res.is_error
    lat.sort()
    p = lambda q: lat[min(len(lat) - 1, int(q * len(lat)))]  # noqa: E731
    print(f"calls={n}  min={lat[0]*1000:.2f}ms  p50={p(0.5)*1000:.2f}ms  "
          f"p95={p(0.95)*1000:.2f}ms  p99={p(0.99)*1000:.2f}ms  max={lat[-1]*1000:.2f}ms")


def main_bench() -> int:
    ap = argparse.ArgumentParser(prog="bench")
    ap.add_argument("-n", type=int, default=500)
    ap.add_argument("--workdir", default=None, help="scratch dir (default: temp)")
    args = ap.parse_args()
    import tempfile

    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="agentgate-bench-"))
    asyncio.run(bench(args.n, work))
    return 0


if __name__ == "__main__":
    sys.exit(main_bench())
