"""Sliding-window rate limiting (v0.3, F3).

Per (agent, server) in-memory sliding window. Policy decision comes first;
the limiter only gates calls the policy would otherwise let through
(allow/grant/ask) - explicit denies are unaffected. Exceeding the window
fails closed with a `rate_limited` audit event.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass

from .config import RateLimit


@dataclass
class RateLimitResult:
    limited: bool
    retry_after: int  # seconds until the oldest in-window call expires (0 if not limited)
    limit: int | None = None


class RateLimiter:
    def __init__(self) -> None:
        self._windows: dict[tuple[str, str], tuple[deque[float], RateLimit]] = {}

    def _config_for(self, agent: str, server: str) -> RateLimit | None:
        # imported lazily to avoid a cycle; engine is injected at bind time
        spol = self._policy_lookup(agent, server)
        return getattr(spol, "rate_limit", None) if spol is not None else None

    def bind(self, policy_lookup) -> None:
        """policy_lookup(agent, server) -> ServerPolicy | None (usually engine's)."""
        self._policy_lookup = policy_lookup  # type: ignore[assignment]

    def check_and_record(self, agent: str, server: str, now: float | None = None) -> RateLimitResult:
        rl = self._config_for(agent, server)
        if rl is None:
            return RateLimitResult(limited=False, retry_after=0)
        now = now if now is not None else time.monotonic()
        key = (agent, server)
        window, _old = self._windows.get(key, (deque(), rl))
        # P2-7 (v0.6 review): always use the CURRENT config - hot-reload must be
        # able to tighten/loosen limits without a restart
        config = rl
        # drop entries outside the window
        horizon = now - config.window_seconds
        while window and window[0] <= horizon:
            window.popleft()
        if len(window) >= config.calls:
            retry_after = int(window[0] + config.window_seconds - now) + 1
            self._windows[key] = (window, config)
            return RateLimitResult(limited=True, retry_after=max(retry_after, 1),
                                   limit=config.calls)
        window.append(now)
        self._windows[key] = (window, config)
        return RateLimitResult(limited=False, retry_after=0, limit=config.calls)

    def current(self, agent: str, server: str, now: float | None = None) -> int:
        """H2: calls currently inside the window (for /status introspection)."""
        rl = self._config_for(agent, server)
        if rl is None:
            return 0
        now = now if now is not None else time.monotonic()
        rl = self._config_for(agent, server)
        if rl is None:
            return 0
        window, _old = self._windows.get((agent, server), (deque(), rl))
        config = rl  # current config (P2-7)
        horizon = now - config.window_seconds
        while window and window[0] <= horizon:
            window.popleft()
        return len(window)
