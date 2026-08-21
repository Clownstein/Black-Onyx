"""In-memory sliding-window rate limiter.

Mirrors the throttle idiom already used inline in AuthService._attempts
(login and password-reset throttling). Process-local, not distributed —
matches the existing precedent and the current single-process deployment.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._events: dict[str, list[datetime]] = {}

    def check(self, key: str, max_events: int, window: timedelta) -> bool:
        """Record an attempt under `key` and report whether it is within limits.

        Returns True (and counts the attempt) when under the limit, False when
        the limit is already exhausted. Callers should still record — and thus
        call this — even on the rejected path when the caller wants every
        attempt audited.
        """
        now = datetime.now(timezone.utc)
        recent = [t for t in self._events.get(key, []) if now - t < window]
        allowed = len(recent) < max_events
        if allowed:
            recent.append(now)
        self._events[key] = recent
        return allowed
