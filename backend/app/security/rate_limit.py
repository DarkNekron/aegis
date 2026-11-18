"""In-process token-bucket rate limiter (single-process deployment; see ARCHITECTURE.md §1).

Each (scope, key) pair has a bucket of ``per_minute`` tokens refilled continuously. Memory is
bounded: the least recently used buckets are evicted beyond ``max_keys``.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from app.core.errors import AegisError


class RateLimitedError(AegisError):
    code = "rate_limited"
    http_status = 429

    def __init__(self, retry_after: int):
        super().__init__(f"Too many requests. Try again in {retry_after} second(s).")
        self.retry_after = retry_after


class RateLimiter:
    def __init__(self, max_keys: int = 10_000, clock=time.monotonic):
        self._buckets: OrderedDict[tuple[str, str], tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._clock = clock

    def hit(self, scope: str, key: str, per_minute: int) -> None:
        """Consume one token or raise ``RateLimitedError``."""
        now = self._clock()
        rate = per_minute / 60.0
        with self._lock:
            tokens, last = self._buckets.pop((scope, key), (float(per_minute), now))
            tokens = min(float(per_minute), tokens + (now - last) * rate)
            if tokens < 1.0:
                self._buckets[(scope, key)] = (tokens, now)
                raise RateLimitedError(max(1, int((1.0 - tokens) / rate) + 1))
            self._buckets[(scope, key)] = (tokens - 1.0, now)
            while len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
