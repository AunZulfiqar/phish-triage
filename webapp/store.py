"""Bounded, expiring, in-memory result store.

Deliberately not a database. An uploaded message is evidence: it contains the
sender's infrastructure, the recipient's address, and often a third party's
personal data. Persisting that to disk turns a triage utility into a system of
record with retention obligations, for no analytical benefit -- the analyst
reads the report once and moves it into a ticket.

So results live in memory, expire on a timer, and are capped in count. A restart
loses everything, which is the correct behaviour.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StoredResult:
    reports: list[Any]
    created_at: float
    online: bool = False

    @property
    def is_batch(self) -> bool:
        return len(self.reports) > 1


class ResultStore:
    """Thread-safe TTL + LRU cache of analysis results."""

    def __init__(self, ttl_seconds: int = 1800, max_entries: int = 200) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, StoredResult] = OrderedDict()

    def put(self, reports: list[Any], online: bool = False) -> str:
        token = secrets.token_urlsafe(16)
        with self._lock:
            self._evict_expired_locked()
            self._entries[token] = StoredResult(reports, time.time(), online)
            self._entries.move_to_end(token)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
        return token

    def get(self, token: str) -> StoredResult | None:
        with self._lock:
            self._evict_expired_locked()
            entry = self._entries.get(token)
            if entry is not None:
                self._entries.move_to_end(token)
            return entry

    def discard(self, token: str) -> bool:
        with self._lock:
            return self._entries.pop(token, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            self._evict_expired_locked()
            return len(self._entries)

    def _evict_expired_locked(self) -> None:
        cutoff = time.time() - self._ttl
        expired = [k for k, v in self._entries.items() if v.created_at < cutoff]
        for key in expired:
            del self._entries[key]


@dataclass
class RateLimiter:
    """Fixed-window request counter, per client key.

    Not distributed and not precise at window boundaries. It exists to stop one
    client from pinning the CPU with a parse loop, not to enforce a billing
    quota, and a fixed window is sufficient for that.
    """

    limit: int = 60
    window: int = 60
    _hits: dict[str, list[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check(self, key: str) -> bool:
        """Record a request; return False when the caller is over the limit."""
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            timestamps = [t for t in self._hits.get(key, ()) if t > cutoff]
            if len(timestamps) >= self.limit:
                self._hits[key] = timestamps
                return False
            timestamps.append(now)
            self._hits[key] = timestamps
            if len(self._hits) > 4096:  # bound the key space
                for stale in [k for k, v in self._hits.items() if not v or max(v) < cutoff]:
                    del self._hits[stale]
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
