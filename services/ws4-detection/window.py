"""Sliding-window counters for WS-4 stateful rules (T6).

A stateful rule fires when the count of matching events for a group reaches
``threshold`` within ``window_seconds``. WHERE that count lives matters:

- **Single process / tests** -> ``DequeWindowCounter``: an in-process deque per
  group. Correct and zero-dependency for one replica.
- **Multiple replicas on Redis** -> ``RedisWindowCounter``: the count lives in a
  Redis sorted set so EVERY replica sees the SAME global count. With a local deque,
  two replicas each see half the events and neither reaches the threshold — the
  brute-force alert would never fire under horizontal scaling. (This was the T6
  finding from the Opus review.)

Both expose the same method::

    hit(key, now_ms, window_ms, member) -> int   # count in [now-window, now] after add

The engine calls it and compares the returned count to the rule's threshold.
"""
from __future__ import annotations

from collections import defaultdict, deque


class DequeWindowCounter:
    """In-process sliding window (default; correct for a single replica)."""

    def __init__(self) -> None:
        self._w: dict[str, deque] = defaultdict(deque)

    def hit(self, key: str, now_ms: int, window_ms: int, member=None) -> int:
        w = self._w[key]
        w.append(now_ms)
        horizon = now_ms - window_ms
        while w and w[0] < horizon:
            w.popleft()
        return len(w)


class RedisWindowCounter:
    """Global sliding window in a Redis sorted set per (rule, group).

    Atomic per call via a pipeline:
      ZADD  key {member: now}            -- record this event (member must be unique)
      ZREMRANGEBYSCORE key 0 horizon-1   -- drop events older than the window
      ZCARD key                          -- the global count in-window
      EXPIRE key window_s+1              -- quiet groups self-delete (no leak)

    ``member`` MUST be unique per event (use the OCSF ingest_id); otherwise ZADD
    would overwrite and undercount. Falls back to the timestamp if none given.
    """

    def __init__(self, client, namespace: str = "ws4:win") -> None:
        self.r = client
        self.ns = namespace

    def hit(self, key: str, now_ms: int, window_ms: int, member=None) -> int:
        zkey = f"{self.ns}:{key}"
        m = str(member) if member is not None else str(now_ms)
        horizon = now_ms - window_ms
        pipe = self.r.pipeline()
        pipe.zadd(zkey, {m: now_ms})
        pipe.zremrangebyscore(zkey, 0, horizon - 1)
        pipe.zcard(zkey)
        pipe.expire(zkey, max(1, window_ms // 1000 + 1))
        res = pipe.execute()
        return int(res[2])  # ZCARD result
