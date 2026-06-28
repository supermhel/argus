"""Shared-runner unit tests — zero infrastructure (MemoryBus).

Proves the four mechanisms the T3 Opus review said were unwritten, as far as they
can be proven without Redis:

  1. handler called once per queued message (dispatch + ack-on-success);
  2. a raising handler leaves the message UNACKED, and after max_redeliveries the
     message is routed to <topic>.deadletter and acked (redelivery simulated
     deterministically on MemoryBus via _process_message, since MemoryBus has no
     persistent PEL to replay);
  3. multi-topic dispatch routes each topic to its own handler;
  4. the threaded serve() loop processes a queued message, runs a /health endpoint,
     and exits cleanly when the shutdown Event is set.

Real-Redis equivalents (XAUTOCLAIM redelivery + XPENDING.times_delivered cap) are
written below but SKIPPED unless BUS_BACKEND=redis and a Redis is reachable.
"""
from __future__ import annotations

import os
import sys
import threading
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
os.environ.setdefault("BUS_BACKEND", "memory")

from shared.bus import Bus, _MemoryBus, Message  # noqa: E402
from shared import runner  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


# --------------------------------------------------------------------------- #
# 1. handler called once per queued message
# --------------------------------------------------------------------------- #
def test_handler_called_once_per_message():
    bus = Bus()
    seen = []
    for i in range(3):
        bus.produce("t.in", key=str(i), payload={"n": i})

    counts = runner.run_once(bus, {"t.in": ("cg-t", lambda p: seen.append(p["n"]))})

    check(seen == [0, 1, 2], f"handler order/count wrong: {seen}")
    check(counts["t.in"]["acked"] == 3, f"expected 3 acked, got {counts['t.in']}")
    # MemoryBus drains-on-yield, so after a full pass nothing remains queued.
    check(bus.drain("t.in") == [], "messages should be drained after run_once")


# --------------------------------------------------------------------------- #
# 2. raising handler -> not acked -> DLQ after max_redeliveries
# --------------------------------------------------------------------------- #
def test_raising_handler_not_acked():
    """A single delivery of a raising handler must NOT ack and must NOT DLQ."""
    bus = Bus()
    bus.produce("t.fail", key="k", payload={"x": 1})

    acked = {"n": 0}
    orig_ack = bus.ack
    bus.ack = lambda m, g=None: (acked.__setitem__("n", acked["n"] + 1), orig_ack(m, g))[1]

    def boom(_payload):
        raise RuntimeError("handler failure")

    counts = runner.run_once(bus, {"t.fail": ("cg-f", boom)}, max_redeliveries=5)

    check(counts["t.fail"]["failed"] == 1, f"expected 1 failed, got {counts['t.fail']}")
    check(acked["n"] == 0, "a failed handler must NOT ack its message")
    check(bus.drain("t.fail.deadletter") == [],
          "must NOT dead-letter on a single failure (cap not reached)")


def test_redelivery_then_deadletter():
    """Deterministically replay redeliveries on MemoryBus and assert that the
    message is DLQ'd exactly when the delivery count exceeds max_redeliveries.

    MemoryBus has no PEL, so we re-create the same Message and call the runner's
    _process_message with an incrementing delivery_count — exactly what the Redis
    worker would do as XPENDING.times_delivered climbs.
    """
    bus = Bus()
    max_redeliveries = 3

    def boom(_payload):
        raise RuntimeError("always fails")

    msg = Message("t.poison", "k", {"x": 1}, "1-0")
    results = []
    # delivery_count climbs 1,2,3 (all fail) then 4 (> max -> DLQ).
    for delivery_count in range(1, max_redeliveries + 2):
        r = runner._process_message(
            bus, "t.poison", "cg-p", msg, boom,
            max_redeliveries=max_redeliveries, delivery_count=delivery_count)
        results.append(r)

    check(results == ["failed", "failed", "failed", "deadlettered"],
          f"redelivery sequence wrong: {results}")
    dlq = bus.drain("t.poison.deadletter")
    check(len(dlq) == 1, f"expected exactly 1 DLQ message, got {len(dlq)}")
    if dlq:
        dl = dlq[0].payload
        check(dl["topic"] == "t.poison", f"DLQ wrong topic: {dl}")
        check(dl["delivery_count"] == 4, f"DLQ wrong delivery_count: {dl}")
        check(dl["payload"] == {"x": 1}, f"DLQ lost original payload: {dl}")


def test_handler_that_eventually_succeeds_is_acked_not_dlqd():
    """If a redelivered message finally succeeds before the cap, it is acked and
    never dead-lettered."""
    bus = Bus()
    attempts = {"n": 0}

    def flaky(_payload):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("transient")

    msg = Message("t.flaky", "k", {"x": 1}, "1-0")
    results = []
    for delivery_count in range(1, 6):
        r = runner._process_message(bus, "t.flaky", "cg-fl", msg, flaky,
                                    max_redeliveries=5,
                                    delivery_count=delivery_count)
        results.append(r)
        if r == "acked":
            break

    check(results == ["failed", "failed", "acked"], f"flaky sequence wrong: {results}")
    check(bus.drain("t.flaky.deadletter") == [],
          "must not DLQ a message that eventually succeeded")


# --------------------------------------------------------------------------- #
# 3. multi-topic dispatch routes to the right handler
# --------------------------------------------------------------------------- #
def test_multi_topic_dispatch():
    bus = Bus()
    bus.produce("topic.a", key="a", payload={"who": "a"})
    bus.produce("topic.b", key="b", payload={"who": "b"})
    bus.produce("topic.b", key="b2", payload={"who": "b"})

    got = {"a": [], "b": []}
    counts = runner.run_once(bus, {
        "topic.a": ("cg-a", lambda p: got["a"].append(p["who"])),
        "topic.b": ("cg-b", lambda p: got["b"].append(p["who"])),
    })

    check(got["a"] == ["a"], f"topic.a handler wrong: {got['a']}")
    check(got["b"] == ["b", "b"], f"topic.b handler wrong: {got['b']}")
    check(counts["topic.a"]["acked"] == 1 and counts["topic.b"]["acked"] == 2,
          f"per-topic counts wrong: {counts}")


# --------------------------------------------------------------------------- #
# 4. threaded serve(): processes a message, /health works, exits on shutdown
# --------------------------------------------------------------------------- #
def test_serve_threaded_and_health_and_shutdown():
    # Each worker calls bus_factory() for its own Bus; share ONE MemoryBus so the
    # test can pre-load it and read results back.
    shared_bus = _MemoryBus()
    shared_bus.produce("live.in", key="k", payload={"n": 42})

    seen = []
    done = threading.Event()

    def handler(payload):
        seen.append(payload["n"])
        done.set()

    shutdown = threading.Event()
    health_port = 8099

    serve_thread = threading.Thread(
        target=runner.serve,
        args=({"live.in": ("cg-live", handler)},),
        kwargs=dict(health_port=health_port, shutdown=shutdown,
                    service_name="test-svc", idle_sleep_s=0.05,
                    install_signal_handlers=False,
                    bus_factory=lambda: shared_bus),
        daemon=True)
    serve_thread.start()

    processed = done.wait(timeout=5)
    check(processed, "serve() did not process the queued message within 5s")
    check(seen == [42], f"serve() handler saw wrong payloads: {seen}")

    # /health
    health_ok = False
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{health_port}/health", timeout=3) as resp:
            import json
            body = json.loads(resp.read().decode())
            health_ok = (body == {"status": "ok", "service": "test-svc"})
    except Exception as e:  # pragma: no cover - diagnostic
        FAILS.append(f"/health request failed: {e!r}")
    check(health_ok, "/health did not return {'status':'ok','service':'test-svc'}")

    # clean shutdown
    shutdown.set()
    serve_thread.join(timeout=5)
    check(not serve_thread.is_alive(), "serve() did not exit after shutdown.set()")


# --------------------------------------------------------------------------- #
# Real-Redis path (XAUTOCLAIM + XPENDING) — SKIPPED unless Redis is reachable.
# --------------------------------------------------------------------------- #
def _redis_reachable():
    if os.getenv("BUS_BACKEND", "memory").lower() != "redis":
        return False
    try:
        import redis  # type: ignore
        r = redis.Redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return True
    except Exception:
        return False


def test_redis_redelivery_and_dlq():
    """Real-Redis: a failing handler leaves the message in the PEL; claim_pending
    redelivers it and after max_redeliveries it is DLQ'd. Skipped without Redis."""
    if not _redis_reachable():
        print("[SKIP] redis redelivery test (no reachable Redis / BUS_BACKEND!=redis)")
        return

    import json
    import redis  # type: ignore
    from shared.bus import _RedisBus

    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    raw = redis.Redis.from_url(url, decode_responses=True)
    topic = f"rt.{int(time.time()*1000)}"
    group = "cg-rt"
    dlq = f"{topic}.deadletter"
    bus = _RedisBus(url)

    bus.produce(topic, key="k", payload={"x": 1})

    max_redeliveries = 3
    # First delivery via consume() -> handler raises -> not acked (stays in PEL).
    for msg in bus.consume(topic, group=group):
        runner._process_message(bus, topic, group, msg, lambda p: (_ for _ in ()).throw(RuntimeError("boom")),
                                max_redeliveries=max_redeliveries, delivery_count=1)

    # Redeliver via claim_pending with min_idle_ms=0 until DLQ'd.
    dlqd = False
    for _ in range(10):
        for msg, times in bus.claim_pending(topic, group, 0, max_redeliveries):
            r = runner._process_message(bus, topic, group, msg, lambda p: (_ for _ in ()).throw(RuntimeError("boom")),
                                        max_redeliveries=max_redeliveries, delivery_count=times)
            if r == "deadlettered":
                dlqd = True
        if dlqd:
            break

    check(dlqd, "redis: message was never dead-lettered")
    check(raw.xlen(dlq) == 1, f"redis: expected 1 DLQ message, got {raw.xlen(dlq)}")
    # cleanup
    raw.delete(topic, dlq)


# --------------------------------------------------------------------------- #
def main():
    tests = [
        test_handler_called_once_per_message,
        test_raising_handler_not_acked,
        test_redelivery_then_deadletter,
        test_handler_that_eventually_succeeds_is_acked_not_dlqd,
        test_multi_topic_dispatch,
        test_serve_threaded_and_health_and_shutdown,
        test_redis_redelivery_and_dlq,
    ]
    for t in tests:
        try:
            t()
            print(f"  . {t.__name__}")
        except Exception as e:
            FAILS.append(f"{t.__name__} raised: {e!r}")
            print(f"  X {t.__name__}: {e!r}")

    if FAILS:
        print(f"\n[FAIL] runner: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("\n[OK] runner unit tests PASS")


if __name__ == "__main__":
    main()
