"""Structured JSON logging (G-06 / T1).

One-line JSON logs: ``{ts, level, service, trace_id, msg, ...}``. A ``trace_id``
context variable lets a single event be followed across services (set it from a
bus message's id/ingest_id at the top of a handler). Replaces bare ``print()`` in
long-running service code so logs are machine-parseable and greppable.

    from shared.log import get_logger, set_trace_id
    log = get_logger("ws4-detection")
    set_trace_id(msg.id)
    log.info("scored event", score=70, rule="brute-force")
"""
from __future__ import annotations

import contextvars
import json
import sys
import time

_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="-")


def set_trace_id(tid: str | None) -> None:
    _trace_id.set(tid or "-")


def get_trace_id() -> str:
    return _trace_id.get()


class Logger:
    def __init__(self, service: str):
        self.service = service

    def _emit(self, level: str, msg: str, **fields) -> None:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "service": self.service,
            "trace_id": _trace_id.get(),
            "msg": msg,
        }
        if fields:
            rec.update(fields)
        # ensure_ascii=False keeps non-ASCII readable; default=str avoids crashes
        # on odd field types. One JSON object per line.
        sys.stdout.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        sys.stdout.flush()

    def info(self, msg: str, **fields) -> None:
        self._emit("info", msg, **fields)

    def warn(self, msg: str, **fields) -> None:
        self._emit("warn", msg, **fields)

    def error(self, msg: str, **fields) -> None:
        self._emit("error", msg, **fields)


def get_logger(service: str) -> Logger:
    return Logger(service)
