"""Real UDP syslog listener (live ingestion path for WS-1).

Binds a UDP socket and turns each received datagram into a raw event on the
``raw.events`` topic, shaped exactly like the other collectors' raw payloads so
it flows straight into the WS-2 ``generic_syslog`` parser::

    {"source_type": "generic_syslog",
     "raw": "<the raw syslog line>",
     "meta": {"received_at": <epoch_s>, "ingest_id": "<uuid|sha-derived>"}}

The source datagram's peer IP is used as the ``raw.events`` partition key so all
events from one device land on the same partition.

This complements (does not replace) the bundled mock collection in ``main.py``.
It is stdlib-only: a ``socketserver.UDPServer`` running on its own thread, with a
graceful ``stop()``. ``main.py`` runs it as the daemon's real ingestion path
alongside the runner's /health endpoint.

Default bind port is 5514 (not the privileged 514) so it runs without elevation.
Binding to 514 requires root/admin (or CAP_NET_BIND_SERVICE on Linux).
"""
from __future__ import annotations

import hashlib
import socketserver
import threading
import time
import uuid
from typing import Optional

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5514


def _deterministic_ingest_id(line: str) -> str:
    """SHA-256-derived UUID-like id (mirrors WS-2's generic_syslog parser)."""
    digest = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def build_raw_event(line: str, *, deterministic_id: bool = False) -> dict:
    """Wrap a decoded syslog line into a WS-2-parseable raw event."""
    if deterministic_id:
        ingest_id = _deterministic_ingest_id(line)
    else:
        ingest_id = str(uuid.uuid4())
    return {
        "source_type": "generic_syslog",
        "raw": line,
        "meta": {
            "received_at": int(time.time()),
            "ingest_id": ingest_id,
        },
    }


class SyslogUDPServer:
    """Threaded UDP syslog server that produces raw events to ``raw.events``.

    :param bus: a ``shared.bus.Bus()`` with ``produce(topic, key, payload)``.
    :param host: bind host (env ``SYSLOG_UDP_HOST``, default ``0.0.0.0``).
    :param port: bind port (env ``SYSLOG_UDP_PORT``, default ``5514``). Pass 0
        to get an ephemeral port (tests). The actual bound port is exposed via
        :attr:`port` after construction.
    :param topic: bus topic to produce to (default ``raw.events``).
    :param deterministic_id: if True, derive ingest_id from the line (idempotent)
        instead of a random uuid4. Tests use this for determinism.
    :param logger: optional shared.log Logger.
    """

    def __init__(self, bus, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
                 topic: str = "raw.events", deterministic_id: bool = False,
                 logger=None):
        self.bus = bus
        self.topic = topic
        self.deterministic_id = deterministic_id
        self.log = logger
        self.events_produced = 0
        self.events_dropped = 0   # datagrams lost because produce() failed

        server = self  # capture for the handler closure

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):  # noqa: D401
                data, _sock = self.request
                peer_ip = self.client_address[0]
                server._handle_datagram(data, peer_ip)

        self._udp = socketserver.UDPServer((host, port), _Handler)
        # bound address (host, port) — port resolves the real one when 0 was asked
        self.host, self.port = self._udp.server_address[0], self._udp.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def _handle_datagram(self, data: bytes, peer_ip: str) -> None:
        line = data.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            return
        event = build_raw_event(line, deterministic_id=self.deterministic_id)
        try:
            self.bus.produce(self.topic, key=peer_ip, payload=event)
        except Exception as exc:  # bus/Redis unreachable -> drop this datagram, keep serving
            self.events_dropped += 1
            if self.log is not None:
                self.log.warn("dropped syslog datagram: bus produce failed",
                              src=peer_ip, error=str(exc))
            return
        self.events_produced += 1
        if self.log is not None:
            self.log.info("syslog datagram", src=peer_ip,
                          ingest_id=event["meta"]["ingest_id"])

    def start(self) -> None:
        """Start serving on a background daemon thread (non-blocking)."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._udp.serve_forever, name="syslog-udp", daemon=True)
        self._thread.start()
        if self.log is not None:
            self.log.info("syslog UDP listening", host=self.host, port=self.port)

    def stop(self) -> None:
        """Stop serving and release the socket (graceful)."""
        self._udp.shutdown()
        self._udp.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self.log is not None:
            self.log.info("syslog UDP stopped", host=self.host, port=self.port)
