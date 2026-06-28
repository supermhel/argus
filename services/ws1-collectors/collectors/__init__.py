"""WS-1 pluggable collector modules.

Each collector ingests raw events from one protocol and yields raw payloads of
the shape ``{"source_type", "raw", "meta"}`` (Contract B, topic ``raw.events``).
Collectors do NOT normalize to OCSF — that is WS-2's job.

Every collector exposes:
  * a ``SOURCE_TYPE`` class attribute (string identifying the protocol/product),
  * either ``handle_line(line)`` (push/streaming sources like syslog) or
    ``poll()`` (pull sources like SNMP / NetFlow file readers),
  * an optional ``asset_observations()`` generator yielding
    ``{"mac", "ip", "hostname", "seen_at"}`` dicts for the ``assets.updates`` topic.

A produced raw payload looks like::

    {
        "source_type": "syslog_rfc5424",
        "raw": "<134>1 2024-... host app - - - message",
        "meta": {"ip": "10.0.0.5", "transport": "udp", "received_at": 1750000000},
    }

The partition key for ``raw.events`` is the source IP, read from ``meta["ip"]``.
"""
