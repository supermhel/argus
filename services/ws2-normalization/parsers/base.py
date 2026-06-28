"""Base parser contract for WS-2 Normalization.

Each source type gets ONE parser, isolated in its own module and registered in
``parsers/__init__.py``. A parser turns a raw bus payload
(``{source_type, raw, meta}`` from ``raw.events``, Contract B) into a single OCSF
event that validates against Contract A.

Invariants every parser MUST honour:

* ``type_uid`` is **derived**, never hand-set — use
  :func:`shared.ocsf.make_type_uid`.
* The ``siem.*`` block (``sector``, ``source_type``, ``ingest_id``) is always set.
* ``category_uid`` is ``class_uid // 1000`` (floored), per Contract A.
* The output validates: ``shared.ocsf.validate(event) == []``.

Adding a new source = adding one ``Parser`` subclass module and registering it.
No existing parser is touched.
"""
from __future__ import annotations

import uuid
from typing import Optional

from shared.ocsf import make_type_uid


# OCSF severity_id values (Contract A).
SEV_UNKNOWN = 0
SEV_INFO = 1
SEV_LOW = 2
SEV_MEDIUM = 3
SEV_HIGH = 4
SEV_CRITICAL = 5
SEV_FATAL = 6


class Parser:
    """Abstract per-source parser.

    Subclasses set ``SOURCE_TYPE``, ``SECTOR`` and ``ORIGINAL_FORMAT`` and
    implement :meth:`parse`.
    """

    #: Source type string this parser handles (matches ``raw["source_type"]``).
    SOURCE_TYPE: str = ""
    #: Routing sector for the ``siem.*`` block: bank | datacenter | common.
    SECTOR: str = "common"
    #: metadata.original_format enum value for this source.
    ORIGINAL_FORMAT: str = "json"
    #: metadata.product describing the source product.
    PRODUCT: dict = {"name": "unknown"}

    def parse(self, raw: dict) -> Optional[dict]:
        """Parse one raw bus payload into a single OCSF event.

        :param raw: ``{"source_type": str, "raw": <str|dict>, "meta": dict}``.
        :returns: an OCSF event (Contract A) or ``None`` if the line is not
            relevant / unparseable (caller drops ``None``).
        """
        raise NotImplementedError

    # ---- helpers shared by every parser -------------------------------

    def base_event(
        self,
        class_uid: int,
        activity_id: int,
        severity_id: int,
        time_ms: int,
        ingest_id: Optional[str] = None,
        logged_time: Optional[int] = None,
        status: Optional[str] = None,
        message: Optional[str] = None,
    ) -> dict:
        """Build the common OCSF scaffold with a derived ``type_uid``.

        Parsers fill in ``src_endpoint`` / ``dst_endpoint`` / ``actor`` on the
        returned dict.
        """
        category_uid = class_uid // 1000  # floored, per Contract A
        event = {
            "metadata": {
                "version": "1.1.0",
                "product": dict(self.PRODUCT),
                "original_format": self.ORIGINAL_FORMAT,
            },
            "class_uid": class_uid,
            "category_uid": category_uid,
            "activity_id": activity_id,
            "type_uid": make_type_uid(class_uid, activity_id),  # derived, never hand-set
            "severity_id": severity_id,
            "time": time_ms,
            "siem": {
                "sector": self.SECTOR,
                "source_type": self.SOURCE_TYPE,
                "ingest_id": ingest_id or str(uuid.uuid4()),
            },
        }
        if logged_time is not None:
            event["metadata"]["logged_time"] = logged_time
        if status is not None:
            event["status"] = status
        if message is not None:
            event["message"] = message
        return event

    @staticmethod
    def partition_key(event: dict) -> str:
        """Bus partition key for ``normalized.events`` = ``src_endpoint.ip``."""
        return (event.get("src_endpoint") or {}).get("ip", "0.0.0.0")
