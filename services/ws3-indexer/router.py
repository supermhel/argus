"""WS-3 routing: map a bus document to (index_name, doc_id).

Index selection (Contract E):
  * OCSF events  -> events-{sector}-{YYYY.MM.DD}   sector in {bank,dc,common}
                    (siem.sector 'datacenter' maps to the 'dc' index family)
  * alerts       -> alerts-{YYYY.MM.DD}
Doc id (idempotency, Contract B at-least-once):
  * events -> siem.ingest_id
  * alerts -> alert_id
"""
from __future__ import annotations

from datetime import datetime, timezone

_SECTOR_TO_FAMILY = {"bank": "bank", "datacenter": "dc", "common": "common"}


def _date_suffix(epoch_ms: int | None) -> str:
    if epoch_ms:
        dt = datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
    else:
        dt = datetime.now(tz=timezone.utc)
    return dt.strftime("%Y.%m.%d")


def route(doc: dict) -> tuple[str, str]:
    """Return (index_name, doc_id) for a document. Raises ValueError if unroutable."""
    # alert?
    if "alert_id" in doc:
        return f"alerts-{_date_suffix(doc.get('time'))}", str(doc["alert_id"])

    # OCSF event
    siem = doc.get("siem") or {}
    sector = siem.get("sector")
    family = _SECTOR_TO_FAMILY.get(sector)
    if family is None:
        raise ValueError(f"unroutable document: sector={sector!r}")
    doc_id = siem.get("ingest_id")
    if not doc_id:
        raise ValueError("event missing siem.ingest_id (needed for idempotency)")
    return f"events-{family}-{_date_suffix(doc.get('time'))}", str(doc_id)


def template_for(index_name: str) -> str:
    """Logical index-template name (Contract E) for an index name."""
    if index_name.startswith("events-bank-"):
        return "events-bank"
    if index_name.startswith("events-dc-"):
        return "events-dc"
    if index_name.startswith("events-common-"):
        return "events-common"
    if index_name.startswith("alerts-"):
        return "alerts"
    return "unknown"
