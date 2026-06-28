"""Cisco ASA parser: syslog -> OCSF Network Activity (4001).

ASA firewall messages carry a ``%ASA-<sev>-<msgid>:`` tag. We map the
accept/deny semantics to Network Activity activity_ids:

    activity_id 6 = Deny, 7 = Accept   (Contract A / ocsf-classes.md)

Typical built lines::

    %ASA-6-302013: Built outbound TCP connection ... for outside:203.0.113.5/51000 (..) to inside:10.0.0.10/22 (..)
    %ASA-4-106023: Deny tcp src outside:203.0.113.5/51000 dst inside:10.0.0.10/22 by access-group ...

The collector hands us ``{source_type, raw, meta}`` where ``raw`` is the syslog
line and ``meta`` may include ``ip`` / ``timestamp`` / ``received_at``.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import Parser, SEV_MEDIUM, SEV_INFO

# Cisco ASA syslog tag: %ASA-<sev>-<msgid>: <text>
_ASA_TAG = re.compile(r"%ASA-(?P<sev>\d)-(?P<msgid>\d+):\s*(?P<text>.*)$")

# src/dst as zone:ip/port pairs, e.g. "src outside:203.0.113.5/51000 dst inside:10.0.0.10/22"
_SRC = re.compile(r"src\s+\S*?:?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)")
_DST = re.compile(r"dst\s+\S*?:?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)")
# "Built ... for outside:IP/port (..) to inside:IP/port"
_FOR = re.compile(r"for\s+\S+?:(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)")
_TO = re.compile(r"to\s+\S+?:(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<port>\d+)")

_CLASS = 4001  # Network Activity


class CiscoAsaParser(Parser):
    SOURCE_TYPE = "cisco_asa"
    SECTOR = "common"
    ORIGINAL_FORMAT = "syslog"
    PRODUCT = {"name": "ASA", "vendor_name": "Cisco"}

    def parse(self, raw: dict) -> Optional[dict]:
        line = raw.get("raw")
        if not isinstance(line, str):
            return None
        meta = raw.get("meta") or {}

        m = _ASA_TAG.search(line)
        if not m:
            return None
        text = m.group("text")
        asa_sev = int(m.group("sev"))

        low = text.lower()
        if low.startswith("deny") or " deny " in low or "denied" in low:
            activity_id, status = 6, "Failure"  # Deny
        else:
            activity_id, status = 7, "Success"  # Accept / Built

        # endpoints
        sm = _SRC.search(text) or _FOR.search(text)
        dm = _DST.search(text) or _TO.search(text)

        time_ms = self._time_ms(meta)
        # ASA severity 0-4 are notable; map to MEDIUM, else INFO.
        severity_id = SEV_MEDIUM if asa_sev <= 4 else SEV_INFO

        event = self.base_event(
            class_uid=_CLASS,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._logged_time(meta),
            status=status,
            message=text.strip(),
        )

        if sm:
            event["src_endpoint"] = {"ip": sm.group("ip"), "port": int(sm.group("port"))}
        elif meta.get("ip"):
            event["src_endpoint"] = {"ip": meta["ip"]}
        if dm:
            event["dst_endpoint"] = {"ip": dm.group("ip"), "port": int(dm.group("port"))}

        return event

    @staticmethod
    def _time_ms(meta: dict) -> int:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return int(time.time() * 1000)

    @staticmethod
    def _logged_time(meta: dict) -> Optional[int]:
        ra = meta.get("received_at")
        if isinstance(ra, (int, float)):
            return int(ra * 1000) if ra < 1e12 else int(ra)
        return None
