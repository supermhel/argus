"""Windows Event Log parser: broad Windows Security/System events -> OCSF.

This parser handles the ``windows_eventlog`` source type. It deliberately covers
a *broader* set of security-relevant Windows EventIDs than the product-specific
``active_directory`` parser (which is scoped to AD logon/Kerberos events). There
is no collision: the two parsers are keyed on different ``source_type`` strings.

Raw bus payload ``raw`` is the parsed Windows event record as a dict (mirroring
the convention used by the AD parser), e.g.::

    {"EventID": 4688, "TimeCreated": 1750000000000,
     "Computer": "wks-jdoe", "SubjectUserName": "jdoe",
     "SubjectDomainName": "BANKCORP",
     "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
     "NewProcessId": "0x1f4"}

EventID -> OCSF mapping (class_uid / activity_id constrained to Contract A):

    4624  Successful logon          -> 3002 Authentication, activity 1 (Logon)
    4634  Logoff                    -> 3002 Authentication, activity 2 (Logoff)
    4647  User-initiated logoff     -> 3002 Authentication, activity 2 (Logoff)
    4688  New process created       -> 1002 Kernel/Process, activity 1 (Launch)
    4672  Special privileges        -> 1002 Kernel/Process, activity 2 (Priv use)

For authentication events, IpAddress/WorkstationName is the logon SOURCE
(``src_endpoint``) and ``Computer`` is the host being logged INTO
(``dst_endpoint.hostname``) -- the lateral-movement rule counts distinct
destination hosts per account off that. Process events have no network
direction, so ``Computer`` stays on ``src_endpoint``.

Class 1002 (Kernel / Process) is used for 4688/4672 because Contract A's
``class_uid`` enum does not include a dedicated Process Activity class (1007);
``ocsf-classes.md`` explicitly scopes 1002 to "process exec, privilege use",
which matches both events. EventIDs not in the table (including 4625, owned by
the AD parser) and malformed input return ``None``.
"""
from __future__ import annotations

import json
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_MEDIUM

_CLS_AUTH = 3002    # Authentication
_CLS_PROC = 1002    # Kernel / Process

# Activity ids within class 1002 (Contract A leaves these open, 0-99).
_ACT_PROC_LAUNCH = 1   # process launch / exec
_ACT_PROC_PRIV = 2     # privilege use

# EventID -> (class_uid, activity_id, status, severity_id, verb)
_EVENT_MAP: dict[int, tuple] = {
    4624: (_CLS_AUTH, 1, "Success", SEV_INFO, "Logon"),
    4634: (_CLS_AUTH, 2, "Success", SEV_INFO, "Logoff"),
    4647: (_CLS_AUTH, 2, "Success", SEV_INFO, "Logoff"),
    4688: (_CLS_PROC, _ACT_PROC_LAUNCH, None, SEV_INFO, "Process created"),
    4672: (_CLS_PROC, _ACT_PROC_PRIV, "Success", SEV_MEDIUM, "Special privileges assigned"),
}


class WindowsEventLogParser(Parser):
    SOURCE_TYPE = "windows_eventlog"
    SECTOR = "common"
    ORIGINAL_FORMAT = "winevent"
    PRODUCT = {"name": "Windows Event Log", "vendor_name": "Microsoft"}

    def parse(self, raw: dict) -> Optional[dict]:
        if not isinstance(raw, dict):
            return None
        rec = raw.get("raw")
        if isinstance(rec, str):
            try:
                rec = json.loads(rec)
            except (ValueError, TypeError):
                return None
        if not isinstance(rec, dict):
            return None

        meta = raw.get("meta") or {}

        try:
            event_id = int(rec.get("EventID"))
        except (TypeError, ValueError):
            return None
        mapping = _EVENT_MAP.get(event_id)
        if mapping is None:
            return None
        class_uid, activity_id, status, severity_id, verb = mapping

        time_ms = self._epoch_ms(rec.get("TimeCreated") or meta.get("received_at"))

        # Subject = the account performing the action; Target = affected account
        # (4624/4672 carry both; logon classes prefer Target identity).
        if class_uid == _CLS_AUTH:
            user = rec.get("TargetUserName") or rec.get("SubjectUserName")
            domain = rec.get("TargetDomainName") or rec.get("SubjectDomainName")
            user_sid = rec.get("TargetUserSid") or rec.get("SubjectUserSid")
        else:
            user = rec.get("SubjectUserName") or rec.get("TargetUserName")
            domain = rec.get("SubjectDomainName") or rec.get("TargetDomainName")
            user_sid = rec.get("SubjectUserSid") or rec.get("TargetUserSid")

        ip = rec.get("IpAddress") or meta.get("ip")
        src_host = rec.get("WorkstationName")   # origin workstation (logon source)
        target_host = rec.get("Computer")       # host the event occurred ON

        message = f"{verb} for user {user or '?'}"
        if event_id == 4688 and rec.get("NewProcessName"):
            message = f"{verb}: {rec['NewProcessName']} (by {user or '?'})"
        elif ip:
            message += f" from {ip}"

        sector = meta.get("sector") or self.SECTOR

        event = self.base_event(
            class_uid=class_uid,
            activity_id=activity_id,
            severity_id=severity_id,
            time_ms=time_ms,
            ingest_id=meta.get("ingest_id"),
            logged_time=self._epoch_ms(meta.get("received_at")) if meta.get("received_at") else None,
            status=status,
            message=message,
        )
        event["siem"]["sector"] = sector

        # Endpoint direction matters for detection. For an AUTHENTICATION event,
        # IpAddress/WorkstationName is where the logon came FROM (source) and
        # `Computer` is the host being logged INTO (destination) -- so they map to
        # src_endpoint and dst_endpoint respectively. This is what lets the
        # lateral-movement rule count distinct destination hosts per account. For a
        # process/kernel event there is no network direction; `Computer` is simply
        # the host it ran on, so it stays on src_endpoint.
        src: dict = {}
        if ip:
            src["ip"] = ip
        if rec.get("MacAddress"):
            src["mac"] = rec["MacAddress"]
        if class_uid == _CLS_AUTH:
            if src_host:
                src["hostname"] = src_host
            if target_host:
                event["dst_endpoint"] = {"hostname": target_host}
        elif target_host or src_host:
            src["hostname"] = target_host or src_host
        if src:
            event["src_endpoint"] = src

        actor: dict = {}
        if user:
            actor_user: dict = {"name": user}
            if domain:
                actor_user["domain"] = domain
            if user_sid:
                actor_user["uid"] = str(user_sid)
            actor["user"] = actor_user

        if event_id == 4688 and rec.get("NewProcessName"):
            proc: dict = {"name": rec["NewProcessName"]}
            pid = self._parse_pid(rec.get("NewProcessId"))
            if pid is not None:
                proc["pid"] = pid
            actor["process"] = proc

        if actor:
            event["actor"] = actor

        return event

    # ---- helpers ------------------------------------------------------

    @staticmethod
    def _epoch_ms(value) -> int:
        if isinstance(value, (int, float)):
            return int(value * 1000) if value < 1e12 else int(value)
        return int(time.time() * 1000)

    @staticmethod
    def _parse_pid(value) -> Optional[int]:
        """Windows logs PIDs as hex strings ("0x1f4") or plain ints."""
        if value is None:
            return None
        if isinstance(value, int):
            return value
        try:
            s = str(value).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (ValueError, TypeError):
            return None
