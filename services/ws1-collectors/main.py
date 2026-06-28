"""WS-1 Collectors entrypoint.

Wires the syslog / SNMP / NetFlow collectors to the message bus (Contract B):
raw payloads -> ``raw.events`` (partition key = source IP), asset observations
-> ``assets.updates`` (partition key = mac, falling back to ip).

Runs offline against the bundled mocks when no real transport is configured.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))  # for `shared`

from shared.bus import Bus  # noqa: E402
from collectors.syslog_collector import SyslogCollector  # noqa: E402
from collectors.snmp_collector import SnmpCollector  # noqa: E402
from collectors.netflow_collector import NetflowCollector  # noqa: E402

MOCKS = HERE / "mocks"


def build_collectors():
    syslog = SyslogCollector()
    snmp = SnmpCollector(devices_file=str(MOCKS / "sample_snmp.json"))
    netflow = NetflowCollector(flows_file=str(MOCKS / "sample_netflow.json"))
    return syslog, snmp, netflow


def run_once(bus) -> dict:
    """One collection cycle over the mock sources. Returns counts (for tests)."""
    syslog, snmp, netflow = build_collectors()
    raw_count = 0
    asset_count = 0

    # syslog: streaming source
    for line in (MOCKS / "sample_syslog.txt").read_text(encoding="utf-8").splitlines():
        payload = syslog.handle_line(line)
        if payload:
            bus.produce("raw.events", key=payload["meta"]["ip"], payload=payload)
            raw_count += 1

    # snmp + netflow: polling sources
    for collector in (snmp, netflow):
        for payload in collector.poll():
            bus.produce("raw.events", key=payload["meta"]["ip"], payload=payload)
            raw_count += 1

    # drain asset observations
    for collector in (syslog, snmp, netflow):
        for obs in collector.asset_observations():
            key = obs.get("mac") or obs.get("ip") or "unknown"
            bus.produce("assets.updates", key=key, payload=obs)
            asset_count += 1

    return {"raw.events": raw_count, "assets.updates": asset_count}


def main() -> None:
    # Daemon (T0): seed raw.events from the mock sources, then stay up with a
    # /health endpoint so the container doesn't exit. WS-1 is a producer, not a
    # bus consumer, so it uses the runner's health-only mode (empty handler map).
    # Real continuous socket collectors (live syslog/SNMP/NetFlow) land in v0.2.
    from shared.runner import serve  # noqa: E402

    from shared.log import get_logger  # noqa: E402

    bus = Bus()
    counts = run_once(bus)
    get_logger("ws1-collectors").info(
        "seeded", raw_events=counts["raw.events"],
        asset_updates=counts["assets.updates"])
    serve({}, health_port=int(os.getenv("PORT", "8001")), service_name="ws1-collectors")


if __name__ == "__main__":
    main()
