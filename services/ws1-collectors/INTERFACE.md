# WS-1 Collectors — Interface Declaration

## Consumes
- External inputs only: syslog (UDP/TCP 514), SNMP polling, NetFlow/IPFIX (2055).
- Contracts: B (bus topics).

## Produces
- Topic `raw.events` — `{source_type, raw, meta}`, partition key = source IP (`meta.ip`).
- Topic `assets.updates` — `{mac, ip, hostname, seen_at}`, partition key = mac (fallback ip).

## Mocks provided
- `mocks/sample_syslog.txt`, `mocks/sample_snmp.json`, `mocks/sample_netflow.json`
  let the whole service run offline with no sockets / SNMP agents.

## Contract tests
- `python test_contract.py`  (BUS_BACKEND=memory, no infra)

## Run locally
- `python main.py`  (offline, drains the mocks once)
