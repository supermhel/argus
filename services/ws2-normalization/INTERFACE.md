# WS-2 Normalization — Interface Declaration

## Consumes
- Topic `raw.events` (group `cg-normalize`) — `{source_type, raw, meta}`.
- Contracts: A (OCSF schema), B (bus).

## Produces
- Topic `normalized.events` — OCSF event (Contract A), partition key = `src_endpoint.ip`.
- Topic `raw.events.deadletter` — unparseable/invalid inputs with errors.

## Parsers (one per source type, registry in `parsers/__init__.py`)
- `cisco_asa` → Network Activity (4001), sector common
- `active_directory` → Authentication (3002), sector bank
- `vmware_vsphere` → API Activity (6003), sector datacenter

Adding a source = new module + one registry line. `type_uid` always derived.

## Contract tests
- `python test_contract.py`  (memory bus; validates every parser's output against the schema)

## Run locally
- `python main.py`
