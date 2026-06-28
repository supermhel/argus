# WS-6 Inventory — Interface Declaration

## Consumes
- Topic `assets.updates` (group `cg-inventory`) — `{mac, ip, hostname, seen_at}`.
- Contract C (this service IS the implementation).

## Produces
- HTTP API (Contract C): `GET /assets`, `GET /assets/resolve`, `GET /assets/{mac}`,
  `POST /assets/upsert`. Consumed by WS-2 (enrichment) and WS-7 (dashboard).

## Model
- MAC = primary key (stable). IP historised as intervals → `/assets/resolve?ip=&at=`
  is historically correct under DHCP churn. SQLite store, swappable to OpenSearch
  `assets` index (Contract E) later.

## Contract tests
- `python test_contract.py`  (in-memory SQLite + live stdlib HTTP server)

## Run locally
- `python app.py`  (serves on :8000)
