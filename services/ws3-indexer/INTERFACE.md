# WS-3 Indexer — Interface Declaration

## Consumes
- Topics `normalized.events`, `scored.events`, `alerts`, `ai.results` (group `cg-index`).
- Contracts: A (events), E (index templates / ILM), B (bus).

## Produces
- Writes to OpenSearch indices: `events-{bank|dc|common}-YYYY.MM.DD`, `alerts-YYYY.MM.DD`.

## Storage adapter (swappable)
- `MemoryStore` (default, tests) / `OpenSearchStore` (env `STORAGE_BACKEND=opensearch`).
- Idempotent on `siem.ingest_id` / `alert_id` (at-least-once delivery).

## Contract tests
- `python test_contract.py`  (MemoryStore; routing + idempotency)

## Run locally
- `python main.py`  (memory store + memory bus by default)
