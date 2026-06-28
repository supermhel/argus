# WS-4 Detection — Interface Declaration

## Consumes
- Topic `normalized.events` (group `cg-detect`).
- Contracts: A (events), D (Sigma rules + scoring), B (bus).
- Files: `contracts/rules/*.yml`, `contracts/scoring.yaml`.

## Produces
- Topic `scored.events` — event + `siem.score`, partition key = src ip.
- Topic `alerts` — one per rule match, partition key = alert_id.
- Topic `ai.requests` — buffered AI funnel input when score >= `llm_min` (60).

## Engine
- Sigma-style rules over OCSF dotted paths; stateful rules use `window_seconds` +
  `threshold` + `group_by` (sliding window). Score = capped sum of weights, with a
  severity floor; funnel route = store / classifier / llm per `scoring.yaml`.

## Contract tests
- `python test_contract.py`  (memory bus; rule firing + stateful thresholds + funnel)

## Run locally
- `python main.py`
