#!/usr/bin/env bash
# CI gate: Phase 0 contract validator + every workstream's contract test.
# Zero infrastructure required (memory bus, in-memory stores, stub LLM).
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
fail=0

echo "== Phase 0: contract validator =="
$PY tools/validate_contract.py || fail=1

for ws in ws1-collectors ws2-normalization ws3-indexer ws4-detection ws5-ai ws6-inventory ws7-dashboard; do
  echo
  echo "== $ws =="
  ( cd "services/$ws" && $PY test_contract.py ) || fail=1
done

# Extended zero-infra suite (runner, window counters, boolean evaluator, e2e).
# Still no Docker/Redis/OpenSearch — all on the memory bus + in-memory store.
echo
echo "== shared runner =="
$PY services/shared/test_runner.py || fail=1
echo
echo "== ws4 window counters (T6) =="
$PY services/ws4-detection/test_window.py || fail=1
echo
echo "== ws4 boolean evaluator + alert id (T4/T7) =="
$PY services/ws4-detection/test_engine_boolean.py || fail=1
echo
echo "== integration e2e (WS-1->2->4->3) =="
$PY tools/integration_e2e.py || fail=1
echo
echo "== acceptance e2e (brute-force -> alert, idempotent) =="
$PY tools/demo_e2e.py || fail=1

echo
if [ "$fail" -eq 0 ]; then echo "ALL TESTS PASS"; else echo "SOME TESTS FAILED"; fi
exit $fail
