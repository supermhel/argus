# WS-5 AI Pipeline — Interface Declaration

## Consumes
- Topic `ai.requests` (group `cg-ai`) — buffered funnel input from WS-4.
- Contracts: B (bus), D (funnel thresholds).

## Produces
- Topic `ai.results` — `{event_id, verdict, summary, level, classification}`.
- Topic `alerts` — enriched AI alert.

## Layers
- Layer 2 `LightClassifier` (CPU, swap for sklearn) → category/priority/confidence.
- Layer 3 LLM via `make_llm()` → `OllamaLLM` (local, confidential) or offline `StubLLM`.
- **Decoupled**: the worker consumes the queue at its own pace; scale by adding workers.

## Contract tests
- `python test_contract.py`  (StubLLM + memory bus; no GPU/Ollama needed)

## Run locally
- `python main.py`  (StubLLM unless OLLAMA_URL is set)
