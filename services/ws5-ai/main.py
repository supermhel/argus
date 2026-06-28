"""WS-5 AI worker entrypoint.

Decoupled funnel consumer (Contract B): reads the buffered `ai.requests` topic at
its own pace, runs the LLM (local Ollama) on each, and publishes `ai.results` and an
enriched `alerts` entry. Scale = run more of these workers; nothing else changes.

The light classifier (layer 2) is also exposed for the 20..59 band, used by WS-4 or
called inline here when an event carries no LLM reason.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from classifier import LightClassifier  # noqa: E402
from llm_adapter import make_llm  # noqa: E402


class AiWorker:
    def __init__(self):
        self.llm = make_llm()
        self.classifier = LightClassifier()

    def handle(self, request: dict) -> dict:
        event = request.get("event", {})
        reasons = request.get("reason", [])
        verdict = self.llm.analyze(event, reasons)
        return {
            "event_id": request.get("event_id"),
            "verdict": verdict.get("verdict"),
            "summary": verdict.get("summary"),
            "level": verdict.get("level"),
            "classification": self.classifier.predict(event),
        }


def run(bus, worker: "AiWorker") -> dict:
    stats = {"analyzed": 0}
    for msg in bus.consume("ai.requests", group="cg-ai"):
        result = worker.handle(msg.payload)
        bus.produce("ai.results", key=result["event_id"] or "unknown", payload=result)
        bus.produce("alerts", key=result["event_id"] or "unknown",
                    payload={"alert_id": f"ai-{result['event_id']}",
                             "time": msg.payload.get("event", {}).get("time"),
                             "level": result["level"],
                             "ai": {"verdict": result["verdict"],
                                    "summary": result["summary"],
                                    "level": result["level"]},
                             "sector": msg.payload.get("event", {}).get("siem", {}).get("sector"),
                             "event_ids": [result["event_id"]]})
        stats["analyzed"] += 1
    return stats


def main():
    # Daemon (T0): consume ai.requests via the shared runner. run() above stays the
    # batch path used by tests / the e2e harness. v0.1 ships the passthrough/stub LLM;
    # real local-Ollama triage lands in v0.2.
    from shared.runner import serve  # noqa: E402
    from shared.log import get_logger  # noqa: E402

    worker = AiWorker()
    mode = "ollama" if os.getenv("OLLAMA_URL") else "passthrough-stub"
    get_logger("ws5-ai").info(
        "ai triage mode", mode=mode,
        note=("real local-LLM triage lands in v0.2" if mode == "passthrough-stub" else ""))

    def handler(payload: dict) -> None:
        bus = Bus()
        result = worker.handle(payload)
        bus.produce("ai.results", key=result["event_id"] or "unknown", payload=result)
        bus.produce("alerts", key=result["event_id"] or "unknown",
                    payload={"alert_id": f"ai-{result['event_id']}",
                             "time": payload.get("event", {}).get("time"),
                             "level": result["level"],
                             "ai": {"verdict": result["verdict"],
                                    "summary": result["summary"],
                                    "level": result["level"]},
                             "sector": payload.get("event", {}).get("siem", {}).get("sector"),
                             "event_ids": [result["event_id"]]})

    serve({"ai.requests": ("cg-ai", handler)},
          health_port=int(os.getenv("PORT", "8005")), service_name="ws5-ai")


if __name__ == "__main__":
    main()
