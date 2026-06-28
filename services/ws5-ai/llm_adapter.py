"""WS-5 layer-3 LLM adapter (Ollama).

The LLM only ever sees the fine tip of the funnel (events WS-4 enqueued to
ai.requests). Two implementations behind one interface:

* `OllamaLLM`     -> POSTs to a local Ollama server (env OLLAMA_URL, OLLAMA_MODEL).
                     Local for log confidentiality. Uses stdlib urllib only.
* `StubLLM`       -> deterministic offline verdict, used by the contract test and
                     when no Ollama server is configured.

Interface: `analyze(event, reasons) -> {verdict, summary, level}`.
verdict in {benign, suspicious, malicious}; level in OCSF-ish {low,medium,high,critical}.
"""
from __future__ import annotations

import json
import os
import urllib.request


PROMPT_TEMPLATE = (
    "You are a SIEM analyst. Given this normalized security event and the rules it "
    "triggered, respond with STRICT JSON {{\"verdict\":..., \"summary\":..., "
    "\"level\":...}}.\nEvent: {event}\nTriggered rules: {reasons}\n"
)


class StubLLM:
    """Deterministic offline analyst. No network, used by tests."""
    def analyze(self, event: dict, reasons: list[str]) -> dict:
        score = event.get("siem", {}).get("score", 0)
        sector = event.get("siem", {}).get("sector", "common")
        if score >= 80:
            verdict, level = "malicious", "critical"
        elif score >= 60:
            verdict, level = "suspicious", "high"
        else:
            verdict, level = "benign", "low"
        summary = (f"{sector} event scored {score}; triggered: "
                   f"{', '.join(reasons) or 'none'}.")
        return {"verdict": verdict, "summary": summary, "level": level}


class OllamaLLM:
    def __init__(self, url: str | None = None, model: str | None = None, timeout: float = 60):
        self.url = (url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct")
        self.timeout = timeout

    def analyze(self, event: dict, reasons: list[str]) -> dict:
        prompt = PROMPT_TEMPLATE.format(event=json.dumps(event)[:4000], reasons=reasons)
        body = json.dumps({"model": self.model, "prompt": prompt,
                           "format": "json", "stream": False}).encode()
        req = urllib.request.Request(f"{self.url}/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
        try:
            return json.loads(data.get("response", "{}"))
        except json.JSONDecodeError:
            return {"verdict": "unknown", "summary": data.get("response", "")[:200], "level": "low"}


def make_llm():
    if os.getenv("OLLAMA_URL"):
        return OllamaLLM()
    return StubLLM()
