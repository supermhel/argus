"""WS-4 scoring + funnel routing (Contract D, scoring.yaml).

score = clamp( max(severity_floor of matched rules, capped_sum of score_weights) )
Funnel decision uses the thresholds defined once in scoring.yaml.
"""
from __future__ import annotations

from pathlib import Path

import yaml


class Scorer:
    def __init__(self, scoring_yaml: Path):
        cfg = yaml.safe_load(Path(scoring_yaml).read_text(encoding="utf-8"))
        self.t = cfg["thresholds"]
        self.floor = cfg["severity_floor"]
        self.clamp_min = cfg["clamp"]["min"]
        self.clamp_max = cfg["clamp"]["max"]

    def score(self, matched_rules) -> int:
        if not matched_rules:
            return 0
        weight_sum = sum(r.score_weight for r in matched_rules)
        floor = max(self.floor.get(r.level, 0) for r in matched_rules)
        return max(self.clamp_min, min(self.clamp_max, max(weight_sum, floor)))

    def route(self, score: int) -> str:
        """Return funnel action: 'store' | 'classifier' | 'llm'."""
        if score >= self.t["llm_min"]:
            return "llm"
        if score >= self.t["classifier_min"]:
            return "classifier"
        return "store"
