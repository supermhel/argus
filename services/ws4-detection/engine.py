"""WS-4 Sigma-style detection engine.

Loads rules from contracts/rules/*.yml (Contract D) and evaluates OCSF events
(Contract A) against them. Rules target OCSF dotted field paths, so one rule works
across every source of that class.

Supported rule shape (subset of Sigma, per sigma-convention.md):

    detection:
      <selection_name>:
        <ocsf.dotted.path>: <scalar>        # equality
      condition: "<sel> [and|or] <sel> ..."  # boolean over selection names
    siem:
      score_weight: <int>
      window_seconds: <int>    # optional -> stateful
      threshold: <int>         # optional -> stateful
      group_by: <ocsf.path>    # optional, defaults to src_endpoint.ip

Stateful rules only "fire" once the count of matching events for a group reaches
`threshold` within `window_seconds`.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from window import DequeWindowCounter


def get_path(doc: dict, dotted: str):
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


class Rule:
    def __init__(self, raw: dict):
        self.raw = raw
        self.id = raw.get("id")
        self.title = raw.get("title", "untitled")
        self.level = raw.get("level", "medium")
        det = raw.get("detection", {})
        self.condition = det.get("condition", "")
        self.selections = {k: v for k, v in det.items() if k != "condition"}
        siem = raw.get("siem", {})
        self.sector = siem.get("sector", "common")
        self.score_weight = int(siem.get("score_weight", 0))
        self.window_seconds = siem.get("window_seconds")
        self.threshold = siem.get("threshold")
        self.group_by = siem.get("group_by", "src_endpoint.ip")
        self.stateful = self.window_seconds is not None and self.threshold is not None
        # Sliding-window counter (T6). Defaults to an in-process deque (correct for a
        # single replica / tests). main() swaps in a RedisWindowCounter when running
        # on Redis so the count is global across replicas. See window.py.
        self._counter = DequeWindowCounter()

    def set_counter(self, counter) -> None:
        """Swap the window backend (e.g. RedisWindowCounter for multi-replica)."""
        self._counter = counter

    def _selection_matches(self, sel: dict, event: dict) -> bool:
        for path, expected in sel.items():
            if get_path(event, path) != expected:
                return False
        return True

    def _eval_condition(self, event: dict) -> bool:
        matched = {name: self._selection_matches(sel, event)
                   for name, sel in self.selections.items()}
        expr = self.condition.strip() or " and ".join(self.selections)
        # tokenize: selection names and and/or/not/parens
        tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", expr)
        # T4: explicit recursive-descent boolean evaluator over the tokens.
        # No eval(): rule files are contributor-supplied (open source), so executing
        # them as Python — even with __builtins__ stripped — is an RCE surface.
        try:
            value, end = _parse_or(tokens, 0, matched)
            return bool(value) if end == len(tokens) else False
        except (ValueError, IndexError):
            return False

    def alert_key(self, event: dict) -> str:
        """Deterministic alert identity (T7).

        Redelivery / duplicate processing of the same triggering event must yield the
        SAME alert id, never a fresh uuid4 — otherwise at-least-once delivery produces
        undeduplicatable duplicate alerts. Keyed by (rule, group, window-bucket) for
        stateful rules, (rule, ingest_id) otherwise.
        """
        if self.stateful:
            group = str(get_path(event, self.group_by))
            now = int(event.get("time", 0) or 0)
            window_ms = int(self.window_seconds) * 1000
            bucket = now // window_ms if window_ms else now
            return f"{self.id}:{group}:{bucket}"
        ingest = (event.get("siem") or {}).get("ingest_id") or "noingest"
        return f"{self.id}:{ingest}"

    def evaluate(self, event: dict) -> bool:
        """Return True if this rule fires for the event (incl. stateful threshold)."""
        if not self._eval_condition(event):
            return False
        if not self.stateful:
            return True
        group = str(get_path(event, self.group_by))
        now = event.get("time", 0)
        member = (event.get("siem") or {}).get("ingest_id") or str(now)
        # Namespace the window by rule id so two rules grouping on the same field
        # don't share a counter. The counter returns the in-window count after add.
        count = self._counter.hit(f"{self.id}:{group}", now,
                                  self.window_seconds * 1000, member)
        return count >= self.threshold


# --- T4 boolean expression evaluator (replaces eval) -------------------------
# Grammar:  or_expr := and_expr ("or" and_expr)*
#           and_expr := not_expr ("and" not_expr)*
#           not_expr := "not" not_expr | atom
#           atom     := "(" or_expr ")" | <selection-name>
# Each function returns (value, next_index). Unknown selection names are False.

def _parse_or(tokens, i, values):
    val, i = _parse_and(tokens, i, values)
    while i < len(tokens) and tokens[i] == "or":
        rhs, i = _parse_and(tokens, i + 1, values)
        val = val or rhs
    return val, i


def _parse_and(tokens, i, values):
    val, i = _parse_not(tokens, i, values)
    while i < len(tokens) and tokens[i] == "and":
        rhs, i = _parse_not(tokens, i + 1, values)
        val = val and rhs
    return val, i


def _parse_not(tokens, i, values):
    if i < len(tokens) and tokens[i] == "not":
        val, i = _parse_not(tokens, i + 1, values)
        return (not val), i
    return _parse_atom(tokens, i, values)


def _parse_atom(tokens, i, values):
    if i >= len(tokens):
        raise ValueError("unexpected end of condition")
    t = tokens[i]
    if t == "(":
        val, i = _parse_or(tokens, i + 1, values)
        if i >= len(tokens) or tokens[i] != ")":
            raise ValueError("missing closing paren")
        return val, i + 1
    if t in ("and", "or", "not", ")"):
        raise ValueError(f"unexpected token {t!r}")
    return bool(values.get(t, False)), i + 1


def load_rules(rules_dir: Path) -> list[Rule]:
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw:
            rules.append(Rule(raw))
    return rules
