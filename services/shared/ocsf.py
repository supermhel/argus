"""Shared OCSF helpers (Contract A) reused across workstreams."""
from __future__ import annotations
import sys
from pathlib import Path

# Reuse the single source-of-truth validator in tools/. Resolve its location for
# BOTH the repo layout (repo/services/shared -> repo/tools, parents[2]) and the
# container layout (/app/shared -> /app/tools, parents[1]).
_here = Path(__file__).resolve()
for _cand in (_here.parents[2] / "tools", _here.parents[1] / "tools", Path("/app/tools")):
    if (_cand / "validate_contract.py").exists():
        sys.path.insert(0, str(_cand))
        break
from validate_contract import load, validate_event, SCHEMA_PATH  # noqa: E402

_SCHEMA = load(SCHEMA_PATH)


def make_type_uid(class_uid: int, activity_id: int) -> int:
    """Always derive type_uid; never hand-set it."""
    return class_uid * 100 + activity_id


def validate(event: dict) -> list[str]:
    """Return list of contract errors ([] means valid)."""
    return validate_event(event, _SCHEMA)


def is_valid(event: dict) -> bool:
    return not validate(event)
