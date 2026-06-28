"""In-memory StorageAdapter (default, test-friendly).

Stores documents in a nested dict keyed by ``index -> doc_id -> document``.
Re-indexing the same ``(index, doc_id)`` overwrites the slot but never grows the
count, which is exactly the idempotency guarantee the bus relies on.
"""
from __future__ import annotations

from .adapter import StorageAdapter


class MemoryStore(StorageAdapter):
    def __init__(self) -> None:
        # index name -> {doc_id: document}
        self._indices: dict[str, dict[str, dict]] = {}
        # template name -> template body (for inspection / assertions)
        self.templates: dict[str, dict] = {}

    def ensure_template(self, name: str, template: dict) -> None:
        self.templates[name] = template

    def index(self, index: str, doc_id: str, document: dict) -> bool:
        bucket = self._indices.setdefault(index, {})
        is_new = doc_id not in bucket
        bucket[doc_id] = document
        return is_new

    def count(self, index: str) -> int:
        return len(self._indices.get(index, {}))

    # -- test/inspection helpers -------------------------------------------
    def indices(self) -> list[str]:
        """Names of every index that has received at least one document."""
        return [name for name, docs in self._indices.items() if docs]

    def get(self, index: str, doc_id: str) -> dict | None:
        return self._indices.get(index, {}).get(doc_id)

    def all_docs(self, index: str) -> list[dict]:
        return list(self._indices.get(index, {}).values())
