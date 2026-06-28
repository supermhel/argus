"""OpenSearch StorageAdapter (skeleton).

Builds the correct HTTP requests against ``OPENSEARCH_URL`` using only the
Python standard library (``urllib``). It is intentionally a thin skeleton: it is
*not* exercised by the offline contract tests (those use :class:`MemoryStore`),
but it constructs the exact requests a real deployment needs.

Idempotency is delegated to OpenSearch: documents are indexed with an explicit
``_id`` (the ``ingest_id`` / ``alert_id``). Re-indexing the same ``_id`` updates
the document in place rather than creating a duplicate, satisfying the
at-least-once contract.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .adapter import StorageAdapter


class OpenSearchStore(StorageAdapter):
    def __init__(self, url: str | None = None, timeout: float = 10.0) -> None:
        self.base = (url or os.getenv("OPENSEARCH_URL", "http://localhost:9200")).rstrip("/")
        self.timeout = timeout

    # -- low-level request helper ------------------------------------------
    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None
        headers = {"Content-Type": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}{path}", data=data, method=method, headers=headers
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            payload = resp.read().decode("utf-8")
            return json.loads(payload) if payload else {}

    # -- StorageAdapter ----------------------------------------------------
    def ensure_template(self, name: str, template: dict) -> None:
        """PUT an index template (Contract E mapping + ILM choice)."""
        self._request("PUT", f"/_index_template/{name}", template)

    def index(self, index: str, doc_id: str, document: dict) -> bool:
        """Index a document with an explicit ``_id`` (idempotent upsert).

        Using ``op_type=index`` (the default with an explicit id) makes the
        write idempotent: the same id overwrites rather than duplicating.
        Returns ``True`` when OpenSearch reports ``created``.
        """
        path = f"/{index}/_doc/{urllib.parse.quote(doc_id, safe='')}"
        result = self._request("PUT", path, document)
        return result.get("result") == "created"

    def count(self, index: str) -> int:
        try:
            result = self._request("GET", f"/{index}/_count")
        except urllib.error.HTTPError:
            return 0
        return int(result.get("count", 0))
