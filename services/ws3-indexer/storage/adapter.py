"""StorageAdapter interface (WS-3 Indexer).

The indexer is decoupled from any concrete search backend through this small
interface. Two implementations ship in this package:

* :class:`storage.memory.MemoryStore` -- process-local, used by the contract
  tests so they run with zero infrastructure.
* :class:`storage.opensearch.OpenSearchStore` -- a thin skeleton that builds the
  correct OpenSearch bulk/index requests against ``OPENSEARCH_URL``. It is not
  exercised by the offline tests.

Idempotency
-----------
Delivery on the bus is *at-least-once* (Contract B), so the same document may be
handed to :meth:`StorageAdapter.index` more than once. Implementations MUST be
idempotent on ``doc_id``: indexing the same ``(index, doc_id)`` twice results in
exactly one stored document. ``doc_id`` is the event ``siem.ingest_id`` or the
``alert_id`` -- the router supplies it.
"""
from __future__ import annotations

import abc


class StorageAdapter(abc.ABC):
    """Abstract document sink keyed by ``(index, doc_id)``."""

    @abc.abstractmethod
    def ensure_template(self, name: str, template: dict) -> None:
        """Register an index template / ILM choice (Contract E).

        Called once per logical index family at startup. The in-memory store
        records it; the OpenSearch store PUTs it to ``_index_template``.
        """

    @abc.abstractmethod
    def index(self, index: str, doc_id: str, document: dict) -> bool:
        """Store ``document`` under ``(index, doc_id)``.

        :returns: ``True`` if this call actually wrote a new document,
            ``False`` if it was suppressed as a duplicate (idempotency).
        """

    @abc.abstractmethod
    def count(self, index: str) -> int:
        """Number of distinct documents currently stored in ``index``."""
