"""Abstract base class for pull-based detection connectors (SIEM/EDR sources).

Mirrors `enrichment/base.py::EnrichmentProvider`'s shape deliberately — same
kind of thing (a pluggable external-system client with a factory dispatch),
same conventions, so a reader who already knows one recognizes the other.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from black_onyx.models.data_model import DataModel


@dataclass
class DetectionPullResult:
    """One page of raw, not-yet-normalized detections from a connector poll."""

    detections: list[dict[str, Any]] = field(default_factory=list)
    # Opaque to the manager — whatever the connector needs to resume from
    # here next poll (a cursor token, an offset, a "since" timestamp string).
    next_cursor: str | None = None
    raw_count: int = 0


class DetectionConnector(ABC):
    """A pull-based client for one external detection source.

    A connector's job stops at "raw detections in, DataModel documents out" —
    it never touches Qdrant, watchlists, or the ingestion pipeline directly.
    `DetectionConnectorManager` is the only caller, and it is what pushes
    `normalize()`'s output through `Ingestor.process_document`, so every
    pulled detection gets exactly the same downstream treatment (search,
    graph, cases, decay, watchlist matching, auto-enrichment) as a file or
    feed ingestion — no parallel data path.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Connector instance name (the user-chosen name, not the vendor type)."""

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Vendor/connector type identifier (e.g. 'generic_rest', 'microsoft_defender',
        'crowdstrike_falcon') — what `factory.create_detection_connector` dispatches on."""

    @abstractmethod
    async def authenticate(self) -> None:
        """Establish or refresh whatever credential the connector needs to call
        its API (e.g. an OAuth2 client-credentials token). Called once before
        the first `pull_detections` in a poll cycle; connectors that cache a
        token should check its expiry here and only refresh if needed."""

    @abstractmethod
    async def pull_detections(
        self, since: datetime | None, cursor: str | None,
    ) -> DetectionPullResult:
        """Fetch new detections since `since`/`cursor` (whichever the
        connector's pagination style uses — see `GenericRestConnector`).

        Args:
            since: Last successful poll's timestamp, or None on first poll.
            cursor: Last successful poll's opaque cursor, or None on first poll.

        Returns:
            DetectionPullResult with raw detection dicts and the cursor to
            resume from next time.
        """

    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> DataModel:
        """Map one raw vendor detection dict onto the shared DataModel schema
        (IOC fields, MITRE fields if the source provides them, a body_text
        summary for the embedding vector, source_file set to something
        identifying this connector+detection for traceability)."""

    async def test_connection(self) -> dict[str, Any]:
        """Verify credentials/reachability without pulling detections.

        Returns:
            Dict with "status" ("ok" or "error") and optional "error" message.
        """
        try:
            await self.authenticate()
        except Exception as exc:
            return {"status": "error", "connector": self.name, "error": str(exc)}
        return {"status": "ok", "connector": self.name}
