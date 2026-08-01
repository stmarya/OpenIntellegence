"""Connector framework.

Every upstream feed is a :class:`Connector`. The framework guarantees four
things the legacy scripts did not:

1. **Provenance is mandatory.** ``NormalizedRecord`` cannot be constructed
   without a ``source``, so merged data never loses where it came from.
2. **Bad records are quarantined, not dropped.** A normalisation failure
   parks the raw payload for replay instead of shrinking the dataset
   silently.
3. **TLS verification is never disabled.** The legacy collector set
   ``CERT_NONE``; here the HTTP client is built centrally and there is no
   switch to turn verification off.
4. **Credentials come from settings only.** No connector may embed a key.
"""

from __future__ import annotations

import abc
import ssl
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

import httpx

from app.core.config import Settings


class EntityKind:
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    RANSOMWARE_VICTIM = "ransomware_victim"
    THREAT_ACTOR = "threat_actor"
    INDICATOR = "indicator"


@dataclass(slots=True)
class NormalizedRecord:
    """One normalised entity, ready to upsert.

    ``source`` and ``dedupe_key`` are required. Together they are what makes
    cross-feed merging deterministic and re-runnable.
    """

    kind: str
    source: str
    dedupe_key: str
    payload: dict[str, Any]
    observed_at: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("NormalizedRecord requires a source (provenance is mandatory)")
        if not self.dedupe_key:
            raise ValueError("NormalizedRecord requires a dedupe_key")


@dataclass(slots=True)
class Quarantine:
    """A record that could not be normalised."""

    source: str
    reason: str
    raw: dict[str, Any]


FetchResult = NormalizedRecord | Quarantine


class ConnectorError(RuntimeError):
    """Raised when a feed is unreachable or returns an unusable response."""


def build_http_client(settings: Settings, *, timeout: float = 30.0) -> httpx.AsyncClient:
    """Construct the one HTTP client every connector uses.

    Certificate verification is enabled unconditionally. There is deliberately
    no parameter to disable it.
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    return httpx.AsyncClient(
        verify=context,
        timeout=httpx.Timeout(timeout, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "OpenIntelligence-CTI/0.1 (+https://api.nogosec.id)"},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    )


class Connector(abc.ABC):
    """Base class for all feed connectors."""

    #: Stable identifier written into every record's ``source`` column.
    name: ClassVar[str]
    #: What this connector produces.
    kind: ClassVar[str]
    #: Human-readable label for the connector-health UI.
    label: ClassVar[str]
    #: Requests per minute this feed tolerates.
    rate_limit_per_minute: ClassVar[int] = 30

    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.client = client

    @property
    def is_enabled(self) -> bool:
        """Whether this connector has what it needs to run.

        A connector missing its credential is *disabled*, not *broken*. The
        distinction matters: the UI shows disabled feeds differently from
        failing ones.
        """
        return True

    @abc.abstractmethod
    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        """Yield normalised records or quarantine entries.

        Implementations must not raise on a single malformed record — yield a
        :class:`Quarantine` instead. Raise :class:`ConnectorError` only when
        the whole feed is unusable.
        """
        raise NotImplementedError
        yield  # pragma: no cover - makes this an async generator


class ConnectorRegistry:
    """Registry of available connectors."""

    def __init__(self) -> None:
        self._connectors: dict[str, type[Connector]] = {}

    def register(self, connector: type[Connector]) -> type[Connector]:
        if not getattr(connector, "name", None):
            raise ValueError(f"{connector.__name__} must define a name")
        if connector.name in self._connectors:
            raise ValueError(f"duplicate connector name: {connector.name}")
        self._connectors[connector.name] = connector
        return connector

    def get(self, name: str) -> type[Connector]:
        try:
            return self._connectors[name]
        except KeyError as exc:
            raise KeyError(f"unknown connector: {name}") from exc

    def all(self) -> Sequence[type[Connector]]:
        return tuple(self._connectors.values())

    def names(self) -> Sequence[str]:
        return tuple(self._connectors)


registry = ConnectorRegistry()
