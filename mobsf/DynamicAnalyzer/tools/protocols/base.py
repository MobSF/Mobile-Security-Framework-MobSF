"""Base classes shared by protocol adapters."""
from __future__ import annotations

from dataclasses import dataclass, field
import abc
from typing import Dict, Iterator, Optional


@dataclass
class EndpointDefinition:
    """Common schema describing a discovered endpoint."""

    url: str
    method: str = 'GET'
    protocol: str = 'http'
    payload: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)


class ProtocolAdapter(abc.ABC):
    """Interface implemented by traffic protocol adapters."""

    name = 'base'

    def __init__(self):
        self._endpoints: list[EndpointDefinition] = []

    @property
    def has_endpoints(self) -> bool:
        """Return True when at least one endpoint was discovered."""
        return bool(self._endpoints)

    def iter_endpoints(self) -> Iterator[EndpointDefinition]:
        """Yield discovered endpoints."""
        yield from self._endpoints

    def clear(self):
        """Reset cached endpoints."""
        self._endpoints.clear()

    @abc.abstractmethod
    def parse(self, traffic: str) -> None:
        """Parse the raw traffic string and populate endpoints."""

    def add_endpoint(self, endpoint: EndpointDefinition) -> None:
        """Register a new endpoint for downstream fuzzing."""
        self._endpoints.append(endpoint)

    def prepare_payload(self, payload: str, endpoint: EndpointDefinition) -> str:
        """Return payload adapted to protocol specific requirements."""
        return payload

