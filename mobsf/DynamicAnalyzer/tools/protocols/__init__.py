"""Protocol detection and adapters for Dynamic Analyzer DAST."""
from .base import ProtocolAdapter, EndpointDefinition
from .rest import RESTProtocolAdapter
from .graphql import GraphQLProtocolAdapter
from .websocket import WebSocketProtocolAdapter


class ProtocolDiscovery:
    """Discover supported protocols from captured traffic."""

    def __init__(self, adapters=None):
        self.adapters = adapters or [
            RESTProtocolAdapter(),
            GraphQLProtocolAdapter(),
            WebSocketProtocolAdapter(),
        ]

    def discover(self, traffic):
        """Run discovery against the raw traffic string."""
        discoveries = {}
        for adapter in self.adapters:
            adapter.parse(traffic)
            entries = list(adapter.iter_endpoints())
            if entries:
                discoveries[adapter.name] = entries
        return discoveries

    def iter_adapters(self):
        """Yield adapters that have at least one parsed endpoint."""
        for adapter in self.adapters:
            if adapter.has_endpoints:
                yield adapter


__all__ = [
    'ProtocolAdapter',
    'EndpointDefinition',
    'RESTProtocolAdapter',
    'GraphQLProtocolAdapter',
    'WebSocketProtocolAdapter',
    'ProtocolDiscovery',
]

