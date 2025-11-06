"""WebSocket protocol adapter."""
from __future__ import annotations

import logging
import re

from .base import EndpointDefinition, ProtocolAdapter

logger = logging.getLogger(__name__)

WS_URL_RE = re.compile(r'\b(wss?://[^\s"\']+)', re.IGNORECASE)


class WebSocketProtocolAdapter(ProtocolAdapter):
    """Discover WebSocket connections from logs."""

    name = 'websocket'

    def parse(self, traffic: str) -> None:  # noqa: D401
        self.clear()
        if not traffic:
            return
        for url in WS_URL_RE.findall(traffic):
            endpoint = EndpointDefinition(
                url=url.strip(),
                method='GET',
                protocol='websocket',
            )
            self.add_endpoint(endpoint)

    def prepare_payload(self, payload: str, endpoint: EndpointDefinition) -> str:
        return payload or 'ping'

