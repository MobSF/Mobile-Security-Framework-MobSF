"""REST protocol adapter for captured traffic."""
from __future__ import annotations

import json
import logging
import re

from .base import EndpointDefinition, ProtocolAdapter

logger = logging.getLogger(__name__)


REST_REQUEST_RE = re.compile(
    r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+'  # HTTP verb
    r'(https?://[^\s"\']+)',
    re.IGNORECASE,
)


class RESTProtocolAdapter(ProtocolAdapter):
    """Parse REST/HTTP endpoints from traffic logs."""

    name = 'rest'

    def parse(self, traffic: str) -> None:  # noqa: D401 - documented in base
        self.clear()
        if not traffic:
            return
        for match in REST_REQUEST_RE.finditer(traffic):
            method, url = match.groups()
            payload = self._extract_payload(traffic, match.end())
            headers = self._extract_headers(traffic, match.end())
            endpoint = EndpointDefinition(
                url=url.strip(),
                method=method.upper(),
                protocol='http',
                payload=payload,
                headers=headers,
            )
            self.add_endpoint(endpoint)

    def _extract_payload(self, traffic: str, start_index: int) -> str | None:
        snippet = traffic[start_index:start_index + 2048]
        payload_match = re.search(r'\r?\n\r?\n(\{.*?\})', snippet, re.S)
        if payload_match:
            payload = payload_match.group(1)
            try:
                json.loads(payload)
            except Exception:
                return payload.strip()
            return payload.strip()
        return None

    def _extract_headers(self, traffic: str, start_index: int) -> dict[str, str]:
        headers: dict[str, str] = {}
        snippet = traffic[start_index:start_index + 2048]
        for header_line in re.findall(r'([A-Za-z\-]+):\s*([^\r\n]+)', snippet):
            name, value = header_line
            headers[name.title()] = value.strip()
        return headers

    def prepare_payload(self, payload: str, endpoint: EndpointDefinition) -> str:
        if not payload and endpoint.payload:
            return endpoint.payload
        if endpoint.headers.get('Content-Type', '').startswith('application/json'):
            try:
                existing = json.loads(endpoint.payload or '{}')
            except json.JSONDecodeError:
                existing = {}
            existing.update({'fuzz': payload})
            return json.dumps(existing)
        return payload

