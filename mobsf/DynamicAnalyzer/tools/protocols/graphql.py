"""GraphQL protocol adapter."""
from __future__ import annotations

import json
import logging
import re

from .base import EndpointDefinition, ProtocolAdapter

logger = logging.getLogger(__name__)

GRAPHQL_QUERY_RE = re.compile(r'"query"\s*:\s*"', re.IGNORECASE)


class GraphQLProtocolAdapter(ProtocolAdapter):
    """Extract GraphQL operations from traffic dumps."""

    name = 'graphql'

    def parse(self, traffic: str) -> None:  # noqa: D401
        self.clear()
        if not traffic:
            return
        for block in self._candidate_blocks(traffic):
            try:
                payload = json.loads(block)
            except json.JSONDecodeError:
                continue
            query = payload.get('query')
            if not query:
                continue
            operation_name = payload.get('operationName') or self._extract_operation_name(query)
            endpoint = EndpointDefinition(
                url=payload.get('url', ''),
                method='POST',
                protocol='graphql',
                payload=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                metadata={'operation': operation_name or ''},
            )
            if endpoint.url:
                self.add_endpoint(endpoint)

    def _candidate_blocks(self, traffic: str):
        for match in GRAPHQL_QUERY_RE.finditer(traffic):
            start = traffic.rfind('{', 0, match.start())
            end = traffic.find('}', match.end())
            if start == -1 or end == -1:
                continue
            block = traffic[start:end + 1]
            yield block

    def prepare_payload(self, payload: str, endpoint: EndpointDefinition) -> str:
        try:
            base = json.loads(endpoint.payload or '{}')
        except json.JSONDecodeError:
            base = {'query': endpoint.metadata.get('operation', '')}
        if 'variables' not in base:
            base['variables'] = {}
        base['variables']['fuzz'] = payload
        return json.dumps(base)

    @staticmethod
    def _extract_operation_name(query: str) -> str | None:
        op_match = re.search(r'(query|mutation)\s+(\w+)', query)
        if op_match:
            return op_match.group(2)
        return None

