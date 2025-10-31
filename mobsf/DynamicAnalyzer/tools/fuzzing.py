"""Automated fuzzing engine used by the Dynamic Analyzer."""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

from .protocols import EndpointDefinition, ProtocolAdapter
from .session_automation import SessionAutomationEngine

logger = logging.getLogger(__name__)


OWASP_TOP10_PAYLOADS: Dict[str, List[str]] = {
    'A01:2021-Broken Access Control': [
        '../../etc/passwd',
        '../admin',
        '?admin=true',
    ],
    'A02:2021-Cryptographic Failures': [
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        '00',
    ],
    'A03:2021-Injection': [
        "' OR '1'='1", "--", '<script>alert(1)</script>',
    ],
    'A04:2021-Insecure Design': [
        '{"role": "admin"}', '{"debug": true}',
    ],
    'A05:2021-Security Misconfiguration': [
        '*', '<%=%>',
    ],
    'A06:2021-Vulnerable and Outdated Components': [
        'User-Agent: MobSF-DAST',
    ],
    'A07:2021-Identification and Authentication Failures': [
        '{"password": "password"}', '{"otp": "0000"}',
    ],
    'A08:2021-Software and Data Integrity Failures': [
        '{"signature": "0"}', '{"hash": "AAAA"}',
    ],
    'A09:2021-Security Logging and Monitoring Failures': [
        '{"logs": []}',
    ],
    'A10:2021-Server-Side Request Forgery': [
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd',
    ],
}


@dataclass
class FuzzingPayload:
    """Payload metadata used for fuzzing."""

    category: str
    value: str


@dataclass
class FuzzingResult:
    """Represents the outcome for a single fuzzing attempt."""

    endpoint: EndpointDefinition
    payload: FuzzingPayload
    status_code: Optional[int]
    elapsed: float
    issues: List[str] = field(default_factory=list)
    error: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class FuzzingReport:
    """Aggregated report across all fuzzing attempts."""

    results: List[FuzzingResult]

    @property
    def total_requests(self) -> int:
        return len(self.results)

    @property
    def potential_issues(self) -> List[FuzzingResult]:
        return [result for result in self.results if result.issues]

    def summary(self) -> Dict[str, int]:
        summary = {payload: 0 for payload in OWASP_TOP10_PAYLOADS}
        for result in self.results:
            summary[result.payload.category] += len(result.issues)
        return summary


class OWASPTop10Fuzzer:
    """Provides payloads aligned with the OWASP Top 10."""

    def __init__(self, categories: Optional[Iterable[str]] = None):
        self.categories = list(categories) if categories else list(OWASP_TOP10_PAYLOADS)

    def payloads(self) -> Iterable[FuzzingPayload]:
        for category in self.categories:
            for value in OWASP_TOP10_PAYLOADS.get(category, []):
                yield FuzzingPayload(category=category, value=value)

    def random_payload(self) -> FuzzingPayload:
        category = random.choice(self.categories)
        return FuzzingPayload(category=category, value=random.choice(OWASP_TOP10_PAYLOADS[category]))


class FuzzingOrchestrator:
    """Coordinates fuzzing by combining adapters, payloads and sessions."""

    def __init__(self, session_engine: SessionAutomationEngine | None = None,
                 fuzzer: OWASPTop10Fuzzer | None = None):
        self.session_engine = session_engine or SessionAutomationEngine()
        self.fuzzer = fuzzer or OWASPTop10Fuzzer()

    def run(self, adapters: Iterable[ProtocolAdapter]) -> FuzzingReport:
        results: List[FuzzingResult] = []
        for adapter in adapters:
            for endpoint in adapter.iter_endpoints():
                for payload in self.fuzzer.payloads():
                    prepared_payload = adapter.prepare_payload(payload.value, endpoint)
                    headers = dict(endpoint.headers)
                    if payload.category.startswith('A07') and 'Authorization' not in headers:
                        headers['Authorization'] = 'Bearer invalid-token'
                    outcome = self._send(endpoint, payload, prepared_payload, headers)
                    results.append(outcome)
        return FuzzingReport(results=results)

    def _send(
        self,
        endpoint: EndpointDefinition,
        payload_meta: FuzzingPayload,
        payload: str,
        headers: Dict[str, str],
    ) -> FuzzingResult:
        logger.debug('Fuzzing %s %s with payload length %s',
                     endpoint.method, endpoint.url, len(payload or ''))
        response = self.session_engine.send(
            endpoint.method,
            endpoint.url,
            data=payload,
            headers=headers,
        )
        issues = self._evaluate(endpoint, response, payload, payload_meta)
        return FuzzingResult(
            endpoint=endpoint,
            payload=payload_meta,
            status_code=response.get('status_code'),
            elapsed=response.get('elapsed', 0.0),
            issues=issues,
            error=response.get('error'),
            response_headers=response.get('headers', {}),
        )

    def _evaluate(
        self,
        endpoint: EndpointDefinition,
        response: Dict[str, object],
        payload: str,
        payload_meta: FuzzingPayload,
    ) -> List[str]:
        issues: List[str] = []
        status = response.get('status_code')
        error = response.get('error')
        if error == 'offline-mode':
            return issues
        if status is not None and status < 400:
            issues.append(f'{payload_meta.category}: payload accepted')
        if payload and 'meta-data' in payload and status == 200:
            issues.append('Possible SSRF via metadata endpoint')
        if payload and payload.startswith("'") and status == 500:
            issues.append('Potential SQL injection due to server error')
        if payload and '<script>' in payload and status == 200:
            issues.append('Reflected XSS may be present')
        if status == 401 and 'invalid-token' in payload:
            issues.append('Authentication bypass attempt returned 401')
        return issues


__all__ = [
    'OWASPTop10Fuzzer',
    'FuzzingOrchestrator',
    'FuzzingReport',
    'FuzzingResult',
    'FuzzingPayload',
]

