"""Helper utilities for building DAST oriented reports."""
from __future__ import annotations

from typing import Dict

from .auth_analysis import AuthenticationAnalyzer
from .fuzzing import FuzzingOrchestrator, OWASPTop10Fuzzer
from .protocols import ProtocolDiscovery
from .session_automation import SessionAutomationEngine


def _endpoint_to_dict(endpoint):
    return {
        'url': endpoint.url,
        'method': endpoint.method,
        'protocol': endpoint.protocol,
        'payload': endpoint.payload,
        'headers': endpoint.headers,
        'metadata': endpoint.metadata,
    }


def build_dast_report(traffic: str) -> Dict[str, object]:
    """Construct a DAST specific report including fuzzing and auth findings."""
    if not traffic:
        return {
            'protocols': {},
            'fuzzing': {'total_requests': 0, 'summary': {}, 'issues': []},
            'authentication': {},
        }
    discovery = ProtocolDiscovery()
    protocol_map = discovery.discover(traffic)
    session_engine = SessionAutomationEngine()
    orchestrator = FuzzingOrchestrator(session_engine, OWASPTop10Fuzzer())
    fuzzing_report = orchestrator.run(discovery.iter_adapters())
    auth_analysis = AuthenticationAnalyzer(traffic, fuzzing_report).analyze()

    protocols = {
        name: [_endpoint_to_dict(endpoint) for endpoint in endpoints]
        for name, endpoints in protocol_map.items()
    }

    fuzzing = {
        'total_requests': fuzzing_report.total_requests,
        'summary': fuzzing_report.summary(),
        'issues': [
            {
                'endpoint': _endpoint_to_dict(result.endpoint),
                'payload': {
                    'category': result.payload.category,
                    'value': result.payload.value,
                },
                'status_code': result.status_code,
                'issues': result.issues,
                'error': result.error,
            }
            for result in fuzzing_report.potential_issues
        ],
    }

    authentication = {
        category: [
            {
                'category': finding.category,
                'evidence': finding.evidence,
                'severity': finding.severity,
            }
            for finding in findings
        ]
        for category, findings in auth_analysis.items()
        if findings
    }

    return {
        'protocols': protocols,
        'fuzzing': fuzzing,
        'authentication': authentication,
    }


__all__ = ['build_dast_report']

