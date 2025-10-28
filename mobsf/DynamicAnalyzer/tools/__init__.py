"""Utilities available for Dynamic Analyzer tooling."""

from .auth_analysis import AuthenticationAnalyzer, AuthenticationFinding
from .fuzzing import (
    FuzzingOrchestrator,
    FuzzingPayload,
    FuzzingReport,
    FuzzingResult,
    OWASPTop10Fuzzer,
)
from .mitmproxy_integration import DEFAULT_CONTROLLER, MitmProxyController
from .protocols import (
    EndpointDefinition,
    GraphQLProtocolAdapter,
    ProtocolAdapter,
    ProtocolDiscovery,
    RESTProtocolAdapter,
    WebSocketProtocolAdapter,
)
from .session_automation import SessionAutomationEngine, SessionState
from .reporting import build_dast_report

__all__ = [
    'AuthenticationAnalyzer',
    'AuthenticationFinding',
    'FuzzingOrchestrator',
    'FuzzingPayload',
    'FuzzingReport',
    'FuzzingResult',
    'OWASPTop10Fuzzer',
    'MitmProxyController',
    'DEFAULT_CONTROLLER',
    'EndpointDefinition',
    'GraphQLProtocolAdapter',
    'ProtocolAdapter',
    'ProtocolDiscovery',
    'RESTProtocolAdapter',
    'WebSocketProtocolAdapter',
    'SessionAutomationEngine',
    'SessionState',
    'build_dast_report',
]
