"""Base classes for external exploitation connectors."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Tuple


@dataclass
class AutomationResult:
    """Result returned by a connector."""

    name: str
    display_name: str
    executed: bool
    status: str
    reason: str = ''
    confirmed: List[str] = field(default_factory=list)
    notes: Mapping[str, str] = field(default_factory=dict)


class AutomationConnector:
    """Base connector exposing common helpers."""

    name: str = 'connector'
    display_name: str = 'Connector'
    required_keys: Tuple[str, ...] = ()

    def __init__(self, config: Mapping[str, object]):
        self.config: Dict[str, object] = dict(config or {})

    def validate(self) -> Tuple[bool, str]:
        """Validate configuration and return status, reason."""
        missing: Iterable[str] = [
            key for key in self.required_keys if not self.config.get(key)
        ]
        if missing:
            return False, f"Missing configuration keys: {', '.join(missing)}"
        return True, ''

    def describe_disabled(self, reason: str, status: str = 'skipped') -> AutomationResult:
        """Generate a disabled connector result."""
        return AutomationResult(
            name=self.name,
            display_name=self.display_name,
            executed=False,
            status=status,
            reason=reason,
        )

    def execute(self, findings: Mapping[str, dict], metadata=None) -> AutomationResult:
        """Execute connector; subclasses must override."""
        raise NotImplementedError


__all__ = ['AutomationConnector', 'AutomationResult']
