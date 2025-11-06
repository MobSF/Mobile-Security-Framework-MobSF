"""OWASP ZAP connector simulation."""

from __future__ import annotations

from typing import Mapping

from .base import AutomationConnector, AutomationResult


class ZAPConnector(AutomationConnector):
    """ZAP API connector placeholder."""

    name = 'zap'
    display_name = 'OWASP ZAP'
    required_keys = ('address', 'port')

    def execute(self, findings: Mapping[str, dict], metadata=None) -> AutomationResult:
        warning_findings = [
            fid for fid, details in (findings or {}).items()
            if (details.get('metadata') or {}).get('severity', '').lower() in {'high', 'warning'}
        ]
        confirmed = warning_findings[:1]
        notes = {
            'context': self.config.get('context', ''),
            'mode': 'passive-simulation',
        }
        return AutomationResult(
            name=self.name,
            display_name=self.display_name,
            executed=True,
            status='completed',
            reason='Simulated passive scan',
            confirmed=confirmed,
            notes=notes,
        )


__all__ = ['ZAPConnector']
