"""ProjectDiscovery Nuclei connector simulation."""

from __future__ import annotations

from typing import Mapping

from .base import AutomationConnector, AutomationResult


class NucleiConnector(AutomationConnector):
    """Nuclei scanner placeholder."""

    name = 'nuclei'
    display_name = 'Nuclei'
    required_keys = ('binary',)

    def execute(self, findings: Mapping[str, dict], metadata=None) -> AutomationResult:
        severity_threshold = (self.config.get('severity_threshold') or 'high').lower()
        candidate_findings = []
        for fid, details in (findings or {}).items():
            severity = (details.get('metadata') or {}).get('severity', '').lower()
            if severity in {'critical', 'high'}:
                candidate_findings.append(fid)
            elif severity_threshold == 'medium' and severity in {'medium', 'warning'}:
                candidate_findings.append(fid)
        notes = {
            'templates': self.config.get('templates', ''),
            'mode': 'template-simulation',
        }
        return AutomationResult(
            name=self.name,
            display_name=self.display_name,
            executed=True,
            status='completed',
            reason='Simulated template execution',
            confirmed=candidate_findings[:2],
            notes=notes,
        )


__all__ = ['NucleiConnector']
