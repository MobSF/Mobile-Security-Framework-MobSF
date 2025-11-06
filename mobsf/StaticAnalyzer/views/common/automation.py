"""Controlled exploitation orchestration helpers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import logging
from typing import Dict, Iterable, Mapping, MutableMapping, Optional, Set

from django.conf import settings

from scripts.automation import get_connector_registry
from scripts.automation.base import AutomationConnector, AutomationResult

from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
    StaticAnalyzerWindows,
)

logger = logging.getLogger(__name__)


def _get_default_mode() -> str:
    return settings.AUTOMATION_EXECUTION.get('default_mode', 'standard')


def _collect_findings(context: Mapping[str, object]) -> Dict[str, dict]:
    analysis = context.get('code_analysis', {})
    if isinstance(analysis, Mapping):
        findings = analysis.get('findings', {})
        if isinstance(findings, Mapping):
            return dict(findings)
    return {}


def classify_findings(findings: Mapping[str, dict], confirmed_ids: Iterable[str]):
    """Split findings into confirmed and potential maps."""
    confirmed: Dict[str, dict] = {}
    potential: Dict[str, dict] = {}
    confirmed_set: Set[str] = set(confirmed_ids)
    for rule_id, details in findings.items():
        entry = deepcopy(details)
        metadata = entry.get('metadata') or {}
        if not isinstance(metadata, MutableMapping):
            metadata = {'value': metadata}
        entry['metadata'] = dict(metadata)
        if rule_id in confirmed_set:
            entry['classification'] = 'exploracao_confirmada'
            confirmed[rule_id] = entry
        else:
            entry['classification'] = 'possivel_vulnerabilidade'
            potential[rule_id] = entry
    return confirmed, potential


def build_result(mode: str,
                 findings: Mapping[str, dict],
                 connectors_output: Iterable[dict],
                 confirmed_ids: Iterable[str]):
    confirmed, potential = classify_findings(findings, confirmed_ids)
    connectors_list = list(connectors_output)
    executed = sum(1 for item in connectors_list if item.get('executed'))
    summary = {
        'mode': mode,
        'confirmed_total': len(confirmed),
        'potential_total': len(potential),
        'connectors_triggered': executed,
    }
    return {
        'mode': mode,
        'summary': summary,
        'confirmed': confirmed,
        'potential': potential,
        'connectors': connectors_list,
    }


class ControlledExploitationOrchestrator:
    """Prepare and run exploitation connectors."""

    def __init__(self, mode: Optional[str], connectors_config: Mapping[str, Mapping[str, object]]):
        self.mode = (mode or _get_default_mode()).lower()
        self.connectors_config = connectors_config or {}
        self.registry = get_connector_registry()
        self.passive_results = []
        self.active_connectors: list[AutomationConnector] = []
        self._prepare_connectors()

    def _prepare_connectors(self) -> None:
        for name, connector_cls in self.registry.items():
            config = self.connectors_config.get(name, {})
            connector = connector_cls(config)
            if self.mode != 'aggressive':
                self.passive_results.append(
                    asdict(connector.describe_disabled('Aggressive mode disabled')))
                continue
            if not config.get('enabled'):
                self.passive_results.append(
                    asdict(connector.describe_disabled('Connector disabled')))
                continue
            ok, reason = connector.validate()
            if not ok:
                self.passive_results.append(
                    asdict(connector.describe_disabled(reason or 'Invalid configuration')))
                continue
            self.active_connectors.append(connector)

    def run(self,
            checksum: Optional[str],
            findings: Mapping[str, dict],
            metadata: Optional[Mapping[str, object]] = None) -> dict:
        connectors_output = list(self.passive_results)
        confirmed_ids: Set[str] = set()
        metadata = metadata or {}
        if self.mode == 'aggressive':
            for connector in self.active_connectors:
                try:
                    result = connector.execute(findings=findings, metadata=metadata)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.exception('Connector %s failed', connector.name)
                    error_result = AutomationResult(
                        name=connector.name,
                        display_name=connector.display_name,
                        executed=False,
                        status='error',
                        reason=str(exc),
                    )
                    connectors_output.append(asdict(error_result))
                    continue
                connectors_output.append(asdict(result))
                confirmed_ids.update(result.confirmed)
        return build_result(self.mode, findings, connectors_output, confirmed_ids)


def ensure_controlled_exploitation(context: MutableMapping[str, object],
                                   mode: Optional[str],
                                   platform: str) -> dict:
    """Ensure controlled exploitation data is attached to context."""
    findings = _collect_findings(context)
    connectors_config = settings.AUTOMATION_EXECUTION.get('connectors', {})
    orchestrator = ControlledExploitationOrchestrator(mode, connectors_config)
    metadata = {
        'platform': platform,
        'app_name': context.get('app_name', ''),
        'package_name': context.get('package_name', ''),
        'bundle_id': context.get('bundle_id', ''),
    }
    checksum = context.get('md5')
    result = orchestrator.run(checksum, findings, metadata)
    context['controlled_exploitation'] = result
    context['execution_mode'] = orchestrator.mode
    persist_controlled_exploitation(checksum, result, platform)
    return result


def persist_controlled_exploitation(checksum: Optional[str],
                                    result: Mapping[str, object],
                                    platform: str) -> None:
    """Persist automation results for future lookups."""
    if not checksum:
        return
    try:
        if platform == 'android':
            StaticAnalyzerAndroid.objects.filter(MD5=checksum).update(
                CONTROLLED_EXPLOITATION=result)
        elif platform == 'ios':
            StaticAnalyzerIOS.objects.filter(MD5=checksum).update(
                CONTROLLED_EXPLOITATION=result)
        elif platform == 'windows':
            StaticAnalyzerWindows.objects.filter(MD5=checksum).update(
                CONTROLLED_EXPLOITATION=result)
    except Exception:  # pragma: no cover - db write safety
        logger.exception('Unable to persist controlled exploitation results')


__all__ = [
    'ControlledExploitationOrchestrator',
    'ensure_controlled_exploitation',
    'classify_findings',
]
