"""Authentication specific analysis for DAST."""
from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional

from .fuzzing import FuzzingReport

logger = logging.getLogger(__name__)

TOKEN_RE = re.compile(r'Authorization:\s*Bearer\s+([A-Za-z0-9\-._]+)', re.IGNORECASE)
FAILED_AUTH_RE = re.compile(r'401\s+Unauthorized|invalid token', re.IGNORECASE)
REPLAY_ID_RE = re.compile(r'X-Request-Id:\s*([A-Za-z0-9\-]+)', re.IGNORECASE)


@dataclass
class AuthenticationFinding:
    category: str
    evidence: List[str]
    severity: str = 'medium'


class AuthenticationAnalyzer:
    """Perform contextual authentication assessments."""

    def __init__(self, traffic_dump: str, fuzzing_report: Optional[FuzzingReport] = None):
        self.traffic_dump = traffic_dump or ''
        self.fuzzing_report = fuzzing_report

    def analyze(self) -> Dict[str, List[AuthenticationFinding]]:
        findings = {
            'invalid_tokens': self._detect_invalid_tokens(),
            'replay_indicators': self._detect_replay(),
            'brute_force': self._detect_bruteforce(),
            'fuzzing': self._analyse_fuzzing_feedback(),
        }
        return findings

    def _detect_invalid_tokens(self) -> List[AuthenticationFinding]:
        tokens = TOKEN_RE.findall(self.traffic_dump)
        failures = FAILED_AUTH_RE.findall(self.traffic_dump)
        if not tokens and not failures:
            return []
        evidence = [
            f'{len(tokens)} tokens observed',
            f'{len(failures)} authentication failures recorded',
        ]
        return [AuthenticationFinding('Invalid tokens observed', evidence, 'high')]

    def _detect_replay(self) -> List[AuthenticationFinding]:
        replay_ids = REPLAY_ID_RE.findall(self.traffic_dump)
        if not replay_ids:
            return []
        counter = Counter(replay_ids)
        collisions = [rid for rid, count in counter.items() if count > 1]
        if not collisions:
            return []
        evidence = [f'Repeated request identifier {rid}' for rid in collisions]
        return [AuthenticationFinding('Potential replay attempt', evidence, 'medium')]

    def _detect_bruteforce(self) -> List[AuthenticationFinding]:
        attempts = defaultdict(int)
        for match in re.finditer(r'login|password|otp', self.traffic_dump, re.IGNORECASE):
            window = self.traffic_dump[match.start():match.start() + 200]
            ip_match = re.search(r'Client-IP:\s*([0-9.]+)', window, re.IGNORECASE)
            if ip_match:
                attempts[ip_match.group(1)] += 1
        suspicious = [ip for ip, count in attempts.items() if count >= 5]
        if not suspicious:
            return []
        evidence = [
            f'{ip} performed {attempts[ip]} credential attempts'
            for ip in suspicious
        ]
        return [AuthenticationFinding('Brute force behaviour detected', evidence, 'high')]

    def _analyse_fuzzing_feedback(self) -> List[AuthenticationFinding]:
        if not self.fuzzing_report:
            return []
        suspicious = []
        for result in self.fuzzing_report.results:
            if result.status_code == 401 and result.payload.value:
                suspicious.append(
                    f'401 after fuzzing {result.endpoint.url} with {result.payload.value[:30]}')
            if any('A07' in issue for issue in result.issues):
                suspicious.append(
                    f'Authentication control bypass signals on {result.endpoint.url}')
        if not suspicious:
            return []
        return [AuthenticationFinding('Fuzzing triggered authentication responses', suspicious, 'medium')]


__all__ = ['AuthenticationAnalyzer', 'AuthenticationFinding']

