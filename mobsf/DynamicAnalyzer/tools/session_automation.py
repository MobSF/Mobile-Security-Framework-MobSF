"""Session automation helpers used by the DAST fuzzing engine."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from django.conf import settings

try:  # pragma: no cover - optional dependency
    import requests
except ImportError:  # pragma: no cover - handled gracefully in runtime
    requests = None

logger = logging.getLogger(__name__)


@dataclass
class SessionState:
    """Represents a logical authenticated session."""

    token: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    last_rotation: float = field(default_factory=time.time)
    retries: int = 0


class SessionAutomationEngine:
    """Automate authenticated sessions for DAST fuzzing."""

    def __init__(self, base_url: str | None = None, verify_tls: bool = True):
        self.base_url = base_url
        self.verify_tls = verify_tls
        self.allow_real_traffic = settings.DAST_ALLOW_REAL_TRAFFIC and requests is not None
        self.timeout = settings.DAST_DEFAULT_TIMEOUT
        self.state = SessionState()
        self._session = requests.Session() if self.allow_real_traffic else None
        if self._session:
            self._session.verify = verify_tls

    def ensure_session(self):
        if not self._session and self.allow_real_traffic:
            self._session = requests.Session()
            self._session.verify = self.verify_tls
        return self._session

    def simulate_login(self, url: str, payload: dict | None = None, headers: dict | None = None):
        """Perform a login workflow and persist tokens when real traffic is allowed."""
        session = self.ensure_session()
        if not session:
            logger.debug('Session automation running in offline mode; login skipped.')
            return None
        try:
            response = session.post(url, json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            token = response.headers.get('Authorization') or response.json().get('token')
            if token:
                self.state.token = token
                session.headers.update({'Authorization': token})
            if response.cookies:
                session.cookies.update(response.cookies)
            self.state.last_rotation = time.time()
            return response
        except Exception:  # pragma: no cover - runtime network interactions
            logger.exception('Automated login failed')
            self.state.retries += 1
            return None

    def refresh_token_if_needed(self):
        rotation_window = settings.DAST_SESSION_STRATEGIES['rotation_window']
        if time.time() - self.state.last_rotation > rotation_window:
            logger.debug('Session rotation window elapsed; invalidating token.')
            self.state.token = None
            if self._session:
                self._session.headers.pop('Authorization', None)
            self.state.last_rotation = time.time()

    def replay_request(self, method: str, url: str, *, data=None, headers=None):
        session = self.ensure_session()
        if not session:
            logger.debug('Replay requested but offline mode is active.')
            return None
        try:
            return session.request(
                method,
                url,
                data=data,
                headers=headers,
                timeout=self.timeout,
            )
        except Exception:  # pragma: no cover
            logger.exception('Replay request failed')
            return None

    def send(self, method: str, url: str, *, data=None, headers=None):
        session = self.ensure_session()
        if not session:
            return {
                'status_code': None,
                'body': '',
                'error': 'offline-mode',
                'elapsed': 0.0,
            }
        start = time.perf_counter()
        try:
            response = session.request(
                method,
                url,
                data=data,
                headers=headers,
                timeout=self.timeout,
            )
            elapsed = time.perf_counter() - start
            return {
                'status_code': response.status_code,
                'body': response.text,
                'error': None,
                'elapsed': elapsed,
                'headers': dict(response.headers),
            }
        except Exception as exc:  # pragma: no cover - runtime dependent
            elapsed = time.perf_counter() - start
            logger.warning('Session request failed: %s', exc)
            return {
                'status_code': None,
                'body': '',
                'error': str(exc),
                'elapsed': elapsed,
            }

    def invalidate(self):
        self.state = SessionState()
        if self._session:
            self._session.close()
        self._session = requests.Session() if self.allow_real_traffic else None


__all__ = ['SessionAutomationEngine', 'SessionState']

