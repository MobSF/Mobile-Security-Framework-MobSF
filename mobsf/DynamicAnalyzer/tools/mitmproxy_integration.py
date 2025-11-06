"""Integration helpers for mitmproxy based traffic capture."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterable, Optional

from django.conf import settings

try:  # pragma: no cover - mitmproxy optional at runtime
    from mitmproxy import io, options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.exceptions import FlowReadException
except Exception:  # pragma: no cover
    io = None
    options = None
    DumpMaster = None
    FlowReadException = Exception

logger = logging.getLogger(__name__)


class MitmProxyController:
    """Manage mitmproxy subprocesses and captured flows."""

    def __init__(self, capture_dir: Optional[str] = None):
        self.capture_dir = Path(capture_dir or settings.DAST_CAPTURE_DIR)
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.capture_dir, 0o700)
        except (PermissionError, NotImplementedError):
            pass
        self._thread: Optional[threading.Thread] = None
        self._master: Optional[DumpMaster] = None
        self._running = threading.Event()

    def start_capture(self, project: str, listen_port: int | None = None):
        """Start mitmproxy capture for a project."""
        capture_file = self.capture_dir / f'{project}.mitm'
        listen_port = listen_port or settings.PROXY_PORT
        if DumpMaster is None:
            logger.warning('mitmproxy not installed; capture disabled.')
            return capture_file
        if self._running.is_set():
            logger.debug('Capture already running for mitmproxy.')
            return capture_file

        opts = options.Options(listen_host='0.0.0.0', listen_port=listen_port)
        opts.add_option('save_stream_file', str(capture_file), str, '')
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._running.set()

        def _run_master():  # pragma: no cover - thread with IO
            try:
                self._master.run()
            except Exception:
                logger.exception('mitmproxy capture error')
            finally:
                self._running.clear()

        self._thread = threading.Thread(target=_run_master, daemon=True)
        self._thread.start()
        logger.info('mitmproxy capture started at port %s', listen_port)
        return capture_file

    def stop_capture(self):
        if self._master:
            try:
                self._master.shutdown()
            except Exception:  # pragma: no cover
                logger.debug('mitmproxy shutdown raised an exception', exc_info=True)
            self._master = None
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info('mitmproxy capture stopped')

    def ensure_ca_certificate(self) -> Optional[str]:
        if options is None:
            return None
        ca_dir = Path(options.CONF_DIR).expanduser()
        ca_file = ca_dir / 'mitmproxy-ca-cert.pem'
        if not ca_file.exists():
            self._generate_ca()
        return str(ca_file)

    def _generate_ca(self):  # pragma: no cover - depends on external binary
        try:
            subprocess.Popen(['mitmdump', '-n'],
                             stdin=None,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             close_fds=True)
            time.sleep(3)
        except FileNotFoundError:
            logger.warning('mitmdump binary not found; cannot generate CA certificate')

    def get_project_traffic(self, project: str) -> str:
        capture_file = self.capture_dir / f'{project}.mitm'
        if not capture_file.exists():
            return ''
        if io is None:
            return capture_file.read_text('utf-8', 'ignore')
        try:
            data = []
            with capture_file.open('rb') as src:
                reader = io.FlowReader(src)
                for flow in reader.stream():
                    data.append(self._flow_to_json(flow))
            return '\n'.join(data)
        except FlowReadException:
            logger.warning('Failed to parse mitmproxy flow file %s', capture_file)
            return capture_file.read_text('utf-8', 'ignore')

    def generate_ca(self):
        """Public helper to generate the mitmproxy CA."""
        self._generate_ca()

    def _flow_to_json(self, flow) -> str:  # pragma: no cover - depends on mitmproxy
        if hasattr(flow, 'request'):
            payload = {
                'request': {
                    'method': flow.request.method,
                    'url': flow.request.pretty_url,
                    'headers': dict(flow.request.headers),
                    'content': flow.request.get_text(strict=False),
                },
                'response': {
                    'status_code': getattr(flow.response, 'status_code', None),
                    'headers': dict(getattr(flow.response, 'headers', {})),
                },
            }
            return json.dumps(payload)
        return json.dumps({'raw': str(flow)})

    def list_captures(self) -> Iterable[str]:
        for file in self.capture_dir.glob('*.mitm'):
            yield file.stem


DEFAULT_CONTROLLER = MitmProxyController()


__all__ = ['MitmProxyController', 'DEFAULT_CONTROLLER']

