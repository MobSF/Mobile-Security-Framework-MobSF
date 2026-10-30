import logging
import os
from pathlib import Path
import subprocess
import threading
import time
from urllib.parse import urlparse

from django.conf import settings
from django.http.request import split_domain_port

from mitmproxy import io as mitm_io
from mitmproxy.http import HTTPFlow

import psutil

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    strict_package_check,
    upstream_proxy,
)

logger = logging.getLogger(__name__)
_PROXY_LOCK = threading.Lock()
_PROXY_PROCESS = None


def flows_dir():
    """Return the directory where mitmproxy flow files are stored."""
    directory = Path.home() / '.httptools' / 'flows'
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _valid_project(project):
    """Validate a package / bundle ID used as a flow file stem."""
    return (
        isinstance(project, str)
        and bool(project.strip())
        and strict_package_check(project)
        and not is_path_traversal(project)
    )


def get_flow_file(project):
    """Return the validated Path to `<project>.flow` if it exists."""
    if not _valid_project(project):
        return None
    root = flows_dir().resolve()
    filename = f'{project}.flow'
    candidate = (root / filename).resolve()
    if (is_safe_path(root, candidate, filename)
            and candidate.is_file()
            and not is_pipe_or_link(candidate)):
        return candidate
    return None


def list_flow_projects():
    """Return sorted project names that have captured `.flow` files."""
    root = flows_dir().resolve()
    projects = []
    for path in sorted(root.glob('*.flow')):
        if path.is_file() and not is_pipe_or_link(path):
            stem = path.stem
            if _valid_project(stem):
                projects.append(stem)
    return projects


def load_flows(flow_file):
    """Read HTTPFlow entries from a mitmproxy stream file."""
    flows = []
    if not flow_file:
        return flows
    try:
        with Path(flow_file).open('rb') as handle:
            for item in mitm_io.FlowReader(handle).stream():
                if isinstance(item, HTTPFlow):
                    flows.append(item)
    except Exception:
        logger.warning('Unable to read full flow stream from %s', flow_file)
    return flows


def get_sorted_flows(flows):
    """Group captured HTTPFlows by scheme://netloc for the traffic viewer."""
    sorted_flows = {}
    for flow in flows:
        if not isinstance(flow, HTTPFlow):
            continue
        parsed = urlparse(flow.request.url)
        domain = (
            f'{parsed.scheme}://{parsed.netloc}'
            if parsed.scheme and parsed.netloc else 'unknown'
        )
        relative = (
            flow.request.url[len(domain):]
            if flow.request.url.startswith(domain) else flow.request.url
        )
        status_code = (
            flow.response.status_code
            if getattr(flow, 'response', None) else None
        )
        meta = {
            'id': flow.id,
            'method': flow.request.method,
            'relative': relative or '/',
            'url': flow.request.url,
            'status_code': status_code,
        }
        sorted_flows.setdefault(domain, []).append(meta)
    return sorted_flows


def get_flow_meta(flow):
    """Return request and response details for one HTTPFlow."""
    req_headers = dict(flow.request.headers.items())
    req_content = (
        flow.request.content.decode('utf-8', 'ignore')
        if flow.request.content else ''
    )
    meta = {
        'id': flow.id,
        'request': {
            'method': flow.request.method,
            'url': flow.request.url,
            'http_version': flow.request.http_version,
            'headers': req_headers,
            'content': req_content,
        },
        'response': None,
    }
    if getattr(flow, 'response', None) and hasattr(flow.response, 'headers'):
        res_headers = dict(flow.response.headers.items())
        res_content = (
            flow.response.content.decode('utf-8', 'ignore')
            if flow.response.content else ''
        )
        meta['response'] = {
            'http_version': flow.response.http_version,
            'status_code': flow.response.status_code,
            'reason': flow.response.reason,
            'headers': res_headers,
            'content': res_content,
        }
    return meta


def stop_httptools():
    """Stop any running mitmdump capture process on the configured proxy port."""
    global _PROXY_PROCESS  # pylint: disable=global-statement
    with _PROXY_LOCK:
        proc = _PROXY_PROCESS
        _PROXY_PROCESS = None
        if proc is not None and proc.poll() is None:
            logger.info('Stopping mitmdump proxy')
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        # Best-effort cleanup of any orphaned mitmdump listening on PROXY_PORT
        port_arg = str(settings.PROXY_PORT)
        for item in psutil.process_iter(['name', 'cmdline']):
            try:
                name = (item.info.get('name') or '').lower()
                cmdline = item.info.get('cmdline') or []
                if ('mitmdump' in name
                        or any('mitmdump' in part.lower() for part in cmdline)):
                    if port_arg in cmdline:
                        item.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


def start_proxy(port, project):
    """Start mitmdump in capture mode."""
    global _PROXY_PROCESS  # pylint: disable=global-statement
    if not _valid_project(project):
        logger.error('Invalid project name for proxy capture')
        return
    flow_dir = flows_dir()
    flow_file = flow_dir / f'{project}.flow'
    txt_file = flow_dir / f'{project}.flow.txt'
    flow_file.unlink(missing_ok=True)
    txt_file.unlink(missing_ok=True)

    capture_script = Path(__file__).resolve().parent / 'mitm_capture.py'
    argz = [
        'mitmdump',
        '--listen-host', '0.0.0.0',
        '--listen-port', str(port),
        '--ssl-insecure',
        '--flow-detail', '0',
        '--save-stream-file', flow_file.as_posix(),
        '--scripts', capture_script.as_posix(),
    ]
    proxies, _ = upstream_proxy('http')
    if proxies['http']:
        argz.extend(['--mode', f'upstream:{proxies["http"]}'])
    with _PROXY_LOCK:
        with open(os.devnull, 'w', encoding='utf-8') as fnull:
            _PROXY_PROCESS = subprocess.Popen(
                argz,
                stdin=subprocess.DEVNULL,
                stdout=fnull,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )


def start_httptools_ui(port):
    """No-op kept for backwards compatibility; UI is served directly by Django."""
    return True


def _mitm_ca_file():
    """Path to the mitmproxy generated CA cert."""
    from mitmproxy import options
    ca_dir = Path(options.CONF_DIR).expanduser()
    return ca_dir / 'mitmproxy-ca-cert.pem'


def create_ca():
    """Generate CA on first run."""
    ca_file = _mitm_ca_file()
    if ca_file.exists():
        return

    argz = ['mitmdump', '-n']
    proc = subprocess.Popen(argz,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            close_fds=True)
    try:
        # mitmdump is only needed here to generate the CA cert. Stop it
        # once the cert file appears instead of leaving it running as a
        # leaked background process.
        for _ in range(30):
            if ca_file.exists() or proc.poll() is not None:
                break
            time.sleep(0.5)
        if not ca_file.exists():
            logger.warning('mitmproxy root CA generation failed.')
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def get_ca_file():
    """Get CA Dir."""
    ca_file = _mitm_ca_file()
    if not ca_file.exists():
        create_ca()
    return ca_file.as_posix()


def get_traffic(package):
    if not _valid_project(package):
        return ''
    web = flows_dir() / f'{package}.flow.txt'
    if web.is_file() and not is_pipe_or_link(web):
        return web.read_text('utf-8', 'ignore')
    return ''


def get_http_tools_url(req):
    """Get a validated browser URL for the local httptools UI."""
    domain, _ = split_domain_port(req.get_host())
    if not domain:
        raise ValueError('Untrusted HTTPTools redirect host')
    scheme = req.scheme if req.scheme in ('http', 'https') else 'http'
    return f'{scheme}://{domain}:{settings.PROXY_PORT}'
