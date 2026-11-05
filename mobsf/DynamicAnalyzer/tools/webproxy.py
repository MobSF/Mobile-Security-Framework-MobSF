import ipaddress
import logging
import os
from pathlib import Path
import re
import subprocess
import threading
import time
from urllib.parse import urlparse

from django.conf import settings

from mitmproxy import io as mitm_io
from mitmproxy.http import HTTPFlow

import psutil

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    docker_translate_proxy_ip,
    strict_package_check,
    upstream_proxy,
)

logger = logging.getLogger(__name__)
_PROXY_LOCK = threading.Lock()
_PROXY_PROCESS = None
_FLOW_CACHE_LOCK = threading.Lock()
_FLOW_CACHE = {}


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
    """Read HTTPFlow entries from a mitmproxy stream file with mtime/size cache."""
    if not flow_file:
        return []
    path = Path(flow_file)
    flows = []
    try:
        stat = path.stat()
        key = path.as_posix()
        sig = (stat.st_mtime_ns, stat.st_size)
        with _FLOW_CACHE_LOCK:
            cached = _FLOW_CACHE.get(key)
            if cached and cached[0] == sig:
                return list(cached[1])
        with path.open('rb') as handle:
            for item in mitm_io.FlowReader(handle).stream():
                if isinstance(item, HTTPFlow):
                    flows.append(item)
        with _FLOW_CACHE_LOCK:
            _FLOW_CACHE.clear()
            _FLOW_CACHE[key] = (sig, flows)
        return list(flows)
    except Exception:
        logger.warning('Unable to read full flow stream from %s', flow_file)
        return list(flows)


def get_sorted_flows(flows):
    """Group captured HTTPFlows by scheme://netloc (newest first)."""
    sorted_flows = {}
    for flow in reversed(flows):
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


def _valid_host_or_ip(host):
    """Return True if host is a valid IPv4/IPv6 literal or DNS hostname."""
    if not isinstance(host, str) or not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host))


def _parse_fuzzer_proxy_parts(proxy_url):
    """Validate an upstream fuzzer proxy URL and return (scheme, host, port, url)."""
    if not isinstance(proxy_url, str) or not proxy_url.strip():
        return None
    parsed = urlparse(proxy_url.strip())
    if parsed.scheme not in ('http', 'https'):
        return None
    if parsed.username or parsed.password or parsed.path not in ('', '/'):
        return None
    host = parsed.hostname
    port = parsed.port
    if (not _valid_host_or_ip(host)
            or not isinstance(port, int)
            or not (1 <= port <= 65535)):
        return None
    if port == int(settings.PROXY_PORT) and host in (
            '127.0.0.1', 'localhost', '::1', '0.0.0.0'):
        return None
    host = docker_translate_proxy_ip(host)
    formatted_host = f'[{host}]' if ':' in host else host
    return (
        parsed.scheme,
        host,
        port,
        f'{parsed.scheme}://{formatted_host}:{port}',
    )


def _parse_fuzzer_proxy(proxy_url):
    """Validate and normalize an upstream fuzzer proxy URL (e.g. Burp/ZAP)."""
    parts = _parse_fuzzer_proxy_parts(proxy_url)
    return parts[3] if parts else None


def replay_flows(project, proxy_url):
    """Replay captured project flows through an upstream proxy (e.g. Burp/ZAP)."""
    flow_file = get_flow_file(project)
    if not flow_file:
        return False, 'No captured HTTP(S) traffic found for this project'
    parts = _parse_fuzzer_proxy_parts(proxy_url)
    if not parts:
        return False, 'Invalid fuzzer proxy URL (expected http://host:port)'
    scheme, host, port, normalized_proxy = parts
    flows = load_flows(flow_file)
    if not flows:
        return False, 'No captured HTTP(S) requests found in project flow file'

    capture_script = Path(__file__).resolve().parent / 'mitm_capture.py'
    args = [
        'mitmdump',
        '--no-server',
        '--ssl-insecure',
        '--scripts', capture_script.as_posix(),
        '--set', 'connection_strategy=lazy',
        '--set', 'upstream_cert=false',
        '--set', f'mobsf_replay_scheme={scheme}',
        '--set', f'mobsf_replay_host={host}',
        '--set', f'mobsf_replay_port={port}',
        '--set', f'mobsf_skip_port={int(settings.PROXY_PORT)}',
        '--client-replay', flow_file.as_posix(),
    ]

    def _run_replay():
        with open(os.devnull, 'w', encoding='utf-8') as fnull:
            subprocess.run(
                args,
                stdin=subprocess.DEVNULL,
                stdout=fnull,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=False,
            )

    thread = threading.Thread(target=_run_replay, daemon=True)
    thread.start()
    return (
        True,
        f'Replaying {len(flows)} captured request(s) to {normalized_proxy}',
    )


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
        orphans = []
        for item in psutil.process_iter(['name', 'cmdline']):
            try:
                name = (item.info.get('name') or '').lower()
                cmdline = item.info.get('cmdline') or []
                if (('mitmdump' in name
                        or any('mitmdump' in part.lower() for part in cmdline))
                        and port_arg in cmdline):
                    item.terminate()
                    orphans.append(item)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if orphans:
            _, alive = psutil.wait_procs(orphans, timeout=5)
            for item in alive:
                try:
                    item.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            psutil.wait_procs(alive, timeout=2)


def _upstream_mitm_args(proxy_url):
    """Build mitmdump `--mode upstream:...` and `--upstream-auth` arguments."""
    if not proxy_url:
        return []
    parsed = urlparse(proxy_url)
    if not parsed.scheme or not parsed.hostname or not parsed.port:
        return []
    host = f'[{parsed.hostname}]' if ':' in parsed.hostname else parsed.hostname
    args = ['--mode', f'upstream:{parsed.scheme}://{host}:{parsed.port}']
    if parsed.username:
        password = parsed.password or ''
        args.extend(['--upstream-auth', f'{parsed.username}:{password}'])
    return args


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
    with _FLOW_CACHE_LOCK:
        _FLOW_CACHE.pop(flow_file.as_posix(), None)

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
    if proxies.get('http'):
        argz.extend(_upstream_mitm_args(proxies['http']))
    with _PROXY_LOCK:
        with open(os.devnull, 'w', encoding='utf-8') as fnull:
            _PROXY_PROCESS = subprocess.Popen(
                argz,
                stdin=subprocess.DEVNULL,
                stdout=fnull,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )


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
