import logging
from pathlib import Path
import subprocess
import sys
import time

import requests

from django.conf import settings

from mobsf.DynamicAnalyzer.tools.capture_runner import (
    capture_arguments,
    capture_config,
    proxy_preflight,
)

logger = logging.getLogger(__name__)


def stop_httptools(url):
    """Kill httptools."""
    # httptools is a local subprocess. Never use the request Host header for
    # this server-side call; ALLOWED_HOSTS may be configured broadly.
    local_url = f'http://127.0.0.1:{settings.PROXY_PORT}'
    # Invoke HTTPtools UI Kill Request
    try:
        requests.get(f'{local_url}/kill', timeout=5)
        logger.info('Killing httptools UI')
    except Exception:
        pass

    # Invoke HTTPtools Proxy Kill Request
    try:
        http_proxy = local_url
        headers = {'httptools': 'kill'}
        proxy_kill_url = 'http://127.0.0.1'
        requests.get(
            proxy_kill_url,
            timeout=5,
            headers=headers,
            proxies={'http': http_proxy})
        logger.info('Killing httptools Proxy')
    except Exception:
        pass


def start_proxy(port, project):
    """Start HTTPtools in Proxy Mode."""
    config = capture_config()
    capture_arguments(port, project, config)
    if config['url'] and not proxy_preflight()['ready']:
        raise ValueError('Configured interception proxy is unreachable')
    argz = [sys.executable, '-m',
            'mobsf.DynamicAnalyzer.tools.capture_runner',
            '--port', str(port), '--project', project]
    logs = Path(settings.MOBSF_HOME) / 'capture-proxy.log'
    with logs.open('a', encoding='utf-8') as output:
        return subprocess.Popen(argz, stdout=output, stderr=subprocess.STDOUT)


def start_httptools_ui(port):
    """Start Server UI."""
    subprocess.Popen([sys.executable, '-m',
                      'mobsf.DynamicAnalyzer.tools.capture_runner',
                      '--ui', '--port', str(port)])
    time.sleep(3)


def _mitm_ca_file():
    """Path to the mitmproxy generated CA cert."""
    ca_dir = Path(settings.MOBSF_HOME) / 'mitmproxy'
    return ca_dir / 'mitmproxy-ca-cert.pem'


def create_ca():
    """Generate CA on first run."""
    ca_file = _mitm_ca_file()
    if ca_file.exists():
        return

    argz = ['mitmdump', '-n', '--set',
            'confdir=' + str(Path(settings.MOBSF_HOME) / 'mitmproxy')]
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
    web = Path(settings.MOBSF_HOME) / 'traffic' / f'{package}.flow.txt'
    if web.is_file():
        return web.read_text('utf-8', 'ignore')
    return ''


def get_http_tools_url(req):
    """Get httptools URL from request."""
    scheme = req.scheme
    ip = req.get_host().split(':')[0]
    port = settings.PROXY_PORT
    return f'{scheme}://{ip}:{str(port)}'
