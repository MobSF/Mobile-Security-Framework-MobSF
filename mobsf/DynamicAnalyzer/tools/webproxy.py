import logging
import os
from pathlib import Path
import subprocess
import time

import requests

from django.conf import settings

from mobsf.MobSF.utils import upstream_proxy

from .mitmproxy_integration import DEFAULT_CONTROLLER

logger = logging.getLogger(__name__)


def stop_httptools(url):
    """Kill httptools."""
    # Invoke HTTPtools UI Kill Request
    try:
        requests.get(f'{url}/kill', timeout=5)
        logger.info('Killing httptools UI')
    except Exception:
        pass

    # Invoke HTTPtools Proxy Kill Request
    try:
        http_proxy = url.replace('https://', 'http://')
        headers = {'httptools': 'kill'}
        url = 'http://127.0.0.1'
        requests.get(
            url,
            timeout=5,
            headers=headers,
            proxies={'http': http_proxy})
        logger.info('Killing httptools Proxy')
    except Exception:
        pass


def start_proxy(port, project):
    """Start HTTPtools in Proxy Mode."""
    argz = ['httptools',
            '-m', 'capture',
            '-p', str(port), '-n', project]
    proxies, _ = upstream_proxy('http')
    if proxies['http']:
        argz.extend(['-u', proxies['http']])
    fnull = open(os.devnull, 'w')
    subprocess.Popen(argz, stdout=fnull, stderr=subprocess.STDOUT)


def start_httptools_ui(port):
    """Start Server UI."""
    subprocess.Popen(['httptools',
                      '-m', 'server', '-p', str(port)])
    time.sleep(3)


def create_ca():
    """Generate CA on first run."""
    DEFAULT_CONTROLLER.generate_ca()


def get_ca_file():
    """Get CA Dir."""
    ca_file = DEFAULT_CONTROLLER.ensure_ca_certificate()
    if ca_file:
        return ca_file
    return ''


def get_traffic(package):
    web = Path.home() / '.httptools' / 'flows' / f'{package}.flow.txt'
    data = []
    if web.is_file():
        data.append(web.read_text('utf-8', 'ignore'))
    mitm_data = DEFAULT_CONTROLLER.get_project_traffic(package)
    if mitm_data:
        data.append(mitm_data)
    return '\n'.join(data)


def start_mitmproxy_capture(project, port=None):
    """Start mitmproxy capture for the supplied project."""
    return DEFAULT_CONTROLLER.start_capture(project, listen_port=port)


def stop_mitmproxy_capture():
    """Stop an active mitmproxy capture session."""
    DEFAULT_CONTROLLER.stop_capture()


def list_mitmproxy_captures():
    """Return a list of available mitmproxy capture files."""
    return list(DEFAULT_CONTROLLER.list_captures())


def get_http_tools_url(req):
    """Get httptools URL from request."""
    scheme = req.scheme
    ip = req.get_host().split(':')[0]
    port = settings.PROXY_PORT
    return f'{scheme}://{ip}:{str(port)}'
