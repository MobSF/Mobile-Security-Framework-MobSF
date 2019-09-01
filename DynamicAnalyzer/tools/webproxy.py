import logging
import os
from pathlib import Path
import subprocess
import time

import requests

from MobSF.utils import upstream_proxy

logger = logging.getLogger(__name__)


def stop_httptools(port):
    """HTTPtools Kill."""
    # Invoke HTTPtools UI Kill Request
    try:
        requests.get('http://127.0.0.1:' + str(port) + '/kill', timeout=5)
        logger.info('Killing httptools UI')
    except Exception:
        pass

    # Inkoke HTTPtools Proxy Kill Request
    try:
        http_proxy = 'http://127.0.0.1:' + str(port)
        headers = {'httptools': 'kill'}
        url = 'http://127.0.0.1'
        requests.get(url, headers=headers, proxies={
                     'http': http_proxy})
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


def get_ca_dir():
    """Get CA Dir."""
    from mitmproxy import ctx
    ca_dir = Path(ctx.mitmproxy.options.CONF_DIR).expanduser()
    return os.path.join(str(ca_dir), 'mitmproxy-ca-cert.cer')
