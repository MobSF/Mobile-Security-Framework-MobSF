"""Strict TLS capture chain for Burp Suite Professional and Caido."""

import argparse
import ipaddress
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings


def capture_config():
    """Validate interception settings without contacting an application target."""
    provider = settings.CAPTURE_PROXY_PROVIDER
    if provider not in ('none', 'burp', 'caido', 'custom'):
        raise ValueError(
            'Invalid capture proxy provider: none, burp, caido or custom required',
        )
    if provider == 'none':
        return {'provider': provider, 'url': '', 'host': '', 'port': 0, 'ca_file': ''}
    url = settings.CAPTURE_PROXY_URL
    parsed = urlsplit(url)
    try:
        valid = (
            parsed.scheme == 'http'
            and parsed.hostname
            and parsed.port
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ('', '/')
            and not parsed.query
            and not parsed.fragment
            and not any(char.isspace() for char in url)
        )
        if not valid:
            raise ValueError
        host = parsed.hostname
        ipaddress.ip_address(host)
    except ValueError as exc:
        # Explicit IPs make the local/lab endpoint predictable and avoid DNS.
        raise ValueError(
            'Capture proxy must be http://<IP>:<port> without credentials or paths',
        ) from exc
    if ipaddress.ip_address(host).is_loopback and parsed.port == settings.PROXY_PORT:
        raise ValueError(
            'Capture proxy cannot point back to the MobSF capture listener',
        )
    ca_file = settings.CAPTURE_PROXY_CA_FILE
    if ca_file:
        ca = Path(ca_file)
        if not ca.is_absolute() or ca.is_symlink() or not ca.is_file():
            raise ValueError('Capture CA must be an absolute regular PEM file')
        # Reject malformed certificates now, rather than disable verification.
        ssl.create_default_context(cafile=str(ca))
    return {
        'provider': provider,
        'url': url.rstrip('/'),
        'host': host,
        'port': parsed.port,
        'ca_file': ca_file,
    }


def capture_arguments(port, project, config=None):
    """Preserve HTTPtools flow format while avoiding its insecure upstream flag."""
    from http_tools import settings as http_settings

    config = config or capture_config()
    if not 1 <= int(port) <= 65535:
        raise ValueError('Invalid capture listener port')
    if (
        not project
        or len(project) > 255
        or any(
            char
            not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-'
            for char in project
        )
        or project in ('.', '..')
    ):
        raise ValueError('Invalid capture project name')
    flows = Path(settings.MOBSF_HOME) / 'traffic'
    flows.mkdir(parents=True, exist_ok=True)
    addon = Path(http_settings.BASE_PATH) / 'modules/capture.py'
    args = [
        '--listen-host',
        settings.PROXY_IP,
        '--listen-port',
        str(port),
        '--scripts',
        str(addon),
        '--save-stream-file',
        str(flows / f'{project}.flow'),
        '--flow-detail',
        '0',
        '--set',
        'confdir=' + str(Path(settings.MOBSF_HOME) / 'mitmproxy'),
    ]
    if config['url']:
        args.extend(['--mode', 'upstream:' + config['url']])
        if config['ca_file']:
            args.extend(
                ['--set', 'ssl_verify_upstream_trusted_ca=' + config['ca_file']],
            )
    return args


def proxy_preflight():
    """Check only the configured proxy TCP listener; never send target requests."""
    result = capture_config()
    result['tls_verification'] = True
    if result['provider'] == 'none':
        result['ready'] = False
        result['error'] = 'Configure Burp or Caido capture settings first'
        return result
    try:
        with socket.create_connection((result['host'], result['port']), timeout=3):
            pass
        result['ready'] = True
        result['check'] = (
            'TCP listener only; HTTPS trust and intercept rules require a lab test'
        )
    except OSError:
        result['ready'] = False
        result['error'] = (
            'Proxy listener unreachable; start the configured Burp/Caido listener'
        )
    return result


def main():
    """Launch the packaged mitmproxy runner with validated arguments."""
    import os
    import django
    from mitmproxy.tools import cmdline, dump
    from mitmproxy.tools.main import run

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')
    django.setup()
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--project')
    parser.add_argument('--ui', action='store_true')
    args = parser.parse_args()
    if args.ui:
        from http_tools import settings as http_settings
        from http_tools.web.server import run_server

        http_settings.FLOWS_DIR = str(Path(settings.MOBSF_HOME) / 'traffic')
        Path(http_settings.FLOWS_DIR).mkdir(parents=True, exist_ok=True)
        run_server(settings.PROXY_IP, args.port)
        return
    if args.project is None:
        parser.error('--project is required for capture')
    run(
        dump.DumpMaster,
        cmdline.mitmdump,
        capture_arguments(args.port, args.project),
        {},
    )


if __name__ == '__main__':
    main()
