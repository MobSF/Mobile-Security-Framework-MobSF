"""Initialize and serve the native desktop edition without legacy installers."""

import argparse
import os
import secrets
import shutil
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from urllib.request import ProxyHandler, build_opener


def configure():
    """Keep native runtime state separate from extracted source and Docker data."""
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    home = Path(os.environ['MOBSF_HOME_DIR'])
    if not home.is_absolute():
        raise RuntimeError('MOBSF_HOME_DIR must be absolute')
    home.mkdir(parents=True, exist_ok=True)
    secret = home / 'secret'
    # Pre-create the secret to bypass first_run's asynchronous tool downloader
    # and obsolete Windows RPC/installer/autostart setup. No migrations generated.
    if not secret.exists():
        with secret.open('x', encoding='utf-8') as output:
            os.chmod(secret, 0o600)
            output.write(secrets.token_urlsafe(50))
    os.environ['DJANGO_SETTINGS_MODULE'] = 'mobsf.MobSF.settings'
    os.environ['MOBSF_DISABLE_AUTHENTICATION'] = '0'
    os.environ['MOBSF_ASYNC_ANALYSIS'] = '0'
    import django

    django.setup()
    from django.conf import settings

    if settings.DISABLE_AUTHENTICATION == '1':
        raise RuntimeError('Desktop installation requires authentication')
    return home


def initialize():
    """Apply checked-in migrations and create only a missing initial account."""
    home = configure()
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from mobsf.MobSF.tools_download import install_jadx

    password = os.environ.get('MOBSF_ADMIN_PASSWORD', '')
    if len(password) < 32:
        raise RuntimeError(
            'A random initial password of at least 32 characters is required',
        )
    call_command('migrate', interactive=False)
    call_command('create_roles')
    users = get_user_model()
    if not users.objects.filter(username='mobsf').exists():
        users.objects.create_superuser('mobsf', '', password)
    install_jadx(str(home))
    if not (home / 'tools/jadx/jadx-1.5.0/bin/jadx.bat').is_file():
        raise RuntimeError(
            'JADX installation failed; retry install with Internet access',
        )
    print('Native data initialized; existing accounts and findings preserved.')


def doctor():
    """Check native dependency imports, application configuration and optional tools."""
    home = configure()
    from django.core.management import call_command
    import frida
    import lief
    import lxml.etree
    import psycopg2
    import waitress
    import xmlsec

    call_command('check')
    # Import compiled modules too: pip metadata alone cannot detect DLL failures.
    if not all((frida, lief, lxml.etree, psycopg2, waitress, xmlsec)):
        raise RuntimeError('Native dependency imports failed')
    print('Native Python modules imported successfully; data:', home)
    print(
        'PDF executable:',
        shutil.which('wkhtmltopdf') or 'missing (PDF export unavailable)',
    )
    print(
        'ADB executable:',
        shutil.which('adb')
        or 'not on PATH (configure an Android SDK for dynamic analysis)',
    )


def serve():
    """Run authenticated Waitress on loopback with verified browser readiness."""
    # A competing instance or unrelated service is never killed automatically.
    # Keep this listener reserved until Waitress takes ownership of its socket.
    listener = socket.socket()
    if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 8000))
    listener.listen(128)
    try:
        configure()
        from django.core.management import call_command
        from mobsf.MobSF.wsgi import application
        from waitress import create_server

        call_command('migrate', interactive=False)
        nonce = secrets.token_hex(32)

        def desktop_app(environ, start_response):
            if environ.get('PATH_INFO') == '/__mobsf_desktop_health__':
                start_response(
                    '200 OK',
                    [('Content-Type', 'text/plain'), ('Cache-Control', 'no-store')],
                )
                return [nonce.encode('ascii')]
            return application(environ, start_response)

        def ready():
            client = build_opener(ProxyHandler({}))
            base = 'http://127.0.0.1:8000'
            for _ in range(60):
                try:
                    with client.open(
                        base + '/__mobsf_desktop_health__', timeout=2,
                    ) as response:
                        owned = response.read(128).decode('ascii') == nonce
                    with client.open(base + '/login/', timeout=2) as response:
                        login = (
                            response.status == 200
                            and b'csrfmiddlewaretoken' in response.read(1 << 20)
                        )
                    if owned and login:
                        print(
                            'Native workspace ready. Press Ctrl+C here to stop;'
                            ' data is preserved.',
                            flush=True,
                        )
                        if os.getenv('MOBSF_DESKTOP_NO_BROWSER') != '1':
                            webbrowser.open('http://127.0.0.1:8000/bounty/')
                        return
                except (OSError, ValueError):
                    pass
                time.sleep(1)
            print(
                'Readiness failed; inspect the native server console.', file=sys.stderr,
            )

        server = create_server(
            desktop_app, sockets=[listener], threads=10, channel_timeout=3600,
        )
        threading.Thread(target=ready, daemon=True).start()
        try:
            server.run()
        finally:
            server.close()
    finally:
        listener.close()


def main():
    """Dispatch finite local maintenance commands."""
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('initialize', 'serve', 'doctor'))
    args = parser.parse_args()
    {'initialize': initialize, 'serve': serve, 'doctor': doctor}[args.action]()


if __name__ == '__main__':
    main()
