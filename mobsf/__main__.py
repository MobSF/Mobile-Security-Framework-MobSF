import os
import sys
import platform

from django.core.management import execute_from_command_line
from django.db import connection


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')


def db():
    execute_from_command_line([
        '',
        'makemigrations',
    ])
    execute_from_command_line([
        '',
        'makemigrations',
        'StaticAnalyzer',
    ])
    execute_from_command_line([
        '',
        'migrate',
    ])
    execute_from_command_line([
        '',
        'create_roles',
    ])


def main():
    try:
        if not connection.introspection.table_names():
            db()
    except Exception:
        db()
    listen = '127.0.0.1:8000'
    if len(sys.argv) == 2 and sys.argv[1]:
        if sys.argv[1] == 'db':
            db()
            listen = None
        elif sys.argv[1]:
            listen = sys.argv[1]
    if not listen:
        exit(0)
    if platform.system() != 'Windows':
        sys.argv = [
            '',
            '-b',
            listen,
            'mobsf.MobSF.wsgi:application',
            '--workers=1',
            '--threads=10',
            '--timeout=3600',
            '--log-level=citical',
            '--log-file=-',
            '--access-logfile=-',
            '--error-logfile=-',
            '--capture-output',
        ]
        from gunicorn.app.wsgiapp import run
        run()
    else:
        from waitress import serve
        from .MobSF import wsgi
        serve(
            wsgi.application,
            listen=listen,
            threads=10,
            channel_timeout=3600)
