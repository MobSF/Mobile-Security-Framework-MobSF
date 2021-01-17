import os
import sys
import platform

from django.core.management import execute_from_command_line


def db():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')
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


def main():
    if len(sys.argv) == 2:
        listen = sys.argv[1]
    else:
        listen = '127.0.0.1:8000'
    if platform.system() != 'Windows':
        sys.argv = [
            '',
            '-b',
            listen,
            'mobsf.MobSF.wsgi:application',
            '--workers=1',
            '--threads=10',
            '--timeout=3600',
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
