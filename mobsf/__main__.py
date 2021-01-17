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
    if platform.system() != 'Windows':
        sys.argv = [
            '',
            '-b',
            '127.0.0.1:8000',
            'mobsf.MobSF.wsgi:application',
            '--workers=1',
            '--threads=10',
            '--timeout=3600',
        ]
        from gunicorn.app.wsgiapp import run
        run()
