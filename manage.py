#!/usr/bin/env python3
"""Django Manage."""
import os
import sys
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='cffi')

if __name__ == '__main__':
    # Add the project root to the Python path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')

    from django.core.management import execute_from_command_line
    if 'runserver' in sys.argv:
        print('We do not allow debug server anymore. '
              'Please follow official docs: '
              'https://mobsf.github.io/docs/')
        sys.exit(0)
    execute_from_command_line(sys.argv)
