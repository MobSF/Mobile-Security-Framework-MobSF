#!/usr/bin/env python3
"""Django Manage."""
import warnings
import os
import sys

warnings.filterwarnings('ignore', category=UserWarning, module='cffi')

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')
    # Development loop: Python reloads on save. Templates and static
    # files are read from disk, so HTML and JS edits show up on refresh.
    # Pass --noreload when a debugger must stay attached to one process.
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        os.environ['MOBSF_RUNSERVER'] = '1'

    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
