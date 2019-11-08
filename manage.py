#!/usr/bin/env python3
"""Django Manage."""
import warnings
import os
import sys

warnings.filterwarnings('ignore', category=UserWarning, module='cffi')

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MobSF.settings')

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
