#!/usr/bin/env python3
"""Django Manage."""
import atexit
import logging
import os
import signal
import sys
import warnings

warnings.filterwarnings('ignore', category=UserWarning, module='cffi')
logger = logging.getLogger('mobsf.MobSF')


def _cleanup_android_on_exit():
    """Restore proxy, Frida, and adb forwards when runserver stops."""
    logger.info('Restoring connected Android device network state')
    try:
        from django.core.management import call_command
        call_command('cleanup_android')
    except Exception as exc:
        print(
            f'Android device cleanup failed: {exc}',
            file=sys.stderr,
        )


def _exit_for_cleanup(signum, _frame):
    sys.exit(128 + signum)


if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')
    # Development loop: Python reloads on save. Templates and static
    # files are read from disk, so HTML and JS edits show up on refresh.
    # Pass --noreload when a debugger must stay attached to one process.
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        os.environ['MOBSF_RUNSERVER'] = '1'
        # The reloader child exits on every Python save. Cleanup belongs
        # to the process that lives for the whole session.
        if os.environ.get('RUN_MAIN') != 'true':
            atexit.register(_cleanup_android_on_exit)
            for _sig in (signal.SIGTERM, signal.SIGHUP):
                signal.signal(_sig, _exit_for_cleanup)

    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
