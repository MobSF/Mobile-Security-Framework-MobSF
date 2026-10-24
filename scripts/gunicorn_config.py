"""Gunicorn lifecycle hooks for MobSF."""
import subprocess
import sys
from pathlib import Path


def on_exit(server):
    """Restore Android network state after a graceful shutdown."""
    project_dir = Path(__file__).resolve().parent.parent
    manage_py = project_dir / 'manage.py'
    server.log.info('Restoring connected Android device network state')
    try:
        result = subprocess.run(
            [
                sys.executable,
                manage_py.as_posix(),
                'cleanup_android',
            ],
            cwd=project_dir,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            server.log.error(
                'Android device cleanup exited with status %d',
                result.returncode,
            )
    except subprocess.TimeoutExpired:
        server.log.error('Android device cleanup timed out')
    except Exception:
        server.log.exception('Android device cleanup failed')
