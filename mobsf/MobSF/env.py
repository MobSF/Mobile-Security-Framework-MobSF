"""Environment variable helpers.

Kept free of Django and MobSF imports so settings.py, the user
config.py and tools_download.py can all use it.
"""
import os

DISABLED = ('', '0', 'false', 'no', 'off')


def env_flag(name):
    """Read a boolean flag from the environment.

    Unset, empty, 0, false, no and off (case-insensitive,
    optionally quoted) are disabled. Anything else is enabled.
    """
    val = os.getenv(name, '').strip().strip('"\'').strip().lower()
    return val not in DISABLED
