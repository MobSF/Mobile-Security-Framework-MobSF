"""Common String Extraction Module."""
import logging
import shutil
import subprocess

from mobsf.StaticAnalyzer.tools.strings import (
    strings_util,
)


logger = logging.getLogger(__name__)


def get_os_strings(filename):
    try:
        strings_bin = shutil.which('strings')
        if not strings_bin:
            return None
        strings = subprocess.check_output([strings_bin, filename])
        return strings.decode('utf-8', 'ignore').splitlines()
    except Exception:
        return None


def strings_on_binary(bin_path):
    """Extract strings from binary."""
    try:
        strings = get_os_strings(bin_path)
        if strings:
            return list(set(strings))
        if isinstance(strings, list):
            return []
        # Only run if OS strings is not present
        return list(set(strings_util(bin_path)))
    except Exception:
        logger.exception('Extracting strings from binary')
