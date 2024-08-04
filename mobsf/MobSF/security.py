"""Runtime Executable Tampering Detection."""
import subprocess
import functools
import logging
import sys
from shutil import which
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor


from mobsf.MobSF.utils import (
    find_java_binary,
    gen_sha256_hash,
    get_adb,
    sha256,
)

from django.conf import settings


logger = logging.getLogger(__name__)
# Non executable files at host level
_SKIP = [
    '.pyc', '.js',
    '.json', '.txt', '.md']
EXECUTABLE_HASH_MAP = None


def get_sha256(filepath):
    """Calculate sha256 hash of a file."""
    return (filepath.as_posix(), sha256(filepath))


def get_all_files(dirlocs):
    """Get all files from a list of directories/files."""
    for dirloc in dirlocs:
        if dirloc.is_file() and dirloc.suffix not in _SKIP:
            yield dirloc
        elif dirloc.is_dir():
            # Use a generator expression for efficient filtering
            files_in_dir = (
                efile for efile in dirloc.rglob('*')
                if efile.is_file() and efile.suffix not in _SKIP
            )
            # Yield all files from the filtered generator
            yield from files_in_dir


def generate_hashes(dirlocs):
    """Generate master hash for all files."""
    exec_hashes = {}
    with ThreadPoolExecutor() as executor:
        futures = []
        for efile in get_all_files(dirlocs):
            futures.append(
                executor.submit(get_sha256, efile))
        for future in futures:
            sha = future.result()
            exec_hashes[sha[0]] = sha[1]
    return exec_hashes, gen_sha256_hash(str(exec_hashes))


def get_executable_hashes():
    # Internal Binaries shipped with MobSF
    base = Path(settings.BASE_DIR)
    manage_py = base.parent / 'manage.py'
    exec_loc = [
        base / 'DynamicAnalyzer' / 'tools',
        base / 'StaticAnalyzer' / 'tools',
        manage_py,
    ]
    # External binaries used directly by MobSF
    system_bins = [
        'adb',
        'which',
        'wkhtmltopdf',
        'httptools',
        'mitmdump',
        'unzip',
        'lipo',
        'ar',
        'nm',
        'objdump',
        'strings',
        'xcrun',
        'BinSkim.exe',
        'BinScope.exe',
        'nuget.exe',
        'where.exe',
        'wkhtmltopdf.exe',
    ]
    for sbin in system_bins:
        bin_path = which(sbin)
        if bin_path:
            exec_loc.append(Path(bin_path))
    # User defined path/binaries
    if settings.JAVA_DIRECTORY:
        exec_loc.append(Path(settings.JAVA_DIRECTORY))
    user_defined_bins = [
        sys.executable,
        settings.JADX_BINARY,
        settings.BACKSMALI_BINARY,
        settings.VD2SVG_BINARY,
        settings.APKTOOL_BINARY,
        settings.ADB_BINARY,
        settings.JTOOL_BINARY,
        settings.CLASSDUMP_BINARY,
        settings.CLASSDUMP_SWIFT_BINARY,
        getattr(settings, 'BUNDLE_TOOL', ''),
    ]
    for ubin in user_defined_bins:
        if ubin:
            exec_loc.append(Path(ubin))
    # Add ADB and Java binaries
    adb = get_adb()
    java = find_java_binary()
    if adb == 'adb':
        adb = which('adb')
    if java == 'java':
        java = which('java')
    if adb:
        exec_loc.append(Path(adb))
    if java:
        exec_loc.append(Path(java))
    return generate_hashes(exec_loc)


def store_exec_hashes_at_first_run():
    """Store executable hashes at first run."""
    try:
        global EXECUTABLE_HASH_MAP
        hashes, signature = get_executable_hashes()
        hashes['signature'] = signature
        EXECUTABLE_HASH_MAP = hashes
    except Exception:
        logger.exception('Cannot calculate executable hashes, '
                         'disabling runtime executable '
                         'tampering detection')


def subprocess_hook(oldfunc, *args, **kwargs):
    global EXECUTABLE_HASH_MAP
    if isinstance(args[0], str):
        # arg is a string
        agmtz = args[0].split()
        exec1 = agmtz[0]
    else:
        # list of args
        agmtz = args[0]
        exec1 = agmtz[0]  # executable
    exec2 = None  # secondary executable
    for arg in agmtz:
        if arg.endswith('.jar'):
            exec2 = Path(arg).as_posix()
            break
    if '/' in exec1 or '\\' in exec1:
        exec1 = Path(exec1).as_posix()
    else:
        exec1 = Path(which(exec1)).as_posix()
    executable_in_hash_map = False
    if exec1 in EXECUTABLE_HASH_MAP:
        executable_in_hash_map = True
        if EXECUTABLE_HASH_MAP[exec1] != sha256(exec1):
            msg = (
                f'Executable Tampering Detected. [{exec1}]'
                ' has been modified during runtime')
            logger.error(msg)
            raise Exception(msg)
    if exec2 and exec2 in EXECUTABLE_HASH_MAP:
        executable_in_hash_map = True
        if EXECUTABLE_HASH_MAP[exec2] != sha256(exec2):
            msg = (
                f'JAR Tampering Detected. [{exec2}]'
                ' has been modified during runtime')
            logger.error(msg)
            raise Exception(msg)
    if not executable_in_hash_map:
        logger.warning('Executable [%s] not found in known hashes, '
                       'skipping runtime executable '
                       'tampering detection', exec1)
        _, signature = get_executable_hashes()
        if EXECUTABLE_HASH_MAP['signature'] != signature:
            msg = 'Executable/Library Tampering Detected'
            logger.error(msg)
            raise Exception(msg)
    return oldfunc(*args, **kwargs)


def init_exec_hooks():
    subprocess.Popen = wrap_function(
        subprocess.Popen,
        subprocess_hook)


def wrap_function(oldfunction, newfunction):
    @functools.wraps(oldfunction)
    def run(*args, **kwargs):
        return newfunction(oldfunction, *args, **kwargs)
    return run


def sanitize_redirect(url):
    """Sanitize Redirect URL."""
    root = '/'
    if url.startswith('//'):
        return root
    elif url.startswith('/'):
        return url
    return root
