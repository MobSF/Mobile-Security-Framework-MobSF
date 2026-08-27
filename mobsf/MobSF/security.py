"""Runtime Executable Tampering Detection."""
import subprocess
import functools
import logging
import re
import socket
import ipaddress
import sys
from contextlib import contextmanager
from shutil import which
from pathlib import Path
from platform import system
import os
import stat
import string
import unicodedata
from urllib.parse import unquote, urljoin, urlparse, urlunsplit
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter

from mobsf.MobSF.utils import (
    find_aapt,
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
    downloaded_tools = Path(settings.DOWNLOADED_TOOLS_DIR)
    manage_py = base.parent / 'manage.py'
    exec_loc = [
        base / 'DynamicAnalyzer' / 'tools',
        base / 'StaticAnalyzer' / 'tools',
        downloaded_tools,
        manage_py,
    ]
    aapt = 'aapt'
    aapt2 = 'aapt2'
    if system() == 'Windows':
        aapt = 'aapt.exe'
        aapt2 = 'aapt2.exe'
    aapts = [find_aapt(aapt), find_aapt(aapt2)]
    exec_loc.extend(Path(a) for a in aapts if a)
    # External binaries used directly by MobSF
    system_bins = [
        'aapt',
        'aapt.exe',
        'aapt2',
        'aapt2.exe',
        'adb',
        'adb.exe',
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
        'idevice_id',
        'ideviceinfo',
        'idevicename',
        'pkill',
        'iproxy',
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
        getattr(settings, 'AAPT2_BINARY', ''),
        getattr(settings, 'AAPT_BINARY', ''),
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
    global EXECUTABLE_HASH_MAP
    try:
        hashes, signature = get_executable_hashes()
        hashes['signature'] = signature
        EXECUTABLE_HASH_MAP = hashes
    except Exception:
        logger.exception('Cannot calculate executable hashes, '
                         'disabling runtime executable '
                         'tampering detection')


def subprocess_hook(oldfunc, *args, **kwargs):
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


def sanitize_filename(filename):
    """Sanitize Filename."""
    # Remove any characters
    # that are not alphanumeric, hyphens, underscores, or dots
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    # Merge multiple underscores into one
    safe_filename = re.sub(r'__+', '_', safe_filename)
    # Remove leading and trailing underscores
    safe_filename = safe_filename.strip('_')
    return safe_filename


def sanitize_for_logging(filename: str, max_length: int = 255) -> str:
    """Sanitize a filename to prevent log injection."""
    # Remove newline, carriage return, and other risky characters
    filename = filename.replace('\n', '_').replace('\r', '_').replace('\t', '_')

    # Allow only safe characters (alphanumeric, underscore, dash, and period)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    # Truncate filename to the maximum allowed length
    return filename[:max_length]


# IPv4 ranges that must never be contacted by SSRF-sensitive fetches.
_DISALLOWED_IPV4_NETWORKS = (
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '10.0.0.0/8',
    '100.64.0.0/10',
)
_IPV6_TRANSLATION_NETWORKS = (
    ipaddress.IPv6Network('64:ff9b::/96'),
    ipaddress.IPv6Network('64:ff9b:1::/48'),
)
_INTERNAL_HOST_SUFFIXES = (
    '.home.arpa',
    '.internal',
    '.lan',
    '.local',
    '.localdomain',
    '.localhost',
)
MAX_PUBLIC_DNS_ADDRESSES = 8


def is_disallowed_ip(ip_str):
    """Return True if an IP must not be contacted (SSRF)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    # Unwrap IPv4-mapped IPv6 (::ffff:127.0.0.1) before classification.
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped
    elif isinstance(ip_obj, ipaddress.IPv6Address):
        # Reject transition addresses that can tunnel an otherwise-blocked
        # IPv4 destination through an apparently public IPv6 literal.
        if ip_obj.sixtofour and is_disallowed_ip(str(ip_obj.sixtofour)):
            return True
        if ip_obj.teredo and is_disallowed_ip(str(ip_obj.teredo[1])):
            return True
        for network in _IPV6_TRANSLATION_NETWORKS:
            if ip_obj in network:
                embedded = ipaddress.IPv4Address(ip_obj.packed[-4:])
                if is_disallowed_ip(str(embedded)):
                    return True

    if (not ip_obj.is_global
        or ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
            or ip_obj.is_unspecified):
        return True

    if isinstance(ip_obj, ipaddress.IPv4Address):
        for network in _DISALLOWED_IPV4_NETWORKS:
            if ip_obj in ipaddress.IPv4Network(network):
                return True
    return False


def resolve_public_ips(hostname, port=None):
    """Resolve hostname and return public addresses, or an empty tuple.

    The entire answer is rejected if any address is non-public. Callers must
    connect to one of the returned literals instead of resolving the hostname
    again, otherwise DNS rebinding remains possible.
    """
    try:
        normalized_host = hostname.rstrip('.').lower()
        try:
            ipaddress.ip_address(normalized_host)
        except ValueError:
            normalized_host = normalized_host.encode(
                'idna',
            ).decode('ascii')
            # Avoid even querying common local-only names. The resulting IP is
            # checked below as well, but that would still permit DNS probing.
            if ('.' not in normalized_host
                    or normalized_host == 'localhost'
                    or normalized_host.endswith(_INTERNAL_HOST_SUFFIXES)):
                return ()
        addresses = []
        addrinfos = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
        for addrinfo in addrinfos:
            address = addrinfo[4][0]
            if is_disallowed_ip(address):
                return ()
            if (address not in addresses
                    and len(addresses) < MAX_PUBLIC_DNS_ADDRESSES):
                addresses.append(address)
        return tuple(addresses)
    except (OSError, TypeError, UnicodeError):
        return ()


def _validated_host(host):
    """Parse a host-only value accepted by valid_host()."""
    if not isinstance(host, str) or not host or len(host) > 2083:
        return None
    if not host.startswith(('http://', 'https://')):
        host = f'http://{host}'
    try:
        parsed = urlparse(host)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme not in ('http', 'https')
        or not parsed.hostname
        or '@' in parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.params
        or parsed.fragment
            or (port and port not in (80, 443))):
        return None
    return parsed


def resolve_public_ip(host):
    """Resolve a host-only value and return one public address."""
    parsed = _validated_host(host)
    if not parsed:
        return None
    addresses = resolve_public_ips(parsed.hostname, parsed.port)
    return addresses[0] if addresses else None


def valid_host(host):
    """Check if host is valid, run SSRF checks."""
    return resolve_public_ip(host) is not None


class _PinnedTLSAdapter(HTTPAdapter):
    """Use the original hostname for TLS while the URL contains an IP."""

    def __init__(self, hostname, **kwargs):
        self.hostname = hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs['server_hostname'] = self.hostname
        pool_kwargs['assert_hostname'] = self.hostname
        super().init_poolmanager(
            connections,
            maxsize,
            block=block,
            **pool_kwargs,
        )


def _upstream_proxy_enabled(proxies):
    """Return True if an actual upstream proxy URL is configured."""
    return bool(proxies) and any(proxies.values())


def _validated_public_url(url, allowed_ports):
    """Parse an HTTP URL and resolve every hostname answer as public."""
    if not isinstance(url, str) or not url or len(url) > 2083:
        raise ValueError('Invalid URL')
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exp:
        raise ValueError('Invalid URL') from exp
    effective_port = port or (443 if parsed.scheme == 'https' else 80)
    if (parsed.scheme not in ('http', 'https')
        or not parsed.hostname
        or '@' in parsed.netloc
        or parsed.params
        or parsed.fragment
            or effective_port not in allowed_ports):
        raise ValueError('Unsafe URL')
    addresses = resolve_public_ips(parsed.hostname, effective_port)
    if not addresses:
        raise ValueError('URL did not resolve exclusively to public addresses')
    return parsed, addresses


def _pinned_url(parsed, address):
    """Replace URL hostname with a literal address, preserving path/query."""
    literal = f'[{address}]' if ':' in address else address
    if parsed.port:
        literal = f'{literal}:{parsed.port}'
    return urlunsplit((
        parsed.scheme,
        literal,
        parsed.path or '/',
        parsed.query,
        '',
    ))


def _open_pinned_request(method, url, allowed_ports, **kwargs):
    """Open one request to a validated literal IP with Host/SNI preserved."""
    proxies = kwargs.pop('proxies', None)
    if _upstream_proxy_enabled(proxies):
        hostname = sanitize_for_logging(
            str(urlparse(url).hostname or ''),
        )
        logger.warning(
            'Blocked SSRF-safe request for %s: upstream proxy performs DNS',
            hostname,
        )
        raise ValueError(
            'SSRF-safe requests cannot use an upstream DNS proxy')
    if kwargs.pop('allow_redirects', False):
        raise ValueError('Redirects must be validated by safe_stream_request')
    kwargs.pop('stream', None)

    parsed, addresses = _validated_public_url(url, allowed_ports)
    headers = dict(kwargs.pop('headers', {}) or {})
    # Always override a caller-supplied Host header.
    headers['Host'] = parsed.netloc
    last_error = None
    for address in addresses:
        session = requests.Session()
        # Ignore HTTP(S)_PROXY environment variables. A proxy would perform
        # its own DNS lookup and undo connection pinning.
        session.trust_env = False
        if parsed.scheme == 'https':
            session.mount('https://', _PinnedTLSAdapter(parsed.hostname))
        try:
            response = session.request(
                method,
                _pinned_url(parsed, address),
                headers=headers,
                allow_redirects=False,
                stream=True,
                **kwargs,
            )
            response.url = url
            return session, response
        except requests.RequestException as exp:
            last_error = exp
            session.close()
    if last_error:
        raise last_error
    raise requests.ConnectionError('No public address available')


@contextmanager
def safe_stream_request(method, url, *,
                        allowed_ports=(80, 443), max_redirects=0, **kwargs):
    """Yield a streaming response with DNS rebinding protections.

    Redirect targets are separately resolved, validated, and pinned. Proxy
    settings fail closed because the proxy—not MobSF—would resolve the host.
    """
    current_url = url
    redirects = 0
    while True:
        session, response = _open_pinned_request(
            method,
            current_url,
            allowed_ports,
            **kwargs,
        )
        location = response.headers.get('Location')
        if (response.status_code in (301, 302, 303, 307, 308)
                and location and redirects < max_redirects):
            response.close()
            session.close()
            current_url = urljoin(current_url, location)
            redirects += 1
            continue
        try:
            yield response
        finally:
            response.close()
            session.close()
        return


def safe_request(method, url, *,
                 allowed_ports=(80, 443), max_redirects=0,
                 max_response_size=1024 * 1024, **kwargs):
    """Return a bounded response from an SSRF-safe network request."""
    with safe_stream_request(
            method,
            url,
            allowed_ports=allowed_ports,
            max_redirects=max_redirects,
            **kwargs) as response:
        content = response.raw.read(max_response_size + 1, decode_content=True)
        if len(content) > max_response_size:
            raise ValueError('Remote response exceeds the allowed size')
        response._content = content
        response._content_consumed = True
        return response


def sanitize_svg(svg_content):
    """Sanitize SVG content to prevent XSS attacks."""
    logger.info('Sanitizing SVG contents')
    import bleach
    # Allow standard SVG tags and attributes, but remove scripts and event handlers
    safe_tags = [
        'svg', 'g', 'path', 'rect', 'circle', 'ellipse',
        'line', 'polyline', 'polygon', 'text', 'tspan',
        'defs', 'use', 'image', 'mask', 'clipPath',
        'filter', 'linearGradient', 'radialGradient', 'stop',
    ]
    safe_attrs = {
        '*': ['id', 'class', 'transform', 'fill', 'stroke', 'stroke-width', 'opacity'],
        'svg': ['width', 'height', 'viewBox', 'xmlns', 'version'],
        'path': ['d'],
        'rect': ['x', 'y', 'width', 'height', 'rx', 'ry'],
        'circle': ['cx', 'cy', 'r'],
        'ellipse': ['cx', 'cy', 'rx', 'ry'],
        'line': ['x1', 'y1', 'x2', 'y2'],
        'polyline': ['points'],
        'polygon': ['points'],
        'text': ['x', 'y', 'font-family', 'font-size'],
        'image': ['x', 'y', 'width', 'height', 'href'],
        'use': ['x', 'y', 'width', 'height', 'href'],
        'filter': ['x', 'y', 'width', 'height', 'href'],
        'linearGradient': ['x1', 'y1', 'x2', 'y2'],
        'radialGradient': ['cx', 'cy', 'r', 'fx', 'fy'],
        'stop': ['offset', 'stop-color', 'stop-opacity'],
    }
    return bleach.clean(
        svg_content,
        tags=safe_tags,
        attributes=safe_attrs,
        strip=True,
    )


def is_path_traversal(user_input):
    """Check for path traversal."""
    if not user_input:
        return False

    # Disallow absolute paths and windows paths and backslashes
    if os.path.isabs(user_input) or user_input.startswith(('\\', '//')):
        logger.error('Path traversal attack detected with absolute path')
        return True

    # Normalize and decode URL-encoded characters
    try:
        # Handle URL decoding (e.g., %2e -> .)
        decoded = unquote(user_input)
        # Handle double URL decoding (e.g., %252e -> %2e -> .)
        double_decoded = unquote(decoded)
    except Exception:
        logger.error('Path traversal attack detected with invalid URL encoding')
        return True

    # Check for path traversal in both original and decoded versions
    dangerous_patterns = ['..', '../', '..\\', '..\\\\']

    if any(pattern in user_input for pattern in dangerous_patterns):
        logger.error('Path traversal attack detected with invalid path')
        return True

    if any(pattern in decoded for pattern in dangerous_patterns):
        logger.error('Path traversal attack detected with invalid path')
        return True

    if any(pattern in double_decoded for pattern in dangerous_patterns):
        logger.error('Path traversal attack detected with invalid path')
        return True
    return False


def is_safe_path(safe_root, check_path, raw_file):
    """Detect Path Traversal."""
    if is_path_traversal(raw_file):
        return False
    safe_root = os.path.realpath(os.path.normpath(safe_root))
    check_path = os.path.realpath(os.path.normpath(check_path))
    return check_path.startswith(safe_root + os.sep) or check_path == safe_root


def clean_filename(filename, replace=' '):
    """Sanitize filename for Windows compatibility."""
    if system() == 'Windows':
        whitelist = f'-_.() {string.ascii_letters}{string.digits}'
        for r in replace:
            filename = filename.replace(r, '_')
        cleaned_filename = unicodedata.normalize(
            'NFKD', filename).encode('ASCII', 'ignore').decode()
        return ''.join(c for c in cleaned_filename if c in whitelist)
    return filename


def cmd_injection_check(data):
    """OS Cmd Injection check from Commix."""
    breakers = [
        ';', '%3B', '&', '%26', '&&',
        '%26%26', '|', '%7C', '||',
        '%7C%7C', '%0a', '%0d%0a',
    ]
    return any(i in data for i in breakers)


def is_pipe_or_link(path):
    """Check for named pipe or symlink."""
    return os.path.islink(path) or stat.S_ISFIFO(os.stat(path).st_mode)


def is_attack_pattern(user_input):
    """Check for shell injection attack patterns."""
    atk_pattern = re.compile(r';|\$\(|\|\||&&')
    result = re.findall(atk_pattern, user_input)
    if result:
        logger.error('Possible RCE attack detected')
    return result
