"""Centralized security helpers.

Path traversal and filesystem checks, input validation, output
sanitization, SSRF-safe outbound requests, and runtime executable
tampering detection.
"""
import functools
import ipaddress
import logging
import ntpath
import os
import posixpath
import re
import shlex
import socket
import stat
import string
import subprocess
import sys
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from platform import system
from shutil import which
from urllib.parse import unquote, urljoin, urlparse, urlunsplit

import requests
from requests.adapters import HTTPAdapter

from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme

from mobsf.MobSF.utils import (
    find_aapt,
    find_java_binary,
    gen_sha256_hash,
    get_adb,
    sha256,
)

logger = logging.getLogger(__name__)
# Non executable files at host level
_SKIP = [
    '.pyc', '.js',
    '.json', '.txt', '.md']
EXECUTABLE_HASH_MAP = None
IS_WINDOWS = os.name == 'nt'
_CONTROL_CHARS_RE = re.compile(r'[\x00-\x1f\x7f]')


def _hash_key(path):
    """Return a canonical, case-normalized key for the executable hash map."""
    return Path(os.path.normcase(os.path.realpath(path))).as_posix()


def get_sha256(filepath):
    """Calculate sha256 hash of a file."""
    return (_hash_key(filepath), sha256(filepath))


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
        'mitmdump',
        'unzip',
        'lipo',
        'ar',
        'nm',
        'objdump',
        'sips',
        'strings',
        'xcrun',
        'BinSkim.exe',
        'BinScope.exe',
        'nuget.exe',
        'where.exe',
        'idevice_id',
        'ideviceinfo',
        'idevicename',
        'pkill',
        'iproxy',
        'keytool',
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


def _to_str(arg):
    """Convert a subprocess argument to str."""
    if isinstance(arg, (str, bytes, os.PathLike)):
        return os.fsdecode(arg)
    return str(arg)


def _split_command(args, kwargs):
    """Return the Popen command as a list of str arguments."""
    cmd = args[0] if args else kwargs.get('args')
    if cmd is None:
        return []
    if isinstance(cmd, os.PathLike):
        return [os.fspath(cmd)]
    if isinstance(cmd, (str, bytes)):
        cmd = os.fsdecode(cmd)
        try:
            parts = shlex.split(cmd, posix=not IS_WINDOWS)
        except ValueError:
            parts = cmd.split()
        if IS_WINDOWS:
            parts = [p.strip('"') for p in parts]
        return parts
    return [_to_str(a) for a in cmd]


def _resolve_executable(exec1):
    """Return the filesystem path of the executable, or None."""
    if '/' in exec1 or '\\' in exec1:
        return exec1
    return which(exec1)


def subprocess_hook(oldfunc, *args, **kwargs):
    agmtz = _split_command(args, kwargs)
    executable = kwargs.get('executable')
    exec1 = _to_str(executable) if executable else (
        agmtz[0] if agmtz else None)
    exec1_path = _resolve_executable(exec1) if exec1 else None
    if not exec1_path:
        # Let Popen raise its usual FileNotFoundError.
        return oldfunc(*args, **kwargs)
    if (IS_WINDOWS
            and exec1_path.lower().endswith(('.bat', '.cmd'))
            and not all(is_safe_windows_batch_arg(a) for a in agmtz[1:])):
        msg = f'Unsafe argument passed to Windows batch file [{exec1_path}]'
        logger.error(msg)
        raise ValueError(msg)
    if EXECUTABLE_HASH_MAP is None:
        return oldfunc(*args, **kwargs)
    exec1 = _hash_key(exec1_path)
    exec2 = None  # secondary executable
    for arg in agmtz:
        if arg.lower().endswith('.jar'):
            exec2 = _hash_key(arg)
            break
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
    """Allow only same-site relative redirect paths."""
    root = '/'
    if not isinstance(url, str) or not url:
        return root
    # Browsers drop tab/CR/LF inside URLs and treat backslash as slash,
    # so '/\t/evil.com' and '/\\evil.com' become '//evil.com'.
    if _CONTROL_CHARS_RE.search(url):
        return root
    if (not url.startswith('/')
            or url.startswith(('//', '/\\'))
            or not url_has_allowed_host_and_scheme(url, allowed_hosts=None)):
        return root
    return url


def sanitize_filename(filename):
    """Sanitize Filename."""
    # Remove any characters
    # that are not alphanumeric, hyphens, underscores, or dots
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', str(filename))
    # Merge multiple underscores into one
    safe_filename = re.sub(r'__+', '_', safe_filename)
    # No leading/trailing dots or underscores: avoids '.', '..',
    # hidden files and names Windows silently rewrites.
    safe_filename = safe_filename.strip('._')
    return safe_filename or 'file'


def sanitize_for_logging(filename: str, max_length: int = 255) -> str:
    """Sanitize a value to prevent log injection."""
    # Allow only safe characters (alphanumeric, underscore, dash, and period)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '_', str(filename))

    # Truncate filename to the maximum allowed length
    return filename[:max_length]


# IPv4 ranges that must never be contacted by SSRF-sensitive fetches.
_DISALLOWED_IPV4_NETWORKS = tuple(ipaddress.IPv4Network(n) for n in (
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '10.0.0.0/8',
    '100.64.0.0/10',  # NOSONAR - RFC 6598 shared address space denylist
))
# Python classifies these as global, but they are cloud-internal endpoints.
_DISALLOWED_IP_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in (
    '168.63.129.16',  # NOSONAR - Azure WireServer / platform DNS denylist
))
DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_TOTAL_TIMEOUT = 30
_SENSITIVE_HEADERS = ('authorization', 'cookie', 'proxy-authorization')
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

    if ip_obj in _DISALLOWED_IP_ADDRESSES:
        return True
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if any(ip_obj in network for network in _DISALLOWED_IPV4_NETWORKS):
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
            or (port is not None and port not in (80, 443))):
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


class _RequestDeadline:
    """Shut down a request's sockets once its total time limit passes.

    Socket timeouts apply per operation, so a peer sending one byte at a
    time could otherwise hold the TLS handshake, headers or body open
    indefinitely and keep the calling thread blocked.
    """

    def __init__(self, seconds):
        self.expired = False
        self._lock = threading.Lock()
        # Duplicates, so shutdown still reaches the connection after TLS
        # wrapping detaches the original socket object, and so a closed
        # and reused descriptor is never touched.
        self._sockets = []
        self._timer = threading.Timer(max(0, seconds), self._expire)
        self._timer.daemon = True
        self._timer.start()

    def register(self, sock):
        dup = sock.dup()
        with self._lock:
            if not self.expired:
                self._sockets.append(dup)
                return
        self._shutdown(dup)

    def _expire(self):
        with self._lock:
            self.expired = True
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            self._shutdown(sock)

    def cancel(self):
        self._timer.cancel()
        with self._lock:
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            sock.close()

    @staticmethod
    def _shutdown(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


def _deadline_pool(pool_cls, deadline):
    """Return a pool class whose connections register with the deadline."""
    class Connection(pool_cls.ConnectionCls):
        def _new_conn(self):
            sock = super()._new_conn()
            deadline.register(sock)
            return sock

    return type(pool_cls.__name__, (pool_cls,), {'ConnectionCls': Connection})


class _PinnedAdapter(HTTPAdapter):
    """Use the original hostname for TLS while the URL contains an IP."""

    def __init__(self, hostname, deadline=None, **kwargs):
        self.hostname = hostname
        self.deadline = deadline
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
        if self.deadline:
            self.poolmanager.pool_classes_by_scheme = {
                scheme: _deadline_pool(pool_cls, self.deadline)
                for scheme, pool_cls in
                self.poolmanager.pool_classes_by_scheme.items()}


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


def _open_pinned_request(method, url, allowed_ports, deadline=None,
                         **kwargs):
    """Open one request to a validated literal IP with Host/SNI preserved."""
    proxies = kwargs.pop('proxies', None)
    if _upstream_proxy_enabled(proxies):
        logger.warning('Blocked SSRF-safe request: upstream proxy performs DNS')
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
        if deadline and deadline.expired:
            raise TimeoutError('Remote request exceeded the time limit')
        session = requests.Session()
        # Ignore HTTP(S)_PROXY environment variables. A proxy would perform
        # its own DNS lookup and undo connection pinning.
        session.trust_env = False
        session.mount(f'{parsed.scheme}://',
                      _PinnedAdapter(parsed.hostname, deadline))
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
            session.close()
            if deadline and deadline.expired:
                raise TimeoutError(
                    'Remote request exceeded the time limit') from exp
            last_error = exp
    if last_error:
        raise last_error
    raise requests.ConnectionError('No public address available')


@contextmanager
def safe_stream_request(method, url, *,
                        allowed_ports=(80, 443), max_redirects=0,
                        max_total_time=None, **kwargs):
    """Yield a streaming response with DNS rebinding protections.

    Redirect targets are separately resolved, validated, and pinned. Proxy
    settings fail closed because the proxy—not MobSF—would resolve the host.
    With max_total_time, the connection is shut down once that many seconds
    have passed, and TimeoutError is raised.
    """
    kwargs.setdefault('timeout', DEFAULT_REQUEST_TIMEOUT)
    deadline = _RequestDeadline(max_total_time) if max_total_time else None
    current_url = url
    redirects = 0
    try:
        while True:
            session, response = _open_pinned_request(
                method,
                current_url,
                allowed_ports,
                deadline=deadline,
                **kwargs,
            )
            location = response.headers.get('Location')
            if (response.status_code in (301, 302, 303, 307, 308)
                    and location and redirects < max_redirects):
                response.close()
                session.close()
                next_url = urljoin(current_url, location)
                current, nxt = urlparse(current_url), urlparse(next_url)
                if current.scheme == 'https' and nxt.scheme != 'https':
                    raise ValueError(
                        'Redirect from HTTPS to HTTP is not allowed')
                if ((current.scheme, current.netloc)
                        != (nxt.scheme, nxt.netloc)):
                    kwargs['headers'] = {
                        k: v for k, v in (kwargs.get('headers') or {}).items()
                        if k.lower() not in _SENSITIVE_HEADERS}
                if response.status_code == 303 and method.upper() != 'HEAD':
                    method = 'GET'
                    kwargs.pop('data', None)
                    kwargs.pop('json', None)
                current_url = next_url
                redirects += 1
                continue
            try:
                yield response
            except Exception as exp:
                if deadline and deadline.expired:
                    raise TimeoutError(
                        'Remote response exceeded the time limit') from exp
                raise
            finally:
                response.close()
                session.close()
            # A body without Content-Length just ends early on shutdown.
            if deadline and deadline.expired:
                raise TimeoutError('Remote response exceeded the time limit')
            return
    finally:
        if deadline:
            deadline.cancel()


def safe_request(method, url, *,
                 allowed_ports=(80, 443), max_redirects=0,
                 max_response_size=1024 * 1024,
                 max_total_time=DEFAULT_TOTAL_TIMEOUT, **kwargs):
    """Return a bounded response from an SSRF-safe network request.

    The timeout kwarg applies per socket operation. max_total_time caps the
    wall-clock time of the whole request, including headers and body.
    """
    with safe_stream_request(
            method,
            url,
            allowed_ports=allowed_ports,
            max_redirects=max_redirects,
            max_total_time=max_total_time,
            **kwargs) as response:
        content = bytearray()
        for chunk in response.raw.stream(65536, decode_content=True):
            content += chunk
            if len(content) > max_response_size:
                raise ValueError('Remote response exceeds the allowed size')
        response._content = bytes(content)
        response._content_consumed = True
        return response


_SVG_SAFE_TAGS = {
    'svg', 'g', 'path', 'rect', 'circle', 'ellipse',
    'line', 'polyline', 'polygon', 'text', 'tspan',
    'defs', 'use', 'image', 'mask', 'clipPath',
    'filter', 'linearGradient', 'radialGradient', 'stop',
}
_SVG_SAFE_ATTRS = {
    '*': {
        'id', 'class', 'transform', 'fill', 'stroke',
        'stroke-width', 'opacity',
    },
    'svg': {'width', 'height', 'viewBox', 'xmlns', 'version'},
    'path': {'d'},
    'rect': {'x', 'y', 'width', 'height', 'rx', 'ry'},
    'circle': {'cx', 'cy', 'r'},
    'ellipse': {'cx', 'cy', 'rx', 'ry'},
    'line': {'x1', 'y1', 'x2', 'y2'},
    'polyline': {'points'},
    'polygon': {'points'},
    'text': {'x', 'y', 'font-family', 'font-size'},
    'image': {'x', 'y', 'width', 'height', 'href'},
    'use': {'x', 'y', 'width', 'height', 'href'},
    'filter': {'x', 'y', 'width', 'height', 'href'},
    'linearGradient': {'gradientUnits', 'x1', 'y1', 'x2', 'y2'},
    'radialGradient': {'cx', 'cy', 'r', 'fx', 'fy'},
    'stop': {'offset', 'stop-color', 'stop-opacity'},
}


def _local_xml_name(name):
    """Strip XML namespace URI prefix from tag or attribute name."""
    if name.startswith('{') and '}' in name:
        return name.split('}', 1)[1]
    return name


def _is_unsafe_svg_attr_value(attr_val):
    """Return True if an SVG attribute value contains script URI vectors."""
    val_norm = re.sub(r'[\x00-\x20]+', '', attr_val).lower()
    return (
        val_norm.startswith(('javascript:', 'vbscript:', 'data:'))
        or 'javascript:' in val_norm
        or 'expression(' in val_norm
    )


def _clean_svg_element(elem):
    """Recursively strip disallowed SVG tags and attributes in place."""
    tag = _local_xml_name(elem.tag)
    allowed = _SVG_SAFE_ATTRS['*'] | _SVG_SAFE_ATTRS.get(tag, set())
    cleaned_attrib = {}
    for attr_key, attr_val in elem.attrib.items():
        attr_name = _local_xml_name(attr_key)
        if attr_name in allowed and not _is_unsafe_svg_attr_value(attr_val):
            cleaned_attrib[attr_name] = attr_val
    elem.tag = tag
    elem.attrib = cleaned_attrib
    remove_children = [
        child for child in elem
        if _local_xml_name(child.tag) not in _SVG_SAFE_TAGS
    ]
    for child in remove_children:
        elem.remove(child)
    for child in elem:
        _clean_svg_element(child)


def sanitize_svg(svg_content):
    """Sanitize SVG content to prevent XSS attacks."""
    from xml.etree import ElementTree as StdET
    import defusedxml.ElementTree as DefusedET
    try:
        StdET.register_namespace('', 'http://www.w3.org/2000/svg')
        root = DefusedET.fromstring(svg_content)
    except Exception:
        return ''
    if _local_xml_name(root.tag) != 'svg':
        return ''
    _clean_svg_element(root)
    root.attrib.setdefault('xmlns', 'http://www.w3.org/2000/svg')
    return StdET.tostring(root, encoding='unicode')


def is_path_traversal(user_input):
    """Check for path traversal with POSIX and Windows path semantics."""
    if not user_input:
        return False

    try:
        path = os.fspath(user_input)
        if isinstance(path, bytes):
            path = path.decode('utf-8')
        if not isinstance(path, str):
            raise TypeError
    except (TypeError, UnicodeError):
        logger.error('Path traversal attack detected with invalid path')
        return True

    paths = []
    try:
        # NFKC folds fullwidth forms (U+FF0E, U+FF0F, U+FF3C) to ASCII,
        # matching what Windows best-fit conversion does in ANSI APIs.
        for base in (path, unicodedata.normalize('NFKC', path)):
            decoded = [base]
            # Single and double URL decoding (%252e -> %2e -> .).
            for _ in range(2):
                decoded.append(unquote(decoded[-1]))
            for candidate in decoded:
                paths.append(candidate)
                paths.append(unicodedata.normalize('NFKC', candidate))
    except Exception:
        logger.error('Path traversal attack detected with invalid URL encoding')
        return True

    for candidate in dict.fromkeys(paths):
        drive, _ = ntpath.splitdrive(candidate)
        if ('\x00' in candidate
                or candidate.startswith(('/', '\\'))
                or posixpath.isabs(candidate)
                or ntpath.isabs(candidate)
                or drive):
            logger.error('Path traversal attack detected with absolute path')
            return True
        if '..' in candidate:
            logger.error('Path traversal attack detected with invalid path')
            return True
        if IS_WINDOWS and _is_unsafe_windows_path(candidate):
            logger.error('Path traversal attack detected with unsafe '
                         'Windows path')
            return True
    return False


_WINDOWS_RESERVED_NAMES = frozenset(
    ['CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$']
    + [f'COM{i}' for i in '123456789\u00b9\u00b2\u00b3']
    + [f'LPT{i}' for i in '123456789\u00b9\u00b2\u00b3'])


def _is_windows_reserved_name(name):
    """Check if a path component is a Windows reserved device name."""
    stem = name.split('.', 1)[0].rstrip(' ').upper()
    return stem in _WINDOWS_RESERVED_NAMES


def _is_unsafe_windows_path(path):
    """Detect NTFS streams, device names and names Windows rewrites."""
    # Drive letters are rejected before this, so any colon is an ADS.
    if ':' in path:
        return True
    for component in re.split(r'[\\/]', path):
        if not component or component == '.':
            continue
        # Windows strips trailing dots and spaces ('a.txt.' -> 'a.txt').
        if component[-1] in '. ':
            return True
        if _is_windows_reserved_name(component):
            return True
    return False


def is_safe_path(safe_root, check_path, raw_file):
    """Detect Path Traversal."""
    if is_path_traversal(raw_file):
        return False
    try:
        safe_root = os.path.normcase(
            os.path.realpath(os.path.normpath(safe_root)))
        check_path = os.path.normcase(
            os.path.realpath(os.path.normpath(check_path)))
        return os.path.commonpath((safe_root, check_path)) == safe_root
    except (TypeError, ValueError):
        return False


def is_safe_android_path(check_path, safe_root='/data/app'):
    """Validate an absolute path reported by an Android device."""
    if not isinstance(check_path, str) or not isinstance(safe_root, str):
        return False
    safe_root = posixpath.normpath(safe_root)
    if (not posixpath.isabs(check_path)
            or not check_path.startswith(f'{safe_root}/')):
        return False
    relative = check_path[len(safe_root) + 1:]
    if is_path_traversal(relative):
        return False
    normalized = posixpath.normpath(check_path)
    try:
        return posixpath.commonpath(
            (safe_root, normalized)) == safe_root
    except ValueError:
        return False


def clean_filename(filename, replace=' '):
    """Sanitize filename for Windows compatibility."""
    if system() == 'Windows':
        whitelist = f'-_.() {string.ascii_letters}{string.digits}'
        for r in replace:
            filename = filename.replace(r, '_')
        cleaned_filename = unicodedata.normalize(
            'NFKD', filename).encode('ASCII', 'ignore').decode()
        cleaned = ''.join(c for c in cleaned_filename if c in whitelist)
        # Windows strips trailing dots/spaces and maps device names
        # such as CON or NUL.txt to devices instead of files.
        cleaned = cleaned.rstrip('. ')
        if _is_windows_reserved_name(cleaned):
            cleaned = f'_{cleaned}'
        return cleaned or '_'
    return filename


# Shell metacharacters, raw and URL-encoded.
_CMD_INJECTION_RE = re.compile(
    r';|&|\||`|\$\(|>|<|\n|\r'
    r'|%3b|%26|%7c|%60|%24%28|%3e|%3c|%0a|%0d',
    re.IGNORECASE)
_ATTACK_PATTERN_RE = re.compile(r';|\$\(|\||&&|`|\n|\r')
# Characters cmd.exe re-parses when Python launches a .bat/.cmd file,
# even with list arguments (BatBadBut).
_UNSAFE_BATCH_CHARS = frozenset('&|%^"<>!\r\n')


def cmd_injection_check(data):
    """OS Cmd Injection check from Commix."""
    return bool(_CMD_INJECTION_RE.search(str(data)))


def is_safe_windows_batch_arg(arg):
    """Check if an argument is safe to pass to a Windows batch file."""
    return not any(c in _UNSAFE_BATCH_CHARS for c in _to_str(arg))


def is_pipe_or_link(path):
    """Check for symlinks, junctions, pipes, sockets and device files."""
    try:
        mode = os.lstat(path).st_mode
        if os.path.isjunction(path):
            return True
    except FileNotFoundError:
        return False
    except (OSError, TypeError, ValueError):
        return True
    return (stat.S_ISLNK(mode)
            or stat.S_ISFIFO(mode)
            or stat.S_ISSOCK(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISBLK(mode))


def is_attack_pattern(user_input):
    """Check for shell injection attack patterns."""
    result = bool(_ATTACK_PATTERN_RE.search(str(user_input)))
    if result:
        logger.error('Possible RCE attack detected')
    return result
