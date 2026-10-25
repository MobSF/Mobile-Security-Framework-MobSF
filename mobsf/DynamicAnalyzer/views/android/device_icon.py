"""Read one launcher icon from an installed APK without pulling it."""
import base64
import io
import json
import logging
import re
import struct
import threading
import time
import zipfile
import zlib
from hashlib import sha256
from pathlib import Path

from django.conf import settings

from mobsf.DynamicAnalyzer.views.android.device_vector import (
    gradient_fill,
    safe_svg_image,
    vector_image,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    _clean_package_display,
)
from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_android_path,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.tools.androguard4.apk import (
    APK,
    NS_ANDROID,
)
from mobsf.StaticAnalyzer.tools.androguard4.axml import AXMLPrinter

logger = logging.getLogger(__name__)

_ICON_FETCHES = threading.BoundedSemaphore(2)
_ICON_NOTICE_GUARD = threading.Lock()
_ICON_NOTICE = {}
_APK_PATH = re.compile(r'/data/app/[A-Za-z0-9_./=~+-]+\.apk')
_ZIP_NAME = re.compile(r'[A-Za-z0-9_./+$+-]{1,180}')
_IMAGE_TYPES = {
    'image/png': '.png',
    'image/webp': '.webp',
    'image/jpeg': '.jpg',
    'image/gif': '.gif',
    'image/svg+xml': '.svg',
}
_MAX_IMAGE = 1_500_000
_MAX_XML = 500_000
_MAX_MANIFEST = 2_000_000
_MAX_RESOURCES = 64 * 1024 * 1024
_COLOR = re.compile(r'#[0-9A-Fa-f]{3,8}')
_MAX_CENTRAL_DIRECTORY = 8 * 1024 * 1024


def device_package_icon(env, package):
    """Return icon bytes, content type, and the launcher label."""
    version, apk_hint = _inventory_identity(env, package)
    cached = _cached_device_icon(
        env.identifier, package, version, apk_hint)
    label = _cached_label(env.identifier, package, version, apk_hint)
    if cached and label:
        return (cached[0], cached[1], label)
    if cached is None:
        matched = _scan_icon(package, version, match_version=True)
        if matched:
            return (matched[0], matched[1], '')
    if not _ICON_FETCHES.acquire(timeout=45):
        fallback = cached or _scan_icon(
            package, version, match_version=False)
        if fallback:
            return (fallback[0], fallback[1], label)
        if label:
            return (None, None, label)
        return None
    try:
        _notice_icon_load(env.identifier)
        image, found = _icon_from_device(env, package)
    except Exception:
        logger.exception(
            'Launcher icon failed for %s',
            sanitize_for_logging(package),
        )
        image, found = None, ''
    finally:
        _ICON_FETCHES.release()
    if found:
        label = found
        _store_label(
            env.identifier, package, version, apk_hint, label)
    if image:
        _store_device_icon(
            env.identifier, package, version, apk_hint, image)
    chosen = image or cached or _scan_icon(
        package, version, match_version=False)
    if chosen:
        return (chosen[0], chosen[1], label)
    if label:
        return (None, None, label)
    return None


def _notice_icon_load(identifier):
    """Log once while a run of icon reads is in progress."""
    now = time.monotonic()
    with _ICON_NOTICE_GUARD:
        last = _ICON_NOTICE.get(identifier, 0)
        _ICON_NOTICE[identifier] = now
        if now - last < 20:
            return
    logger.info('Loading launcher icons')


def _inventory_identity(env, package):
    packages = env.get_device_packages(announce=False)
    details = packages.get(package) if isinstance(packages, dict) else None
    if not isinstance(details, (list, tuple)) or len(details) < 4:
        return '', ''
    version = details[3] if isinstance(details[3], str) else ''
    apk_path = details[1] if isinstance(details[1], str) else ''
    if not _safe_apk_path(apk_path):
        apk_path = ''
    return version[:100], apk_path


def _icon_from_device(env, package):
    paths = env.get_apk_paths(package)
    if not paths:
        return None, ''
    ordered = [_base_path(paths)]
    ordered.extend(
        apk_path for apk_path in paths
        if apk_path != ordered[0]
    )
    source = _IconSource(env, ordered[:6])
    remote = source.primary()
    if remote is None:
        return None, ''
    apk = _apk_from_remote(remote)
    if apk is None:
        return _fallback_icon(source, package), ''
    return _raster_icon(apk, source, package), _app_label(apk)


def _apk_from_remote(remote):
    """Build a minimal APK parser from one installed split."""
    manifest = remote.read_entry('AndroidManifest.xml', _MAX_MANIFEST)
    resources = remote.read_entry('resources.arsc', _MAX_RESOURCES)
    if not manifest or not resources:
        return None
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as bundle:
        bundle.writestr('AndroidManifest.xml', manifest)
        bundle.writestr('resources.arsc', resources)
    apk = APK(archive.getvalue(), raw=True)
    return apk if apk.valid_apk else None


def _base_path(paths):
    for apk_path in paths:
        if apk_path.name == 'base.apk':
            return apk_path
    return paths[0]


class _IconSource:
    """Read zip entries from the base APK, then from splits if needed."""

    def __init__(self, env, paths):
        self.env = env
        self.paths = paths
        self._opened = {}
        self._resource_apks = None

    def primary(self):
        for apk_path in self.paths:
            remote = self._open(apk_path)
            if (remote
                    and remote.has('AndroidManifest.xml')
                    and remote.has('resources.arsc')):
                return remote
        return None

    def read_entry(self, name, limit):
        if not _safe_zip_name(name):
            return None
        for apk_path in self.paths:
            remote = self._open(apk_path)
            if remote and remote.has(name):
                return remote.read_entry(name, limit)
        return None

    def resource_apks(self, primary_apk=None):
        """Return parsers for base and configuration resource tables."""
        if self._resource_apks is not None:
            return self._resource_apks
        parsed = []
        primary_remote = self.primary()
        for apk_path in self.paths:
            remote = self._open(apk_path)
            if (not remote
                    or not remote.has('AndroidManifest.xml')
                    or not remote.has('resources.arsc')):
                continue
            apk = (
                primary_apk
                if remote is primary_remote and primary_apk is not None
                else _apk_from_remote(remote)
            )
            if apk is not None:
                parsed.append(apk)
        self._resource_apks = tuple(parsed)
        return self._resource_apks

    def _open(self, apk_path):
        raw_path = apk_path.as_posix()
        if raw_path in self._opened:
            return self._opened[raw_path]
        remote = None
        if _safe_apk_path(raw_path):
            remote = _RemoteApk(self.env, raw_path)
            if not remote.load():
                remote = None
        self._opened[raw_path] = remote
        return remote


class _RemoteApk:
    """Read selected zip entries from an installed APK."""

    def __init__(self, env, apk_path):
        self.env = env
        self.apk_path = apk_path
        self.size = 0
        self.entries = {}

    def has(self, name):
        return name in self.entries

    def load(self):
        if not self._read_size():
            return False
        tail_len = min(self.size, 65557)
        tail = self._read_range(self.size - tail_len, tail_len)
        if not tail:
            return False
        eocd = _find_eocd(tail)
        if eocd is None:
            return False
        span = self._central_directory_span(tail, eocd)
        if not span:
            return False
        cd_off, cd_size = span
        if (cd_size <= 0
                or cd_size > _MAX_CENTRAL_DIRECTORY
                or cd_off < 0
                or cd_off + cd_size > self.size):
            return False
        blob = self._read_range(cd_off, cd_size)
        if not blob:
            return False
        self.entries = _parse_central_directory(blob)
        return bool(self.entries)

    def read_entry(self, name, limit):
        entry = self.entries.get(name)
        if not entry:
            return None
        method, comp_size, uncomp_size, local_off = entry
        if (comp_size <= 0
                or comp_size > limit
                or uncomp_size > limit
                or local_off < 0):
            return None
        header = self._read_range(local_off, 30)
        if not header or header[:4] != b'PK\x03\x04':
            return None
        name_len, extra_len = struct.unpack_from('<HH', header, 26)
        if name_len > 512 or extra_len > 8192:
            return None
        raw = self._read_range(
            local_off + 30 + name_len + extra_len,
            comp_size,
        )
        if not raw:
            return None
        if method == 0:
            return raw[:uncomp_size] if uncomp_size else raw
        return _inflate(raw, limit)

    def _read_size(self):
        raw = self.env.adb_exec_out(
            ['stat', '-c', '%s', self.apk_path],
            timeout=15,
        )
        if not raw:
            return False
        text = raw.strip()
        if not text.isdigit():
            return False
        size = int(text)
        if size < 22 or size > 8 * 1024 ** 3:
            return False
        self.size = size
        return True

    def _read_range(self, offset, size):
        if offset < 0 or size <= 0 or size > _MAX_RESOURCES:
            return None
        args = [
            'dd',
            f'if={self.apk_path}',
            'bs=1048576',
            f'skip={offset}',
            f'count={size}',
            'iflag=skip_bytes,count_bytes',
            'status=none',
        ]
        for _ in range(2):
            blob = self.env.adb_exec_out(args, timeout=45)
            if blob and len(blob) >= size:
                return blob[:size]
        return None

    def _central_directory_span(self, tail, eocd):
        cd_size, cd_off = struct.unpack_from('<II', tail, eocd + 12)
        if cd_size != 0xFFFFFFFF and cd_off != 0xFFFFFFFF:
            return cd_off, cd_size
        locator = eocd - 20
        if locator < 0 or tail[locator:locator + 4] != b'PK\x06\x07':
            return None
        z64_off = struct.unpack_from('<Q', tail, locator + 8)[0]
        record = self._read_range(z64_off, 56)
        if (not record
                or len(record) < 56
                or record[:4] != b'PK\x06\x06'):
            return None
        return (
            struct.unpack_from('<Q', record, 48)[0],
            struct.unpack_from('<Q', record, 40)[0],
        )


def _app_label(apk):
    """Resolve android:label from the manifest and resource table."""
    try:
        label = apk.get_app_name()
    except Exception:
        return ''
    return _clean_label(label)


def _clean_label(value):
    if not isinstance(value, str):
        return ''
    normalized = ' '.join(value.split())
    cleaned = _clean_package_display(normalized, 80)
    if cleaned.startswith('@') or cleaned.startswith('res/'):
        return ''
    return cleaned


def _raster_icon(apk, source, package):
    resolved = None
    try:
        resource_id = _icon_resource_id(apk)
        if resource_id:
            resolved = _raster_for_id(
                apk, source, resource_id, set())
            if resolved and resolved[1] != 'image/svg+xml':
                return resolved
    except Exception:
        logger.debug('Launcher icon resources could not be resolved')
    return _fallback_icon(source, package) or resolved


def _resolved_configs(apk, source, resource_id):
    """Resolve an id from the base table, then configuration splits."""
    candidates = []
    resources = apk.get_android_resources()
    if resources:
        try:
            candidates = resources.get_resolved_res_configs(resource_id)
        except Exception:
            candidates = []
    if candidates:
        return candidates
    for split_apk in source.resource_apks(apk):
        if split_apk is apk:
            continue
        resources = split_apk.get_android_resources()
        if not resources:
            continue
        try:
            candidates = resources.get_resolved_res_configs(resource_id)
        except Exception:
            continue
        if candidates:
            return candidates
    return []


def _raster_for_id(apk, source, resource_id, seen):
    if resource_id in seen or len(seen) > 8:
        return None
    seen.add(resource_id)
    candidates = _resolved_configs(apk, source, resource_id)
    images = []
    xml_names = []
    for config, name in candidates:
        if not _safe_zip_name(name):
            continue
        if name.endswith('.xml'):
            xml_names.append(name)
            continue
        density = config.get_density()
        if not isinstance(density, int) or density <= 0:
            density = 160
        images.append((abs(density - 240), name))
    images.sort()
    for _distance, name in images[:4]:
        data = source.read_entry(name, _MAX_IMAGE)
        image = _image(data)
        if image:
            return image
        if data and data.startswith(b'\x03\x00\x08\x00'):
            xml_names.append(name)
    for name in xml_names[:3]:
        xml_bytes = source.read_entry(name, _MAX_XML)
        if not xml_bytes:
            continue
        stacked = _adaptive_icon(apk, source, resource_id, xml_bytes, seen)
        if stacked:
            return stacked
        for ref in _xml_drawables(xml_bytes):
            child = _resource_id(apk, ref)
            if not child or child == resource_id:
                continue
            image = _raster_for_id(apk, source, child, seen)
            if image:
                return image
        image = vector_image(
            xml_bytes,
            _paint_resolver(apk, source, seen),
        )
        if image:
            return image
    return None


def _fallback_icon(source, package):
    """Use a conventional or package-branded bitmap from any split."""
    ranked = []
    package_tokens = [
        token.casefold()
        for token in package.split('.')
        if len(token) >= 4
        and token.casefold() not in {
            'android', 'mobile', 'application', 'apps',
        }
    ]
    package_tokens = set(package_tokens[-2:])
    for split_order, apk_path in enumerate(source.paths):
        remote = source._open(apk_path)
        if remote is None:
            continue
        for name in remote.entries:
            lower = name.lower()
            if not lower.endswith(
                    ('.png', '.webp', '.jpg', '.jpeg', '.gif')):
                continue
            if not _safe_zip_name(name):
                continue
            basename = Path(lower).stem
            launcher = 'ic_launcher' in basename
            branded = (
                any(token in basename for token in package_tokens)
                and ('logo' in basename or 'icon' in basename)
            )
            app_icon = any(
                token in basename
                for token in ('app_icon', 'appicon', 'application_icon')
            )
            if not (launcher or branded or app_icon):
                continue
            if 'xxhdpi' in lower:
                score = 0
            elif 'xhdpi' in lower:
                score = 1
            elif 'hdpi' in lower:
                score = 2
            else:
                score = 3
            if branded:
                score -= 20
            if app_icon:
                score -= 10
            if 'foreground' in lower:
                score += 4
            if 'background' in lower:
                score += 8
            ranked.append((score, split_order, name, remote))
    ranked.sort()
    for _score, _order, name, remote in ranked[:8]:
        image = _image(remote.read_entry(name, _MAX_IMAGE))
        if image:
            return image
    return None


def _icon_resource_id(apk):
    icon = None
    main_activity = apk.get_main_activity()
    if main_activity:
        icon = apk.get_attribute_value(
            'activity', 'icon', name=main_activity)
    if not icon:
        icon = apk.get_attribute_value('application', 'icon')
    if icon:
        return _resource_id(apk, icon)
    resources = apk.get_android_resources()
    if not resources:
        return None
    for kind in ('mipmap', 'drawable'):
        resource_id = resources.get_res_id_by_key(
            apk.package, kind, 'ic_launcher')
        if resource_id:
            return resource_id
    return None


def _resource_id(apk, value):
    if not isinstance(value, str) or not value.startswith('@'):
        return None
    token = value[1:]
    if token.startswith('android:'):
        return None
    if token.startswith('0x') or token.startswith('0X'):
        token = token[2:]
    if '/' in token:
        kind, _sep, key = token.partition('/')
        resources = apk.get_android_resources()
        if not resources or not kind or not key:
            return None
        return resources.get_res_id_by_key(apk.package, kind, key)
    if ':' in token:
        token = token.split(':')[-1]
    try:
        return int(token, 16)
    except ValueError:
        return None


def _adaptive_icon(apk, source, resource_id, xml_bytes, seen):
    """Stack an adaptive icon's background under its foreground."""
    refs = _adaptive_refs(xml_bytes)
    if not refs:
        return None
    layers = []
    for ref in refs:
        child = _resource_id(apk, ref)
        if not child or child == resource_id or child in seen:
            continue
        color = _direct_color(apk, source, child)
        if color:
            layers.append(('color', color))
            continue
        image = _raster_for_id(apk, source, child, seen)
        if image:
            layers.append(image)
    stacked = _composite_layers(layers)
    if stacked:
        return stacked
    for layer in reversed(layers):
        if layer and layer[0] != 'color':
            return layer
    return None


def _adaptive_refs(xml_bytes):
    try:
        root = AXMLPrinter(xml_bytes).get_xml_obj()
    except Exception:
        return None
    if (root is None
            or not isinstance(root.tag, str)
            or root.tag.split('}')[-1] != 'adaptive-icon'):
        return None
    refs = []
    for elem in root.iter():
        tag = elem.tag.split('}')[-1] if isinstance(elem.tag, str) else ''
        if tag not in ('background', 'foreground', 'bitmap'):
            continue
        for attr in ('drawable', 'src'):
            value = elem.get(NS_ANDROID + attr) or elem.get(attr)
            if isinstance(value, str) and value.startswith('@'):
                if value not in refs:
                    refs.append(value)
                break
    return refs


def _direct_color(apk, source, resource_id):
    for _config, value in _resolved_configs(apk, source, resource_id):
        if _direct_color_value(value):
            return value
    return None


def _paint_resolver(apk, source, seen):
    """Resolve a vector fill that points at a color or gradient."""
    followed = set()

    def resolve(value):
        resource_id = _resource_id(apk, value)
        if (not resource_id
                or resource_id in seen
                or resource_id in followed
                or len(followed) > 8):
            return None
        followed.add(resource_id)
        color = _direct_color(apk, source, resource_id)
        if color:
            return ('color', color)
        for _config, name in _resolved_configs(apk, source, resource_id):
            if (not isinstance(name, str)
                    or not name.endswith('.xml')
                    or not _safe_zip_name(name)):
                continue
            blob = source.read_entry(name, _MAX_XML)
            gradient = gradient_fill(blob) if blob else None
            if gradient:
                return ('gradient', gradient)
        return None

    return resolve


def _composite_layers(layers):
    """Send adaptive-icon layers for the browser to stack.

    Raster images and sanitized vectors are both painted by the browser.
    """
    if len(layers) < 2:
        return None
    described = []
    for layer in layers[:2]:
        if layer[0] == 'color':
            color = layer[1]
            if isinstance(color, str) and _direct_color_value(color):
                described.append({'color': color})
            continue
        image = _accepted_layer(layer[0], layer[1])
        if not image:
            continue
        described.append({
            'mime': image[1],
            'data': base64.b64encode(image[0]).decode('ascii'),
        })
    body = _layer_document(described)
    if not body:
        return None
    return body, 'application/json'


def _xml_drawables(xml_bytes):
    try:
        root = AXMLPrinter(xml_bytes).get_xml_obj()
    except Exception:
        return []
    if root is None:
        return []
    primary = []
    secondary = []
    for elem in root.iter():
        tag = elem.tag.split('}')[-1] if isinstance(elem.tag, str) else ''
        value = None
        for attr in ('drawable', 'foreground', 'src'):
            value = elem.get(NS_ANDROID + attr) or elem.get(attr)
            if value:
                break
        if not isinstance(value, str):
            continue
        if tag == 'foreground':
            primary.append(value)
        else:
            secondary.append(value)
    return primary + secondary


def _parse_central_directory(blob):
    entries = {}
    pos = 0
    while pos + 46 <= len(blob):
        if blob[pos:pos + 4] != b'PK\x01\x02':
            break
        flag = struct.unpack_from('<H', blob, pos + 8)[0]
        method = struct.unpack_from('<H', blob, pos + 10)[0]
        comp_size, uncomp_size = struct.unpack_from('<II', blob, pos + 20)
        name_len, extra_len, comment_len = struct.unpack_from(
            '<HHH', blob, pos + 28)
        local_off = struct.unpack_from('<I', blob, pos + 42)[0]
        nxt = pos + 46 + name_len + extra_len + comment_len
        if nxt > len(blob):
            break
        name_raw = blob[pos + 46:pos + 46 + name_len]
        extra = blob[pos + 46 + name_len:pos + 46 + name_len + extra_len]
        pos = nxt
        if flag & 1 or method not in (0, 8):
            continue
        try:
            name = name_raw.decode('utf-8')
        except UnicodeDecodeError:
            continue
        if not _safe_zip_name(name):
            continue
        uncomp_size, comp_size, local_off = _zip64_values(
            extra, uncomp_size, comp_size, local_off)
        entries[name] = (method, comp_size, uncomp_size, local_off)
    return entries


def _zip64_values(extra, uncomp_size, comp_size, local_off):
    need_uncomp = uncomp_size == 0xFFFFFFFF
    need_comp = comp_size == 0xFFFFFFFF
    need_off = local_off == 0xFFFFFFFF
    if not (need_uncomp or need_comp or need_off):
        return uncomp_size, comp_size, local_off
    pos = 0
    while pos + 4 <= len(extra):
        header_id, data_size = struct.unpack_from('<HH', extra, pos)
        pos += 4
        if pos + data_size > len(extra):
            break
        data = extra[pos:pos + data_size]
        pos += data_size
        if header_id != 0x0001:
            continue
        cursor = 0
        if need_uncomp and cursor + 8 <= len(data):
            uncomp_size = struct.unpack_from('<Q', data, cursor)[0]
            cursor += 8
        if need_comp and cursor + 8 <= len(data):
            comp_size = struct.unpack_from('<Q', data, cursor)[0]
            cursor += 8
        if need_off and cursor + 8 <= len(data):
            local_off = struct.unpack_from('<Q', data, cursor)[0]
        break
    return uncomp_size, comp_size, local_off


def _find_eocd(tail):
    search_end = len(tail)
    while True:
        found = tail.rfind(b'PK\x05\x06', 0, search_end)
        if found < 0 or found + 22 > len(tail):
            return None
        comment_len = struct.unpack_from('<H', tail, found + 20)[0]
        if found + 22 + comment_len == len(tail):
            return found
        search_end = found


def _inflate(raw, limit):
    try:
        decoder = zlib.decompressobj(-15)
        out = decoder.decompress(raw, limit + 1)
    except zlib.error:
        return None
    if decoder.unconsumed_tail or not decoder.eof or len(out) > limit:
        return None
    return out


def _accepted_layer(data, mime):
    """Return one checked raster or sanitized vector layer."""
    if mime == 'image/svg+xml':
        return safe_svg_image(data)
    image = _image(data)
    if not image or image[1] != mime:
        return None
    return image


def _image(data):
    if not data or len(data) > _MAX_IMAGE:
        return None
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return data, 'image/png'
    if data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        return data, 'image/webp'
    if data.startswith(b'\xff\xd8\xff'):
        return data, 'image/jpeg'
    if data.startswith((b'GIF87a', b'GIF89a')):
        return data, 'image/gif'
    return None


def _safe_apk_path(apk_path):
    return (
        isinstance(apk_path, str)
        and bool(_APK_PATH.fullmatch(apk_path))
        and is_safe_android_path(apk_path)
    )


def _safe_zip_name(name):
    return (
        isinstance(name, str)
        and bool(_ZIP_NAME.fullmatch(name))
        and '..' not in name
        and not name.startswith(('/', '\\'))
    )


def _cache_digest(identifier, package, version, apk_path):
    return sha256(
        f'v4\n{identifier}\n{package}\n{version}\n{apk_path}'.encode(),
    ).hexdigest()


def _icon_root():
    return Path(settings.MOBSF_HOME) / 'device_icons'


def _cached_device_icon(identifier, package, version, apk_path):
    digest = _cache_digest(identifier, package, version, apk_path)
    root = _icon_root()
    layered = _read_cached_layers(root, f'{digest}.json')
    if layered:
        return layered
    for suffix in _IMAGE_TYPES.values():
        image = _read_cached_image(
            root,
            f'{digest}{suffix}',
            allow_svg=suffix == '.svg',
        )
        if image:
            return image
    return None


def _store_device_icon(identifier, package, version, apk_path, image):
    data, content_type = image
    if content_type == 'application/json':
        data = _valid_layer_document(data)
        suffix = '.json'
    else:
        suffix = _IMAGE_TYPES.get(content_type)
    if not data or not suffix:
        return
    digest = _cache_digest(identifier, package, version, apk_path)
    root = _icon_root()
    relative = f'{digest}{suffix}'
    if is_path_traversal(relative):
        return
    try:
        root.mkdir(mode=0o750, parents=True, exist_ok=True)
    except OSError:
        return
    target = root / relative
    if not is_safe_path(root, target, relative):
        return
    if target.exists() and is_pipe_or_link(target):
        return
    partial = f'{digest}{suffix}.part'
    temporary = root / partial
    if (is_path_traversal(partial)
            or not is_safe_path(root, temporary, partial)
            or (temporary.exists() and is_pipe_or_link(temporary))):
        return
    try:
        temporary.write_bytes(data)
        temporary.replace(target)
    except OSError:
        return


def _cached_label(identifier, package, version, apk_path):
    digest = _cache_digest(identifier, package, version, apk_path)
    relative = f'{digest}.label'
    root = _icon_root()
    if is_path_traversal(relative):
        return ''
    candidate = root / relative
    if not is_safe_path(root, candidate, relative):
        return ''
    try:
        if (not candidate.is_file()
                or candidate.is_symlink()
                or is_pipe_or_link(candidate)
                or candidate.stat().st_size > 512):
            return ''
        text = candidate.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        return ''
    return _clean_label(text)


def _store_label(identifier, package, version, apk_path, label):
    cleaned = _clean_label(label)
    if not cleaned:
        return
    digest = _cache_digest(identifier, package, version, apk_path)
    relative = f'{digest}.label'
    root = _icon_root()
    if is_path_traversal(relative):
        return
    try:
        root.mkdir(mode=0o750, parents=True, exist_ok=True)
    except OSError:
        return
    target = root / relative
    if not is_safe_path(root, target, relative):
        return
    if target.exists() and is_pipe_or_link(target):
        return
    partial = f'{digest}.label.part'
    temporary = root / partial
    if (is_path_traversal(partial)
            or not is_safe_path(root, temporary, partial)
            or (temporary.exists() and is_pipe_or_link(temporary))):
        return
    try:
        temporary.write_text(cleaned, encoding='utf-8')
        temporary.replace(target)
    except OSError:
        return


def _scan_icon(package, version, match_version):
    root = Path(settings.DWD_DIR)
    rows = StaticAnalyzerAndroid.objects.filter(
        PACKAGE_NAME=package,
    ).values_list('VERSION_NAME', 'ICON_PATH')
    for scan_version, icon_path in rows:
        if match_version and (not version or scan_version != version):
            continue
        image = _read_cached_image(root, icon_path)
        if image:
            return image
    return None


def _read_cached_bytes(root, relative):
    if not isinstance(relative, str) or not relative:
        return None
    if is_path_traversal(relative) or Path(relative).is_absolute():
        return None
    candidate = root / relative
    if not is_safe_path(root, candidate, relative):
        return None
    try:
        if (not candidate.is_file()
                or candidate.is_symlink()
                or is_pipe_or_link(candidate)):
            return None
        if candidate.stat().st_size > _MAX_IMAGE:
            return None
        with candidate.open('rb') as handle:
            data = handle.read(_MAX_IMAGE + 1)
    except OSError:
        return None
    if len(data) > _MAX_IMAGE:
        return None
    return data


def _read_cached_image(root, relative, allow_svg=False):
    data = _read_cached_bytes(root, relative)
    if data is None:
        return None
    if allow_svg and data.lstrip().startswith(b'<svg'):
        return safe_svg_image(data)
    return _image(data)


def _read_cached_layers(root, relative):
    data = _read_cached_bytes(root, relative)
    if data is None:
        return None
    body = _valid_layer_document(data)
    if not body:
        return None
    return body, 'application/json'


def _direct_color_value(value):
    return (
        isinstance(value, str)
        and bool(_COLOR.fullmatch(value))
        and len(value) in (4, 5, 7, 9)
    )


def _layer_document(described):
    """Return canonical layer JSON, or None when the stack is incomplete."""
    if not isinstance(described, list) or not 1 < len(described) <= 2:
        return None
    pictures = 0
    for layer in described:
        if not isinstance(layer, dict):
            return None
        if set(layer) == {'color'}:
            if not _direct_color_value(layer['color']):
                return None
            continue
        if set(layer) != {'mime', 'data'}:
            return None
        encoded = layer['data']
        if not isinstance(encoded, str) or len(encoded) > _MAX_IMAGE:
            return None
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            return None
        image = _accepted_layer(raw, layer['mime'])
        if not image:
            return None
        layer['mime'] = image[1]
        layer['data'] = base64.b64encode(image[0]).decode('ascii')
        pictures += 1
    if pictures < 1:
        return None
    body = json.dumps(
        {'layers': described},
        separators=(',', ':'),
    ).encode('ascii')
    if len(body) > _MAX_IMAGE:
        return None
    return body


def _valid_layer_document(data):
    try:
        payload = json.loads(data)
    except ValueError:
        return None
    if not isinstance(payload, dict) or set(payload) != {'layers'}:
        return None
    return _layer_document(payload.get('layers'))
