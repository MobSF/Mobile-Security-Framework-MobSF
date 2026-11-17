# -*- coding: utf_8 -*-
"""Frida API Monitor event parsing and formatting.

Events originate inside the analyzed app's process and are untrusted.
Every field is type-checked and length-bounded before it is stored as a
single JSON line, and readers parse the log line by line so a malformed
entry cannot hide the rest of the capture.
"""
import base64
import json
import logging
import re
from pathlib import Path

from mobsf.MobSF.security import is_pipe_or_link

logger = logging.getLogger(__name__)

API_MONITOR_PREFIX = 'MobSF-API-Monitor: '
FORMAT_VERSION = 2
MAX_TEXT = 2048
MAX_FIELD = 512
MAX_ITEMS = 32
MAX_STACK = 12
MAX_BYTES = 1024
MAX_DEPTH = 3
MAX_BATCH = 200
MAX_COUNT = 1_000_000
PRINTABLE_RATIO = 0.95
BASE64_CLASSES = (
    'android.util.Base64',
    'java.util.Base64$Decoder',
    'java.util.Base64$Encoder',
)
JVM_PRIMITIVES = {
    'B': 'byte',
    'C': 'char',
    'D': 'double',
    'F': 'float',
    'I': 'int',
    'J': 'long',
    'S': 'short',
    'Z': 'boolean',
}
ICON_MAP = {
    'Process': 'fas fa-chart-bar',
    'Command': 'fas fa-terminal',
    'Java Native Interface': 'fab fa-cuttlefish',
    'WebView': 'far fa-window-maximize',
    'File IO': 'fas fa-file-signature',
    'Shared Preferences': 'fas fa-sliders-h',
    'Database': 'fas fa-database',
    'IPC': 'fas fa-broadcast-tower',
    'Binder': 'fas fa-cubes',
    'Crypto': 'fas fa-lock',
    'Crypto - Hash': 'fas fa-hashtag',
    'Device Info': 'fas fa-info',
    'Network': 'fas fa-wifi',
    'Dex Class Loader': 'fas fa-asterisk',
    'Base64': 'fas fa-puzzle-piece',
    'System Manager': 'fas fa-cogs',
    'SMS': 'fas fa-comment-alt',
    'Device Data': 'fas fa-phone',
}
HEX_RE = re.compile(r'[0-9a-fA-F]*')
LEGACY_BYTES_RE = re.compile(r'-?\d{1,3}(?:,-?\d{1,3})+')
LEGACY_INSTANCE_RE = re.compile(r'<instance: [^<>]{1,256}>')


def get_icon_map(name):
    """Get Font Awesome icon for an API category."""
    return ICON_MAP.get(name, 'far fa-dot-circle')


def _clip(text, limit=MAX_TEXT):
    if len(text) > limit:
        return text[:limit] + '…'
    return text


def _text(value, limit=MAX_FIELD):
    """Return a bounded string, or None for non-string values."""
    if not isinstance(value, str):
        return None
    return _clip(value, limit)


def _text_list(value, max_items, limit=MAX_TEXT):
    if not isinstance(value, list):
        return []
    return [_clip(v, limit) for v in value[:max_items]
            if isinstance(v, str)]


def _non_negative_int(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _simple_class(cls):
    return cls.rsplit('.', 1)[-1]


def java_type_name(descriptor):
    """Convert a JVM type descriptor to a short readable name."""
    if not isinstance(descriptor, str) or not descriptor:
        return '?'
    dims = len(descriptor) - len(descriptor.lstrip('['))
    base = descriptor[dims:]
    if dims:
        if base in JVM_PRIMITIVES:
            base = JVM_PRIMITIVES[base]
        elif base.startswith('L') and base.endswith(';'):
            base = base[1:-1]
    return _clip(_simple_class(base) + '[]' * dims, 128)


def bytes_as_text(data):
    """Return data decoded as UTF-8 if it is mostly printable text."""
    if not data:
        return None
    text = data.decode('utf-8', 'replace')
    bad = sum(1 for ch in text
              if ch == '\ufffd'
              or not (ch.isprintable() or ch in '\r\n\t'))
    if bad > len(text) * (1 - PRINTABLE_RATIO):
        return None
    return text


def format_bytes(data, length):
    """Render a byte array as quoted text when printable, else hex."""
    text = bytes_as_text(data)
    body = (json.dumps(text, ensure_ascii=False)
            if text is not None else '0x' + data.hex())
    suffix = '…' if len(data) < length else ''
    return _clip(f'byte[{length}] {body}{suffix}')


def _decode_hex(value):
    if (not isinstance(value, str)
            or len(value) % 2
            or not HEX_RE.fullmatch(value)):
        return b''
    return bytes.fromhex(value[:MAX_BYTES * 2])


def _bytes_value(value):
    """Return (data, length) for a byte array value from the hook."""
    if isinstance(value, dict) and value.get('$t') == 'bytes':
        data = _decode_hex(value.get('hex'))
        length = _non_negative_int(value.get('len'))
        return data, max(length or 0, len(data))
    return None


def format_value(value, depth=0):
    """Render a structured hook value as a readable one-line string."""
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return _clip(json.dumps(value, ensure_ascii=False))
    if isinstance(value, list):
        if depth >= MAX_DEPTH:
            return '[…]'
        items = [format_value(v, depth + 1) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f'… {len(value) - MAX_ITEMS} more')
        return _clip('[' + ', '.join(items) + ']')
    if isinstance(value, dict):
        kind = value.get('$t')
        if kind == 'bytes':
            return format_bytes(*_bytes_value(value))
        if kind == 'object':
            text = _text(value.get('str'), MAX_TEXT)
            return text or _text(value.get('cls')) or 'object'
        if kind == 'more':
            return f'… {_non_negative_int(value.get("count")) or 0} more'
    return 'object'


def _decoded_base64(cls, method, args, retval):
    """Return decoded text for android.util and java.util Base64 calls."""
    if cls not in BASE64_CLASSES:
        return None
    if method == 'decode':
        target = retval
    elif method in ('encode', 'encodeToString') and args:
        target = args[0]
    else:
        return None
    data = _bytes_value(target)
    if not data:
        return None
    text = bytes_as_text(data[0])
    return _clip(text) if text else None


def _count(value):
    count = _non_negative_int(value)
    return min(count, MAX_COUNT) if count else 1


def _entry(cls, method, *, name, arguments, return_value=None,
           arg_types=None, called_from=None, stack=None, thread=None,
           timestamp=None, exception=None, decoded=None, instance=None,
           app=True, count=1):
    if arg_types is None:
        signature = f'{method}(…)'
    else:
        signature = f'{method}({", ".join(arg_types)})'
    return {
        'v': FORMAT_VERSION,
        'name': _text(name, 64) or 'Other',
        'class': cls,
        'method': method,
        'api': f'{_simple_class(cls)}.{method}',
        'signature': _clip(signature, MAX_FIELD),
        'instance': _text(instance, MAX_TEXT),
        'arguments': arguments,
        'returnValue': return_value,
        # Kept for REST API clients of the original format.
        'result': return_value,
        'calledFrom': _text(called_from) or '',
        'app': app if isinstance(app, bool) else True,
        'stack': stack or [],
        'thread': _text(thread, 128) or '',
        'timestamp': _non_negative_int(timestamp),
        'exception': _text(exception, MAX_TEXT),
        'decoded': _text(decoded, MAX_TEXT),
        'count': _count(count),
    }


def normalize_event(raw):
    """Normalize a structured event sent by api_monitor.js."""
    if not isinstance(raw, dict):
        return None
    cls = _text(raw.get('class'), 256)
    method = _text(raw.get('method'), 128)
    if not cls or not method:
        return None
    args = raw.get('arguments')
    args = args[:MAX_ITEMS] if isinstance(args, list) else []
    arg_types = raw.get('argumentTypes')
    retval = raw.get('returnValue')
    return _entry(
        cls,
        method,
        name=raw.get('name'),
        arg_types=([java_type_name(t) for t in arg_types[:MAX_ITEMS]]
                   if isinstance(arg_types, list) else None),
        arguments=[format_value(a) for a in args],
        return_value=(format_value(retval)
                      if 'returnValue' in raw else None),
        called_from=raw.get('calledFrom'),
        stack=_text_list(raw.get('stack'), MAX_STACK, MAX_FIELD),
        thread=raw.get('thread'),
        timestamp=raw.get('timestamp'),
        exception=raw.get('exception'),
        decoded=_decoded_base64(cls, method, args, retval),
        instance=raw.get('instance'),
        app=raw.get('app'),
        count=raw.get('count'))


def _load_stored(item):
    """Re-validate an entry previously written by serialize_event."""
    cls = _text(item.get('class'), 256)
    method = _text(item.get('method'), 128)
    if not cls or not method:
        return None
    entry = _entry(
        cls,
        method,
        name=item.get('name'),
        arguments=_text_list(item.get('arguments'), MAX_ITEMS),
        return_value=_text(item.get('returnValue'), MAX_TEXT * 2),
        called_from=item.get('calledFrom'),
        stack=_text_list(item.get('stack'), MAX_STACK, MAX_FIELD),
        thread=item.get('thread'),
        timestamp=item.get('timestamp'),
        exception=item.get('exception'),
        decoded=item.get('decoded'),
        instance=item.get('instance'),
        app=item.get('app'),
        count=item.get('count'))
    signature = _text(item.get('signature'))
    if signature:
        entry['signature'] = signature
    return entry


def _legacy_value(value):
    """Format argument values from the pre-v2 hook output."""
    if (isinstance(value, list) and value
            and all(isinstance(v, int) and not isinstance(v, bool)
                    and -128 <= v <= 255 for v in value)):
        data = bytes(v & 0xff for v in value[:MAX_BYTES])
        return format_bytes(data, len(value))
    if isinstance(value, str) and LEGACY_INSTANCE_RE.fullmatch(value):
        return value
    return format_value(value)


def _legacy_result(value):
    if not isinstance(value, str):
        return None
    if LEGACY_BYTES_RE.fullmatch(value):
        nums = [int(v) for v in value.split(',')]
        if all(-128 <= v <= 255 for v in nums):
            data = bytes(v & 0xff for v in nums[:MAX_BYTES])
            return format_bytes(data, len(nums))
    return _clip(value)


def decode_base64(data, altchars=b'+/'):
    """Decode base64, padding being optional."""
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars, b'', data.encode())
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'=' * (4 - missing_padding)
    return base64.b64decode(data, altchars)


def _legacy_decoded(cls, method, args, retval):
    if cls != 'android.util.Base64':
        return None
    target = None
    if method == 'encodeToString' and isinstance(retval, str):
        target = retval.replace('"', '')
    elif method == 'decode' and args and isinstance(args[0], str):
        target = args[0]
    if not target:
        return None
    try:
        return decode_base64(target).decode('utf-8', 'ignore')
    except ValueError:
        return None


def _load_legacy(item):
    """Normalize an entry from the original comma-joined log format."""
    cls = _text(item.get('class'), 256)
    method = _text(item.get('method'), 128)
    if not cls or not method:
        return None
    args = item.get('arguments')
    args = args[:MAX_ITEMS] if isinstance(args, list) else []
    retval = item.get('result')
    if retval is None:
        retval = item.get('returnValue')
    return _entry(
        cls,
        method,
        name=item.get('name'),
        arguments=[_legacy_value(a) for a in args],
        return_value=_legacy_result(retval),
        called_from=item.get('calledFrom'),
        decoded=_legacy_decoded(cls, method, args, item.get('returnValue')))


def load_entry(item):
    """Validate one stored log entry of any supported format."""
    if not isinstance(item, dict):
        return None
    if item.get('v') == FORMAT_VERSION:
        return _load_stored(item)
    return _load_legacy(item)


def serialize_event(payload):
    """Parse a Frida API monitor payload into JSON log lines.

    The payload is a single event or a batch: {"events": [...]}.
    """
    if not isinstance(payload, str):
        return None
    try:
        raw = json.loads(payload)
    except ValueError:
        return None
    if isinstance(raw, dict) and 'events' in raw:
        events = raw['events']
        events = events[:MAX_BATCH] if isinstance(events, list) else []
    else:
        events = [raw]
    lines = []
    for event in events:
        entry = normalize_event(event)
        if entry:
            lines.append(json.dumps(entry, ensure_ascii=False) + '\n')
    return ''.join(lines) or None


def _parse_line(line):
    try:
        data = json.loads(line)
    except ValueError:
        # Original format: objects joined by ',' with a trailing ','.
        try:
            data = json.loads('[' + line.rstrip(',') + ']')
        except ValueError:
            return []
    items = data if isinstance(data, list) else [data]
    return [e for e in (load_entry(i) for i in items) if e]


def read_api_monitor(location):
    """Read and normalize all entries from an API monitor log."""
    path = Path(location)
    if is_pipe_or_link(path) or not path.is_file():
        return []
    entries = []
    with path.open('r', encoding='utf-8', errors='replace') as flip:
        for line in flip:
            line = line.strip()
            if line:
                entries.extend(_parse_line(line))
    return entries


def group_api_calls(entries):
    """Group entries by category, collapsing identical calls.

    App-initiated calls are listed before framework-internal ones.
    """
    groups = {}
    strings = []
    seen_strings = set()
    for entry in entries:
        calls = groups.setdefault(entry['name'], {})
        key = (
            entry['class'],
            entry['method'],
            entry['instance'],
            tuple(entry['arguments']),
            entry['returnValue'],
            entry['calledFrom'],
            entry['exception'],
            entry['app'],
        )
        if key in calls:
            calls[key]['count'] += entry['count']
            continue
        calls[key] = dict(entry, icon=get_icon_map(entry['name']))
        decoded = entry['decoded']
        if decoded and (entry['calledFrom'], decoded) not in seen_strings:
            seen_strings.add((entry['calledFrom'], decoded))
            strings.append((entry['calledFrom'], decoded))
    grouped = {
        name: sorted(calls.values(), key=lambda c: not c['app'])
        for name, calls in groups.items()}
    return grouped, strings


def framework_call_counts(groups):
    """Return the number of framework-internal unique calls per category."""
    return {name: sum(1 for c in calls if not c['app'])
            for name, calls in groups.items()}
