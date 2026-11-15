# -*- coding: utf_8 -*-
"""Cordova, Capacitor and Expo configuration checks."""
import json
import re
from xml.parsers import expat

from defusedxml.ElementTree import fromstring as xml_fromstring

from mobsf.StaticAnalyzer.views.common.js_analysis.constants import (
    MAX_CONFIG_BYTES,
)
from mobsf.StaticAnalyzer.views.common.shared_func import is_secret_key


_WILDCARD_NAV_RE = re.compile(
    r'^(?:\*|(?:\*|https?)://\*(?::(?:\*|\d+))?(?:/.*)?)$',
    re.IGNORECASE,
)
_JSON_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|[{}\[\]:,]|[^\s{}\[\]:,"]+',
)
_EXPO_ROOT_MARKER_KEYS = {
    'slug',
    'sdkVersion',
    'runtimeVersion',
    'platforms',
    'orientation',
    'ios',
    'android',
    'scheme',
    'newArchEnabled',
    'jsEngine',
    'updates',
    'extra',
}
_NON_EXPO_APP_JSON_KEYS = {
    'addons',
    'buildpacks',
    'formation',
    'stack',
}


def make_finding(description, severity, cvss, cwe, owasp, masvs, files_dict):
    """Build a libsast-compatible finding dictionary."""
    return {
        'files': files_dict,
        'metadata': {
            'description': description,
            'severity': severity,
            'cvss': cvss,
            'cwe': cwe,
            'owasp-mobile': owasp,
            'masvs': masvs,
        },
    }


_MAX_CONFIG_LINES = 25


def _append_line(files_map, rel_path, line):
    """Record up to _MAX_CONFIG_LINES unique 1-indexed lines per file."""
    line_str = str(line)
    existing = files_map.get(rel_path)
    if not existing:
        files_map[rel_path] = line_str
        return
    parts = [tok.strip() for tok in existing.split(',') if tok.strip()]
    if len(parts) >= _MAX_CONFIG_LINES or line_str in parts:
        return
    parts.append(line_str)
    files_map[rel_path] = ','.join(parts)


def _parse_cordova_elements(raw):
    """Validate XML via defusedxml and return (tag, attrs, line) under <widget>."""
    xml_fromstring(raw.encode('utf-8', 'ignore'))
    parser = expat.ParserCreate()
    elements = []
    state = {'depth': 0, 'is_widget': False}

    def start_element(name, attrs):
        local_tag = name.split(':')[-1].lower()
        if state['depth'] == 0:
            state['is_widget'] = local_tag == 'widget'
        state['depth'] += 1
        if not state['is_widget']:
            return
        norm_attrs = {k.lower(): str(v) for k, v in attrs.items()}
        elements.append((local_tag, norm_attrs, parser.CurrentLineNumber))

    def end_element(_name):
        state['depth'] -= 1

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.Parse(raw, True)
    return elements


_MAX_JSON_PATH_DEPTH = 3
_MAX_JSON_TOKENS = 100_000


def _parse_json_value(tokens, pos, path, lines):
    """Advance past one RFC-8259 JSON value, recording key line numbers.

    path is None inside arrays, where no line numbers are recorded.
    """
    tok = tokens[pos][0]
    if tok == '{':
        return _parse_json_object(tokens, pos + 1, path, lines)
    if tok == '[':
        return _parse_json_array(tokens, pos + 1, lines)
    return pos + 1


def _parse_json_object(tokens, pos, path, lines):
    """Advance past a JSON object body and record each property's line."""
    if tokens[pos][0] == '}':
        return pos + 1
    while pos < len(tokens):
        key_path = None
        if path is not None and len(path) < _MAX_JSON_PATH_DEPTH:
            key_tok, key_line = tokens[pos]
            key_path = path + (json.loads(key_tok),)
            lines[key_path] = key_line
        pos = _parse_json_value(tokens, pos + 2, key_path, lines)
        if tokens[pos][0] == ',':
            pos += 1
            continue
        return pos + 1
    return pos


def _parse_json_array(tokens, pos, lines):
    """Advance past a JSON array body without recording element lines."""
    if tokens[pos][0] == ']':
        return pos + 1
    while pos < len(tokens):
        pos = _parse_json_value(tokens, pos, None, lines)
        if tokens[pos][0] == ',':
            pos += 1
            continue
        return pos + 1
    return pos


def _load_json_with_lines(cfg_path):
    """Parse JSON file within size limit and return (data, {key_path: line})."""
    try:
        if cfg_path.stat().st_size > MAX_CONFIG_BYTES:
            return None, {}
        raw = cfg_path.read_text('utf-8', 'ignore')
        data = json.loads(raw)
    except Exception:
        return None, {}
    lines = {}
    try:
        tokens = []
        line_no = 1
        last_idx = 0
        for match in _JSON_TOKEN_RE.finditer(raw):
            if len(tokens) >= _MAX_JSON_TOKENS:
                return data, {}
            start = match.start()
            line_no += raw.count('\n', last_idx, start)
            last_idx = start
            tokens.append((match.group(0), line_no))
        if tokens:
            _parse_json_value(tokens, 0, (), lines)
    except Exception:
        lines = {}
    return data, lines


def check_cordova_config(cfg_path, rel_path, findings):
    """Check Cordova / PhoneGap config.xml for insecure directives."""
    try:
        if cfg_path.stat().st_size > MAX_CONFIG_BYTES:
            return
        raw = cfg_path.read_text('utf-8', 'ignore')
        elements = _parse_cordova_elements(raw)
    except Exception:
        return
    for tag, attrs, line in elements:
        if tag == 'access' and attrs.get('origin', '').strip() == '*':
            entry = findings.setdefault(
                'cordova_config_wildcard_access',
                make_finding(
                    'Cordova config.xml allows network access to all '
                    'origins (<access origin="*" />). Restrict allowed '
                    'domains to trusted backend endpoints.',
                    'warning',
                    5.3,
                    'CWE-942: Permissive Cross-domain Policy with Untrusted Domains',
                    'M5: Insecure Communication',
                    'MSTG-PLATFORM-2',
                    {},
                ),
            )
            _append_line(entry['files'], rel_path, line)
        elif tag == 'allow-navigation':
            href = attrs.get('href', '').strip()
            if _WILDCARD_NAV_RE.match(href):  # NOSONAR - rule pattern
                entry = findings.setdefault(
                    'cordova_config_wildcard_navigation',
                    make_finding(
                        f'Cordova config.xml permits WebView navigation to '
                        f'wildcard origin (href="{href}"). Remote pages '
                        'loaded into the Cordova WebView can access exposed '
                        'native plugins.',
                        'high',
                        7.5,
                        'CWE-601: URL Redirection to Untrusted Site',
                        'M8: Security Misconfiguration',
                        'MSTG-PLATFORM-2',
                        {},
                    ),
                )
                _append_line(entry['files'], rel_path, line)


def check_capacitor_config(cfg_path, rel_path, findings):
    """Check Capacitor capacitor.config.json for cleartext or wildcard nav."""
    data, lines = _load_json_with_lines(cfg_path)
    if not isinstance(data, dict):
        return
    server = data.get('server')
    if not isinstance(server, dict):
        return
    cleartext_on = server.get('cleartext') is True
    url_http = str(server.get('url', '')).lower().startswith('http://')
    if cleartext_on or url_http:
        prop_path = ('server', 'cleartext') if cleartext_on else (
            'server', 'url')
        line = lines.get(prop_path, lines.get(('server',), 1))
        findings.setdefault(
            'capacitor_cleartext_traffic',
            make_finding(
                'Capacitor configuration enables cleartext HTTP traffic '
                '(server.cleartext: true or HTTP server.url).',
                'high',
                7.4,
                'CWE-319: Cleartext Transmission of Sensitive Information',
                'M5: Insecure Communication',
                'MSTG-NETWORK-1',
                {},
            ),
        )['files'][rel_path] = str(line)
    allow_nav = server.get('allowNavigation')
    if isinstance(allow_nav, list) and any(
            '*' in str(item) for item in allow_nav):
        line = lines.get(
            ('server', 'allowNavigation'),
            lines.get(('server',), 1),
        )
        findings.setdefault(
            'capacitor_wildcard_navigation',
            make_finding(
                'Capacitor server.allowNavigation includes a wildcard '
                'pattern, allowing the privileged WebView to navigate to '
                'untrusted origins.',
                'warning',
                6.1,
                'CWE-601: URL Redirection to Untrusted Site',
                'M8: Security Misconfiguration',
                'MSTG-PLATFORM-2',
                {},
            ),
        )['files'][rel_path] = str(line)


def _is_root_expo_app_json(data):
    """Return True if an unwrapped app.json looks like an Expo app config."""
    keys = set(data.keys())
    if keys & _NON_EXPO_APP_JSON_KEYS:
        return False
    if not (keys & _EXPO_ROOT_MARKER_KEYS):
        return False
    extra = data.get('extra')
    updates = data.get('updates')
    has_expo_markers = bool(
        keys & (_EXPO_ROOT_MARKER_KEYS - {'extra', 'updates'}),
    )
    has_expo_extra = isinstance(extra, dict) and 'eas' in extra
    has_expo_updates = isinstance(updates, dict) and (
        'url' in updates
        or 'codeSigningCertificate' in updates
        or 'fallbackToCacheTimeout' in updates
    )
    return has_expo_markers or has_expo_extra or has_expo_updates


def _load_expo_config(cfg_path):
    """Return (expo_dict, lines_map, root_prefix) for an Expo config."""
    data, lines = _load_json_with_lines(cfg_path)
    if not isinstance(data, dict):
        return None, {}, ()
    if isinstance(data.get('expo'), dict):
        return data['expo'], lines, ('expo',)
    if cfg_path.name.lower() == 'app.json':
        if _is_root_expo_app_json(data):
            return data, lines, ()
        return None, {}, ()
    return data, lines, ()


def _iter_secret_pairs(obj, prefix=''):
    """Yield (dotted key, value) for secret-looking string values."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            name = f'{prefix}{key}'
            if isinstance(val, (dict, list)):
                yield from _iter_secret_pairs(val, f'{name}.')
            elif (isinstance(val, str) and len(val) >= 8
                    and is_secret_key(str(key))):
                yield name, val
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_secret_pairs(item, prefix)


def check_expo_config(cfg_path, rel_path, findings, secrets):
    """Check an Expo app config / embedded manifest for insecure settings."""
    data, lines, root_prefix = _load_expo_config(cfg_path)
    if data is None:
        return
    extra_secrets = list(_iter_secret_pairs(data.get('extra')))
    if extra_secrets:
        for key, val in extra_secrets:
            secrets.add(f'"{key}" : "{val}"')
        new_keys = {k for k, _ in extra_secrets}
        entry = findings.get('expo_config_extra_secrets')
        if entry:
            prev = entry.get('_secret_keys', set())
            all_keys = prev | new_keys
        else:
            all_keys = set(new_keys)
            entry = make_finding(
                '',
                'warning',
                7.5,
                'CWE-798: Use of Hard-coded Credentials',
                'M1: Improper Credential Usage',
                'MSTG-STORAGE-14',
                {},
            )
            findings['expo_config_extra_secrets'] = entry
        entry['_secret_keys'] = all_keys
        entry['metadata']['description'] = (
            'Expo app config "extra" contains secret-looking values ('
            + ', '.join(sorted(all_keys)[:10])
            + '). Values in "extra" are embedded in the app package '
            'and readable by anyone through expo-constants.'
        )
        entry['files'][rel_path] = str(
            lines.get(root_prefix + ('extra',), 1))
    updates = data.get('updates')
    if not isinstance(updates, dict) or updates.get('enabled') is False:
        return
    url = str(updates.get('url', ''))
    if url.lower().startswith('http://'):
        line = lines.get(
            root_prefix + ('updates', 'url'),
            lines.get(root_prefix + ('updates',), 1),
        )
        findings.setdefault(
            'expo_updates_cleartext',
            make_finding(
                'Expo over-the-air updates are fetched over cleartext HTTP '
                '(updates.url). A network attacker can serve a malicious '
                'JavaScript bundle that runs with full app privileges.',
                'high',
                8.1,
                'CWE-319: Cleartext Transmission of Sensitive Information',
                'M5: Insecure Communication',
                'MSTG-NETWORK-1',
                {},
            ),
        )['files'][rel_path] = str(line)
    if url and not updates.get('codeSigningCertificate'):
        line = lines.get(root_prefix + ('updates',), 1)
        findings.setdefault(
            'expo_updates_unsigned',
            make_finding(
                'Expo over-the-air updates are enabled without code signing '
                '(no updates.codeSigningCertificate). Update integrity '
                'relies only on transport security and the update server.',
                'info',
                3.7,
                'CWE-494: Download of Code Without Integrity Check',
                'M7: Insufficient Binary Protections',
                'MSTG-CODE-1',
                {},
            ),
        )['files'][rel_path] = str(line)
