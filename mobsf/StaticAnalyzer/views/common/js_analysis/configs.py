# -*- coding: utf_8 -*-
"""Cordova, Capacitor and Expo configuration checks."""
import json

from defusedxml.ElementTree import fromstring as xml_fromstring

from mobsf.StaticAnalyzer.views.common.js_analysis.constants import (
    MAX_CONFIG_BYTES,
)
from mobsf.StaticAnalyzer.views.common.shared_func import is_secret_key


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


def _line_of_substring(text, needle):
    """Return 1-indexed line number of needle in text."""
    idx = text.find(needle)
    if idx == -1:
        return '1'
    return str(text.count('\n', 0, idx) + 1)


def check_cordova_config(cfg_path, rel_path, findings):
    """Check Cordova / PhoneGap config.xml for insecure directives."""
    try:
        raw = cfg_path.read_text('utf-8', 'ignore')
        root = xml_fromstring(raw.encode('utf-8', 'ignore'))
    except Exception:
        return
    for elem in root.iter():
        tag = elem.tag.split('}')[-1].lower()
        if tag == 'access' and elem.attrib.get('origin', '').strip() == '*':
            line = _line_of_substring(raw, '<access')
            findings.setdefault(
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
            )['files'][rel_path] = line
        elif tag == 'allow-navigation':
            href = elem.attrib.get('href', '').strip()
            if href in ('*', 'http://*/*', 'https://*/*'):
                line = _line_of_substring(raw, '<allow-navigation')
                findings.setdefault(
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
                )['files'][rel_path] = line


def check_capacitor_config(cfg_path, rel_path, findings):
    """Check Capacitor capacitor.config.json for cleartext or wildcard nav."""
    try:
        raw = cfg_path.read_text('utf-8', 'ignore')
        data = json.loads(raw)
    except Exception:
        return
    if not isinstance(data, dict):
        return
    server = data.get('server')
    if not isinstance(server, dict):
        return
    if server.get('cleartext') is True or str(
            server.get('url', '')).startswith('http://'):
        line = _line_of_substring(raw, 'cleartext')
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
        )['files'][rel_path] = line
    allow_nav = server.get('allowNavigation')
    if isinstance(allow_nav, list) and any(
            '*' in str(item) for item in allow_nav):
        line = _line_of_substring(raw, 'allowNavigation')
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
        )['files'][rel_path] = line


def _load_expo_config(cfg_path):
    """Return (raw, expo config dict) for an embedded or source Expo config."""
    if cfg_path.stat().st_size > MAX_CONFIG_BYTES:
        return None, None
    try:
        raw = cfg_path.read_text('utf-8', 'ignore')
        data = json.loads(raw)
    except Exception:
        return None, None
    if not isinstance(data, dict):
        return None, None
    if cfg_path.name.lower() == 'app.json':
        data = data.get('expo')
        if not isinstance(data, dict):
            return None, None
    return raw, data


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
    raw, data = _load_expo_config(cfg_path)
    if data is None:
        return
    extra_secrets = list(_iter_secret_pairs(data.get('extra')))
    if extra_secrets:
        for key, val in extra_secrets:
            secrets.add(f'"{key}" : "{val}"')
        findings.setdefault(
            'expo_config_extra_secrets',
            make_finding(
                'Expo app config "extra" contains secret-looking values ('
                + ', '.join(sorted(k for k, _ in extra_secrets)[:10])
                + '). Values in "extra" are embedded in the app package '
                'and readable by anyone through expo-constants.',
                'warning',
                7.5,
                'CWE-798: Use of Hard-coded Credentials',
                'M1: Improper Credential Usage',
                'MSTG-STORAGE-14',
                {},
            ),
        )['files'][rel_path] = _line_of_substring(raw, '"extra"')
    updates = data.get('updates')
    if not isinstance(updates, dict) or updates.get('enabled') is False:
        return
    url = str(updates.get('url', ''))
    if url.lower().startswith('http://'):
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
        )['files'][rel_path] = _line_of_substring(raw, '"url"')
    if url and not updates.get('codeSigningCertificate'):
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
        )['files'][rel_path] = _line_of_substring(raw, '"updates"')
