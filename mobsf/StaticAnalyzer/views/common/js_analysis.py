# -*- coding: utf_8 -*-
"""JavaScript, TypeScript, Hybrid & Hermes Bytecode Static Analysis."""
import json
import logging
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

from defusedxml.ElementTree import fromstring as xml_fromstring

from django.conf import settings

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    python_dict,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.views.common.secret_detection import (
    get_secrets,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    STRINGS_REGEX,
    is_secret_key,
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.sast_engine import SastEngine

logger = logging.getLogger(__name__)

HERMES_MAGIC = b'\xc6\x1f\xbc\x03\xc1\x03\x19\x1f'
MAX_JS_FILE_BYTES = 50 * 1024 * 1024
MAX_URL_SCAN_BYTES = 25 * 1024 * 1024

JS_SOURCE_EXTS = {
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
    '.vue', '.svelte', '.html', '.htm',
}
BUNDLE_EXTS = {'.bundle', '.jsbundle', '.hbc'}
SKIP_JS_DIRS = {
    'node_modules', '.git', '.gradle', 'build', 'dist', '.expo',
    '.next', 'coverage', 'pods', 'carthage', 'deriveddata',
    'java_source', 'smali_source', 'apktool_out', '__macosx',
    'vendor', 'frameworks', 'plugins', '_codesignature', 'sc_info',
}
# Cordova/Capacitor ship plugin JS under www/plugins or public/plugins.
WEB_ROOT_DIRS = {'www', 'public'}
EXPO_CONFIG_FILES = {'app.config', 'app.manifest', 'app.json'}
HYBRID_CONFIG_FILES = {'config.xml', 'capacitor.config.json'} | (
    EXPO_CONFIG_FILES)
MAX_CONFIG_BYTES = 5 * 1024 * 1024
MAX_LISTED_JS_FILES = 10000
SKIP_VENDOR_FILES = {
    'cordova.js', 'cordova_plugins.js', 'phonegap.js',
    'jquery.js', 'jquery.min.js', 'bootstrap.js', 'bootstrap.min.js',
    'polyfills.js', 'runtime.js',
}

_REG_ASSIGN_RE = re.compile(r'^(\s*)(r\d+)\s*=\s*(.+);$')
_REG_SUBSCRIPT_ASSIGN_RE = re.compile(
    r'^(\s*)(r\d+\[[\'"][^\'"]+[\'"]\])\s*=\s*(r\d+);$')
_REG_BIND_CALL_RE = re.compile(r'^(r\d+)\.bind\((r\d+)\)\((.*)\)$')
_OBJ_CREATE_CTOR_RE = re.compile(
    r'^Object\.create\(r\d+(?:\.prototype'
    r'|,\s*\{constructor:\s*\{value:\s*(r\d+)\}\})\)$')
_REG_TOKEN_RE = re.compile(r'\br\d+\b')
_SAFE_EXPR_RE = re.compile(
    r'^(?:true|false|null|-?\d+(?:\.\d+)?|[\'"][^\r\n]{0,80}[\'"]'
    r'|r\d+(?:\.[A-Za-z_$][\w$]*)+)$')
_JS_FORMAT_RE = re.compile(
    r'(?P<lit>"(?:\\.|[^"\\\r\n])*"|\'(?:\\.|[^\'\\\r\n])*\''
    r'|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*[\s\S]*?\*/)'
    r'|(?P<open>\{)|(?P<close>\})|(?P<semi>;)')
BEAUTIFY_EXTS = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.bundle', '.jsbundle'}


def is_minified_js(text):
    """Return True if JS text has very long minified lines."""
    if not text or len(text) < 500:
        return False
    lines = text.splitlines()
    if not lines:
        return False
    if len(text) // max(len(lines), 1) > 250:
        return True
    return any(len(line) > 1000 for line in lines[:50])


def beautify_minified_js(text):
    """Fast token-aware JS formatter that splits minified code onto lines."""
    indent = 0
    out = []
    pos = 0
    for match in _JS_FORMAT_RE.finditer(text):
        start, end = match.span()
        if start > pos:
            out.append(text[pos:start])
        if match.group('lit'):
            out.append(match.group(0))
        elif match.group('open'):
            indent = min(indent + 1, 16)
            out.append('{\n' + ('  ' * indent))
        elif match.group('close'):
            indent = max(indent - 1, 0)
            out.append('\n' + ('  ' * indent) + '}')
        elif match.group('semi'):
            out.append(';\n' + ('  ' * indent))
        pos = end
    if pos < len(text):
        out.append(text[pos:])
    return ''.join(out)


def _format_long_object_line(line):
    """Expand multi-property single-line Hermes object literals across lines."""
    if len(line) <= 300 or '= {' not in line or not line.endswith('};'):
        return [line]
    head, _, rest = line.partition('= {')
    body = rest[:-2]
    indent = len(line) - len(line.lstrip())
    pad = ' ' * (indent + 4)
    end_pad = ' ' * indent
    parts = [p.strip() for p in body.split(', ') if p.strip()]
    if len(parts) < 3:
        return [line]
    expanded = [f'{head}= {{']
    for idx, prop in enumerate(parts):
        suffix = ',' if idx + 1 < len(parts) else ''
        expanded.append(f'{pad}{prop}{suffix}')
    expanded.append(f'{end_pad}}};')
    return expanded


def slice_large_source(text, lines_param, max_bytes=1500000, radius=300):
    """Return (sliced_text, start_line) when a string is too large for DOM."""
    if not text or len(text) <= max_bytes:
        return text, 1
    all_lines = text.splitlines()
    total = len(all_lines)
    target = 1
    if lines_param:
        for tok in str(lines_param).split(','):
            tok = tok.strip()
            if tok.isdigit():
                target = max(1, min(int(tok), total))
                break
    start = max(1, target - radius)
    end = min(total, start + (radius * 2))
    return '\n'.join(all_lines[start - 1:end]), start


def read_js_source_window(file_path, lines_param=None, line_start=None,
                          search_term=None, max_bytes=1500000,
                          window_lines=2000):
    """Read a JS file or a paged window with O(1) RAM and total line count."""
    size = file_path.stat().st_size
    if size <= max_bytes:
        text = file_path.read_text('utf-8', 'ignore')
        total = text.count('\n') + 1
        return {
            'data': text,
            'start_line': 1,
            'end_line': total,
            'total_lines': total,
            'window_lines': window_lines,
            'is_paged': False,
        }

    target_start = None
    if line_start and str(line_start).strip().isdigit():
        target_start = max(1, int(str(line_start).strip()))
    elif lines_param:
        for tok in str(lines_param).split(','):
            tok = tok.strip()
            if tok.isdigit():
                target_start = max(1, int(tok) - (window_lines // 4))
                break

    q_low = search_term.strip().lower() if search_term else ''
    total = 0
    first_match_line = None
    with open(file_path, 'rb') as fbin:
        for idx, raw_bytes in enumerate(fbin, 1):
            total = idx
            if q_low and first_match_line is None:
                if q_low in raw_bytes.decode('utf-8', 'ignore').lower():
                    first_match_line = idx

    if target_start is None:
        if first_match_line is not None:
            target_start = max(1, first_match_line - 100)
        else:
            target_start = 1

    start = min(target_start, max(1, total - window_lines + 1))
    end = min(total, start + window_lines - 1)
    collected = []
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fp:
        for lno, raw_line in enumerate(fp, 1):
            if lno < start:
                continue
            if lno > end:
                break
            collected.append(raw_line.rstrip('\r\n'))
    return {
        'data': '\n'.join(collected),
        'start_line': start,
        'end_line': end,
        'total_lines': total,
        'window_lines': window_lines,
        'is_paged': True,
    }


def is_hermes_bytecode(file_path):
    """Return (is_hermes, bytecode_version) for a candidate file."""
    try:
        with open(file_path, 'rb') as fp:
            header = fp.read(12)
        if len(header) >= 12 and header[:8] == HERMES_MAGIC:
            version = struct.unpack('<I', header[8:12])[0]
            return True, int(version)
    except OSError:
        pass
    return False, None


def _fold_args(args_str, reg_map):
    """Replace register tokens inside a call argument list."""
    if not args_str.strip():
        return args_str

    def _repl(match):
        tok = match.group(0)
        return reg_map.get(tok, tok)

    return _REG_TOKEN_RE.sub(_repl, args_str)


def _rewrite_hermes_rhs(lhs, rhs, reg_map, ctor_map):
    """Fold register assignments and .bind() calls in hermes-dec output."""
    ctor_match = _OBJ_CREATE_CTOR_RE.match(rhs)
    if ctor_match:
        ctor_reg = ctor_match.group(1)
        if ctor_reg:
            ctor_map[lhs] = reg_map.get(ctor_reg, ctor_reg)
        return rhs

    bind_match = _REG_BIND_CALL_RE.match(rhs)
    if bind_match:
        fn_reg, this_reg, raw_args = bind_match.groups()
        folded_args = _fold_args(raw_args, reg_map)
        if this_reg in ctor_map:
            return f'new {ctor_map[this_reg]}({folded_args})'
        fn_expr = reg_map.get(fn_reg, fn_reg)
        return f'{fn_expr}({folded_args})'

    if rhs in reg_map:
        return reg_map[rhs]

    if '.' in rhs and rhs.startswith('r'):
        base_reg, _, tail = rhs.partition('.')
        if base_reg in reg_map and not reg_map[base_reg].startswith(("'", '"')):
            return f'{reg_map[base_reg]}.{tail}'
    return rhs


def _normalize_hermes_stream(raw_path, dec_path):
    """Stream-normalize hermes-dec output with O(1) memory usage."""
    reg_map = {}
    ctor_map = {}
    in_disassembly = False

    with open(raw_path, 'r', encoding='utf-8', errors='ignore') as src, open(
            dec_path, 'w', encoding='utf-8') as dst:
        for raw_line in src:
            line = raw_line.rstrip('\r\n')
            stripped = line.strip()
            if stripped.startswith('==== Falling back to Disassembly ===='):
                in_disassembly = True
                dst.write(f'// {line}\n')
                continue
            if in_disassembly:
                if line.startswith(('function', '}')):
                    in_disassembly = False
                else:
                    dst.write(f'// {line}\n')
                    continue

            if stripped.startswith(('function', 'case ', '{', '}')):
                reg_map.clear()
                ctor_map.clear()

            sub_match = _REG_SUBSCRIPT_ASSIGN_RE.match(line)
            if sub_match:
                indent, target, val_reg = sub_match.groups()
                resolved = reg_map.get(val_reg, val_reg)
                dst.write(f'{indent}{target} = {resolved};\n')
                continue

            assign_match = _REG_ASSIGN_RE.match(line)
            if assign_match:
                indent, lhs, rhs = assign_match.groups()
                new_rhs = _rewrite_hermes_rhs(lhs, rhs, reg_map, ctor_map)
                if (_SAFE_EXPR_RE.match(new_rhs)
                        and len(new_rhs) <= 96
                        and lhs not in new_rhs):
                    reg_map[lhs] = new_rhs
                else:
                    reg_map.pop(lhs, None)
                for exp_line in _format_long_object_line(
                        f'{indent}{lhs} = {new_rhs};'):
                    dst.write(f'{exp_line}\n')
                continue

            for exp_line in _format_long_object_line(line):
                dst.write(f'{exp_line}\n')


def _extract_hermes_strings(bundle_path):
    """Extract string table from a Hermes bytecode file via HBCReader."""
    try:
        from hermes_dec.parsers.hbc_file_parser import HBCReader
        with open(bundle_path, 'rb') as fp:
            reader = HBCReader()
            reader.read_whole_file(fp)
            return [s for s in (reader.strings or []) if isinstance(s, str)]
    except Exception:
        try:
            raw = bundle_path.read_bytes()[:MAX_URL_SCAN_BYTES]
            return [
                m.group(0).decode('utf-8', 'ignore')
                for m in re.finditer(rb'[\x20-\x7e]{6,200}', raw)
            ]
        except OSError:
            return []


def decompile_hermes_bundle(checksum, bundle_path, scan_root):
    """Decompile a Hermes bytecode file to <name>.dec.js using hermes-dec."""
    dec_path = bundle_path.with_name(f'{bundle_path.name}.dec.js')
    raw_tmp = bundle_path.with_name(f'{bundle_path.name}.raw.dec.js')
    try:
        rel = dec_path.relative_to(scan_root).as_posix()
        if (not is_safe_path(scan_root, dec_path, rel)
                or is_pipe_or_link(bundle_path)):
            return None
        msg = f'Decompiling Hermes bytecode bundle: {bundle_path.name}'
        logger.info(msg)
        append_scan_status(checksum, msg)
        timeout = getattr(settings, 'SAST_TIMEOUT', 1800)
        subprocess.run(
            [
                sys.executable,
                '-m',
                'hermes_dec.decompilation.hbc_decompiler',
                bundle_path.as_posix(),
                raw_tmp.as_posix(),
            ],
            timeout=timeout,
            capture_output=True,
            check=False,
        )
        if raw_tmp.is_file() and raw_tmp.stat().st_size > 0:
            _normalize_hermes_stream(raw_tmp, dec_path)
            raw_tmp.unlink()
            return dec_path
    except Exception as exp:
        logger.warning(
            'Hermes decompilation failed for %s: %s',
            sanitize_for_logging(bundle_path.name),
            sanitize_for_logging(repr(exp)),
        )
    finally:
        if raw_tmp.exists() and not is_pipe_or_link(raw_tmp):
            try:
                raw_tmp.unlink()
            except OSError:
                pass
    if dec_path.exists() and not is_pipe_or_link(dec_path):
        try:
            dec_path.unlink()
        except OSError:
            pass
    return None


def _is_valid_candidate(scan_root, pfile):
    """Return True if pfile is a safe regular file inside scan_root."""
    try:
        rel = pfile.relative_to(scan_root).as_posix()
    except ValueError:
        return False
    if (not is_safe_path(scan_root, pfile, rel)
            or is_pipe_or_link(pfile)
            or not pfile.is_file()):
        return False
    if pfile.name.lower() in SKIP_VENDOR_FILES:
        return False
    if pfile.name.endswith('.dec.js'):
        return False
    return True


def _is_skipped_dir(name, parent):
    """Return True if a directory should not be descended into."""
    low = name.lower()
    if low.endswith('.framework'):
        return True
    if low == 'plugins' and parent.lower() in WEB_ROOT_DIRS:
        return False
    return low in SKIP_JS_DIRS


def _iter_files(root):
    """Yield files under root, pruning skipped dirs without following links."""
    for dirpath, dirnames, filenames in os.walk(root):
        parent = os.path.basename(dirpath)
        dirnames[:] = [
            d for d in dirnames if not _is_skipped_dir(d, parent)]
        for fname in filenames:
            yield Path(dirpath, fname)


def _is_js_name(name):
    """Return True if a filename has a JS source or bundle extension."""
    suffix = os.path.splitext(name)[1].lower()
    return suffix in JS_SOURCE_EXTS or suffix in BUNDLE_EXTS


def _is_analysis_name(name):
    """Return True if a filename is relevant to JS/hybrid analysis."""
    low = name.lower()
    return (_is_js_name(low)
            or low in HYBRID_CONFIG_FILES
            or low.endswith('.map'))


def _collect_roots_for_scan(scan_root, scan_type, app_root=None):
    """Return directories to search for JS/hybrid files."""
    if scan_type == 'apk':
        roots = [scan_root / 'assets', scan_root / 'res' / 'raw']
        return [r for r in roots if r.is_dir() and not is_pipe_or_link(r)]
    if scan_type == 'ipa' and app_root:
        aroot = Path(app_root)
        if aroot.is_dir() and not is_pipe_or_link(aroot):
            return [aroot]
    return [scan_root]


def _detect_frameworks_from_package_json(scan_root, frameworks):
    """Inspect root package.json for JS/mobile framework dependencies."""
    pkg_json = scan_root / 'package.json'
    if not _is_valid_candidate(scan_root, pkg_json):
        return
    try:
        data = json.loads(pkg_json.read_text('utf-8', 'ignore'))
    except Exception:
        return
    if not isinstance(data, dict):
        return
    deps = set()
    for section in ('dependencies', 'devDependencies'):
        sec = data.get(section)
        if isinstance(sec, dict):
            deps.update(sec.keys())
    if 'react-native' in deps:
        frameworks.add('React Native')
    if 'expo' in deps:
        frameworks.add('Expo')
    if '@capacitor/core' in deps or '@capacitor/android' in deps:
        frameworks.add('Capacitor')
    if any(d.startswith(('cordova-', '@ionic/')) for d in deps):
        frameworks.add('Cordova / Ionic')
    if '@nativescript/core' in deps or 'tns-core-modules' in deps:
        frameworks.add('NativeScript')


def _classify_path_framework(rel_posix, frameworks):
    """Infer hybrid framework from relative asset paths."""
    low = rel_posix.lower()
    if low.endswith(('index.android.bundle', 'main.jsbundle', 'index.ios.bundle')):
        frameworks.add('React Native')
    elif '/www/' in f'/{low}' and (low.endswith('.html') or 'cordova' in low):
        frameworks.add('Cordova / Ionic')
    elif 'capacitor.config.json' in low or '/public/index.html' in f'/{low}':
        frameworks.add('Capacitor')
    elif '/app/bundle.js' in f'/{low}' or '/app/vendor.js' in f'/{low}':
        frameworks.add('NativeScript')
    elif low.endswith(('app.manifest', 'exshell.plist', 'expo.plist')):
        frameworks.add('Expo')


def _make_finding(description, severity, cvss, cwe, owasp, masvs, files_dict):
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


def _check_cordova_config(cfg_path, rel_path, findings):
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
                _make_finding(
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
                    _make_finding(
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


def _check_capacitor_config(cfg_path, rel_path, findings):
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
            _make_finding(
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
            _make_finding(
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


def _check_expo_config(cfg_path, rel_path, findings, secrets):
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
            _make_finding(
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
            _make_finding(
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
            _make_finding(
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


def _extract_js_urls_emails_secrets(file_path, rel_path, urls_list, urls_nf,
                                    emails_nf, secrets_set, extra_strings=None):
    """Extract URLs, emails, and high-entropy secrets from JS or HBC strings."""
    try:
        content = ''
        if file_path and file_path.is_file() and (
                file_path.stat().st_size <= MAX_URL_SCAN_BYTES):
            content = file_path.read_text('utf-8', 'ignore')
        elif extra_strings:
            content = '\n'.join(extra_strings[:20000])
        if not content:
            return
        url_text = content.translate(str.maketrans({"'": '"', '`': '"'}))
        urls, u_nf, e_nf = url_n_email_extract(url_text, rel_path)
        urls_list.extend(urls)
        urls_nf.extend(u_nf)
        emails_nf.extend(e_nf)
        candidate_strings = set()
        if extra_strings:
            for s in extra_strings[:20000]:
                if 8 <= len(s) <= 256 and s[0].isalnum():
                    candidate_strings.add(s)
        else:
            for match in STRINGS_REGEX.finditer(content, re.MULTILINE):
                s = match.group()
                if 8 <= len(s) <= 256 and s[0].isalnum():
                    candidate_strings.add(s)
        if candidate_strings:
            secrets_set.update(get_secrets(candidate_strings))
    except Exception:
        pass


def _cap_finding_lines(findings):
    """Ensure line lists per file stay compact for the source viewer."""
    for details in findings.values():
        files_map = details.get('files', {})
        for fpath, line_str in list(files_map.items()):
            parts = []
            seen = set()
            for tok in str(line_str).split(','):
                tok = tok.strip()
                if tok.isdigit() and tok not in seen:
                    seen.add(tok)
                    parts.append(tok)
                    if len(parts) >= 25:
                        break
            files_map[fpath] = ','.join(parts) if parts else '1'


CHUNK_LINES = 50000
MAX_CHUNK_THRESHOLD_BYTES = 3 * 1024 * 1024


def _expand_file_chunks(fpath):
    """Split huge JS/Hermes files into line-offset-padded chunks to bound RAM."""
    size = fpath.stat().st_size
    text = fpath.read_text('utf-8', 'ignore')
    if size <= MAX_CHUNK_THRESHOLD_BYTES:
        return [(fpath, text)]
    lines = text.splitlines()
    chunks = []
    for start_idx in range(0, len(lines), CHUNK_LINES):
        body = '\n'.join(lines[start_idx:start_idx + CHUNK_LINES])
        prefix = '\n' * start_idx
        chunks.append((fpath, prefix + body))
    return chunks


def _scan_js_files_with_sast(scan_files, rel_base):
    """Run Tree-sitter JS/TS rules via SastEngine on collected files."""
    if not scan_files:
        return {}
    rules_path = (
        Path(settings.BASE_DIR)
        / 'StaticAnalyzer'
        / 'views'
        / 'common'
        / 'rules'
        / 'js_rules.yaml'
    )
    if not rules_path.is_file():
        return {}
    root_prefix = rel_base.as_posix().rstrip('/') + '/'
    options = {
        'match_rules': rules_path.as_posix(),
        'match_extensions': JS_SOURCE_EXTS | {'.bundle', '.jsbundle'},
        'ts_extension_map': {
            '.bundle': 'javascript',
            '.jsbundle': 'javascript',
        },
    }
    sast = SastEngine(options, root_prefix)
    file_data = []
    for fpath in scan_files:
        try:
            if fpath.stat().st_size <= MAX_JS_FILE_BYTES:
                file_data.extend(_expand_file_chunks(fpath))
        except OSError:
            continue
    if not file_data:
        return {}
    findings = sast.run_rules(file_data, rules_path.as_posix())
    _cap_finding_lines(findings)
    return findings


def _inspect_candidate_file(checksum, pfile, scan_root, rel_base, scan_type,
                            state):
    """Classify and collect a single candidate file under scan_root."""
    rel_to_base = pfile.relative_to(rel_base).as_posix()
    _classify_path_framework(rel_to_base, state['frameworks'])
    name_low = pfile.name.lower()
    suffix_low = pfile.suffix.lower()

    if name_low == 'config.xml':
        _check_cordova_config(pfile, rel_to_base, state['config_findings'])
        return
    if name_low == 'capacitor.config.json':
        state['frameworks'].add('Capacitor')
        _check_capacitor_config(pfile, rel_to_base, state['config_findings'])
        return
    if name_low in EXPO_CONFIG_FILES:
        _check_expo_config(
            pfile, rel_to_base, state['config_findings'], state['secrets'])
        return
    if suffix_low == '.map' and scan_type in ('apk', 'ipa'):
        state['sourcemaps'][rel_to_base] = '1'
        return

    if suffix_low not in JS_SOURCE_EXTS and suffix_low not in BUNDLE_EXTS:
        return

    is_hbc, hbc_ver = is_hermes_bytecode(pfile)
    if is_hbc:
        state['frameworks'].add('React Native (Hermes)')
        state['hermes']['detected'] = True
        state['hermes']['version'] = hbc_ver
        state['hermes']['bundles'].append(rel_to_base)
        hbc_strings = _extract_hermes_strings(pfile)
        dec_file = decompile_hermes_bundle(checksum, pfile, scan_root)
        if dec_file:
            state['hermes']['decompiled'] = True
            state['scan_files'].append(dec_file)
            dec_rel = dec_file.relative_to(rel_base).as_posix()
            state['hermes']['dec_bundles'].append(dec_rel)
            state['source_files'].append(dec_rel)
            _extract_js_urls_emails_secrets(
                dec_file, dec_rel, state['urls_list'], state['urls'],
                state['emails'], state['secrets'], hbc_strings)
        else:
            _extract_js_urls_emails_secrets(
                None, rel_to_base, state['urls_list'], state['urls'],
                state['emails'], state['secrets'], hbc_strings)
        return

    state['source_files'].append(rel_to_base)
    if pfile.stat().st_size <= MAX_JS_FILE_BYTES:
        if suffix_low in BEAUTIFY_EXTS:
            try:
                raw_js = pfile.read_text('utf-8', 'ignore')
                if is_minified_js(raw_js):
                    pfile.write_text(
                        beautify_minified_js(raw_js), encoding='utf-8')
            except OSError:
                pass
        state['scan_files'].append(pfile)
        _extract_js_urls_emails_secrets(
            pfile, rel_to_base, state['urls_list'], state['urls'],
            state['emails'], state['secrets'])


def analyze_js(checksum, scan_root, scan_type, app_root=None, rel_base=None):
    """Collect and analyze JS/TS, hybrid configs, and Hermes bundles."""
    scan_root = Path(scan_root)
    rel_base = Path(rel_base) if rel_base else scan_root
    state = {
        'frameworks': set(),
        'hermes': {
            'detected': False,
            'version': None,
            'decompiled': False,
            'bundles': [],
            'dec_bundles': [],
        },
        'scan_files': [],
        'source_files': [],
        'config_findings': {},
        'sourcemaps': {},
        'urls_list': [],
        'urls': [],
        'emails': [],
        'secrets': set(),
    }
    try:
        if not scan_root.exists() or is_pipe_or_link(scan_root):
            return _finalize_state(state, {})
        _detect_frameworks_from_package_json(scan_root, state['frameworks'])
        roots = _collect_roots_for_scan(scan_root, scan_type, app_root)
        if scan_type == 'apk':
            xml_cfg = scan_root / 'res' / 'xml' / 'config.xml'
            if _is_valid_candidate(scan_root, xml_cfg):
                _inspect_candidate_file(
                    checksum, xml_cfg, scan_root, rel_base, scan_type, state)

        for rdir in roots:
            for pfile in _iter_files(rdir):
                if (not _is_analysis_name(pfile.name)
                        or not _is_valid_candidate(scan_root, pfile)):
                    continue
                _inspect_candidate_file(
                    checksum, pfile, scan_root, rel_base, scan_type, state)

        if state['sourcemaps']:
            state['config_findings']['js_sourcemap_exposed'] = _make_finding(
                'JavaScript source map (.map) file is packaged inside the '
                'application archive, exposing original unminified source '
                'code and internal file paths.',
                'warning',
                5.3,
                'CWE-540: Inclusion of Sensitive Information in Source Code',
                'M8: Security Misconfiguration',
                'MSTG-CODE-3',
                state['sourcemaps'],
            )

        sast_findings = {}
        if state['scan_files']:
            msg = 'Running JavaScript / Hybrid Code Analysis'
            logger.info(msg)
            append_scan_status(checksum, msg)
            sast_findings = _scan_js_files_with_sast(
                state['scan_files'], rel_base)
    except Exception as exp:
        msg = 'JavaScript / Hybrid Code Analysis failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
        sast_findings = {}

    return _finalize_state(state, sast_findings)


def _finalize_state(state, sast_findings):
    """Merge config and SAST findings and return structured output."""
    merged = dict(state['config_findings'])
    for rule_id, details in (sast_findings or {}).items():
        if rule_id in merged:
            merged[rule_id]['files'].update(details.get('files', {}))
        else:
            merged[rule_id] = details
    source_files = None
    if len(state['source_files']) <= MAX_LISTED_JS_FILES:
        source_files = sorted(set(state['source_files']))
    return {
        'source_files': source_files,
        'frameworks': sorted(state['frameworks']),
        'hermes': state['hermes'] if state['hermes']['detected'] else {},
        'findings': merged,
        'urls_list': state['urls_list'],
        'urls': state['urls'],
        'emails': state['emails'],
        'secrets': list(state['secrets']),
    }


def _is_listable_file(base_dir, pfile, rel_posix):
    """Return True if pfile is a safe regular file inside base_dir."""
    return (is_safe_path(base_dir, pfile, rel_posix)
            and not is_pipe_or_link(pfile)
            and pfile.is_file())


def cached_js_source_files(checksum):
    """Return the JS file list recorded at scan time, or None."""
    entry = StaticAnalyzerAndroid.objects.filter(
        MD5=checksum).values_list('JS_ANALYSIS', flat=True).first()
    try:
        files = python_dict(entry).get('source_files')
    except Exception:
        return None
    return files if isinstance(files, list) else None


def list_js_source_files(base_dir, cached=None):
    """Return sorted relative paths of JS/TS/Hybrid files under base_dir."""
    base_dir = Path(base_dir)
    if not base_dir.exists() or is_pipe_or_link(base_dir):
        return []
    found = []
    if cached is not None:
        for rel_posix in cached:
            if not isinstance(rel_posix, str) or is_path_traversal(rel_posix):
                continue
            if _is_listable_file(base_dir, base_dir / rel_posix, rel_posix):
                found.append(rel_posix)
        return sorted(found)
    for pfile in _iter_files(base_dir):
        name = pfile.name.lower()
        if (not _is_js_name(name)
                or name.endswith('.hbc')
                or name.endswith('.raw.dec.js')):
            continue
        rel_posix = pfile.relative_to(base_dir).as_posix()
        if not _is_listable_file(base_dir, pfile, rel_posix):
            continue
        is_hbc, _ = is_hermes_bytecode(pfile)
        if is_hbc:
            continue
        found.append(rel_posix)
    return sorted(found)


def analyze_android_js(checksum, app_dir, typ):
    """Run JS/Hybrid analysis for an Android APK or source ZIP."""
    base_dir = Path(settings.UPLD_DIR) / checksum
    target_root = base_dir if base_dir.exists() else Path(app_dir)
    mode = 'apk' if typ == 'apk' else 'zip'
    return analyze_js(
        checksum,
        target_root,
        mode,
        rel_base=target_root,
    )


def analyze_ios_js(checksum, app_dic, scan_type):
    """Run JS/Hybrid analysis for an iOS IPA or source ZIP."""
    if scan_type == 'ipa':
        bin_dir = Path(app_dic['bin_dir'])
        app_root = Path(app_dic['app_root'])
        return analyze_js(
            checksum,
            bin_dir,
            'ipa',
            app_root=app_root,
            rel_base=bin_dir,
        )
    scan_root = Path(app_dic['app_dir'])
    return analyze_js(
        checksum,
        scan_root,
        'zip',
        rel_base=scan_root,
    )
