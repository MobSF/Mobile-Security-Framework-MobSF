# -*- coding: utf_8 -*-
"""JavaScript, TypeScript, Hybrid & Hermes analysis entry points."""
import logging
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.security import is_pipe_or_link
from mobsf.MobSF.utils import append_scan_status
from mobsf.StaticAnalyzer.views.common.js_analysis.configs import (
    check_capacitor_config,
    check_cordova_config,
    check_expo_config,
    make_finding,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.constants import (
    BEAUTIFY_EXTS,
    BUNDLE_EXTS,
    EXPO_CONFIG_FILES,
    EXPO_DEV_CLIENT_DIRS,
    EXPO_DEV_CLIENT_FILES,
    JS_SOURCE_EXTS,
    MAX_JS_FILE_BYTES,
    MAX_LISTED_JS_FILES,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.files import (
    collect_roots_for_scan,
    is_analysis_name,
    is_valid_candidate,
    iter_files,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.frameworks import (
    classify_path_framework,
    detect_frameworks_from_package_json,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.hermes import (
    decompile_hermes_bundle,
    extract_hermes_strings,
    is_hermes_bytecode,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.sast import (
    extract_js_urls_emails_secrets,
    scan_js_files_with_sast,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.viewer import (
    beautify_minified_js,
    is_minified_js,
)


logger = logging.getLogger(__name__)


def _inspect_candidate_file(checksum, pfile, scan_root, rel_base, scan_type,
                            state):
    """Classify and collect a single candidate file under scan_root."""
    rel_to_base = pfile.relative_to(rel_base).as_posix()
    classify_path_framework(rel_to_base, state['frameworks'])
    name_low = pfile.name.lower()
    suffix_low = pfile.suffix.lower()

    parts_low = {p.lower() for p in Path(rel_to_base).parts[:-1]}
    if (name_low in EXPO_DEV_CLIENT_FILES
            or parts_low & EXPO_DEV_CLIENT_DIRS):
        state['dev_client'][rel_to_base] = '1'
        return
    if name_low == 'config.xml':
        check_cordova_config(pfile, rel_to_base, state['config_findings'])
        return
    if name_low == 'capacitor.config.json':
        state['frameworks'].add('Capacitor')
        check_capacitor_config(pfile, rel_to_base, state['config_findings'])
        return
    if name_low in EXPO_CONFIG_FILES:
        check_expo_config(
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
        hbc_strings = extract_hermes_strings(pfile)
        dec_file = decompile_hermes_bundle(checksum, pfile, scan_root)
        if dec_file:
            state['hermes']['decompiled'] = True
            state['scan_files'].append(dec_file)
            dec_rel = dec_file.relative_to(rel_base).as_posix()
            state['hermes']['dec_bundles'].append(dec_rel)
            state['source_files'].append(dec_rel)
            extract_js_urls_emails_secrets(
                dec_file, dec_rel, state['urls_list'], state['urls'],
                state['emails'], state['secrets'], hbc_strings)
        else:
            extract_js_urls_emails_secrets(
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
        extract_js_urls_emails_secrets(
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
        'dev_client': {},
        'urls_list': [],
        'urls': [],
        'emails': [],
        'secrets': set(),
    }
    try:
        if not scan_root.exists() or is_pipe_or_link(scan_root):
            return _finalize_state(state, {})
        detect_frameworks_from_package_json(scan_root, state['frameworks'])
        roots = collect_roots_for_scan(scan_root, scan_type, app_root)
        if scan_type == 'apk':
            xml_cfg = scan_root / 'res' / 'xml' / 'config.xml'
            if is_valid_candidate(scan_root, xml_cfg):
                _inspect_candidate_file(
                    checksum, xml_cfg, scan_root, rel_base, scan_type, state)

        for rdir in roots:
            for pfile in iter_files(rdir):
                if (not is_analysis_name(pfile.name)
                        or not is_valid_candidate(scan_root, pfile)):
                    continue
                _inspect_candidate_file(
                    checksum, pfile, scan_root, rel_base, scan_type, state)

        if state['sourcemaps']:
            state['config_findings']['js_sourcemap_exposed'] = make_finding(
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
        if state['dev_client']:
            state['config_findings']['js_expo_dev_client_bundled'] = (
                make_finding(
                    'expo-dev-launcher / expo-dev-menu bundles are packaged '
                    'in the app. Development client builds can load '
                    'JavaScript from arbitrary development servers; confirm '
                    'this is not a distributed release build.',
                    'info',
                    0,
                    'CWE-489: Active Debug Code',
                    'M7: Insufficient Binary Protection',
                    'MSTG-CODE-2',
                    state['dev_client'],
                ))

        sast_findings = {}
        if state['scan_files']:
            msg = 'Running JavaScript / Hybrid Code Analysis'
            logger.info(msg)
            append_scan_status(checksum, msg)
            sast_findings = scan_js_files_with_sast(
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
