# -*- coding: utf_8 -*-
"""SBOM component extraction and OSV.dev vulnerability scanning."""
import hashlib
import json
import logging
from pathlib import Path
from plistlib import load as plist_load
import re

from django.conf import settings

import requests

from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    is_internet_available,
    settings_enabled,
    upstream_proxy,
)

logger = logging.getLogger(__name__)

_MAX_SBOM_FILE_SIZE = 2 * 1024 * 1024
_MAX_OSV_QUERIES = 1000
_MAX_OSV_VULN_FETCH = 40
_VALID_VERSION_RE = re.compile(r'^[0-9][0-9A-Za-z._+-]{0,63}$')
_VALID_OSV_ID_RE = re.compile(r'^[A-Za-z0-9._-]{3,64}$')
_POM_DEP_LINE_RE = re.compile(
    r'([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):(?:jar|aar):([0-9][0-9A-Za-z._+-]*)')
_GRADLE_COORD_RE = re.compile(
    r'["\']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][0-9A-Za-z._+-]+)["\']')
_TOML_VERSION_REF_RE = re.compile(
    r'^\s*([A-Za-z0-9_.-]+)\s*=\s*["\']([0-9][0-9A-Za-z._+-]+)["\']')
_TOML_MODULE_RE = re.compile(
    r'module\s*=\s*["\']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)["\']'
    r'[^}\n]*?version(?:\.ref)?\s*=\s*["\']([A-Za-z0-9_.-]+)["\']')
_TOML_GROUP_NAME_RE = re.compile(
    r'group\s*=\s*["\']([A-Za-z0-9_.-]+)["\'][^}\n]*?'
    r'name\s*=\s*["\']([A-Za-z0-9_.-]+)["\'][^}\n]*?'
    r'version(?:\.ref)?\s*=\s*["\']([A-Za-z0-9_.-]+)["\']')
_OKHTTP_VER_RE = re.compile(r'\bokhttp/([0-9]+\.[0-9]+\.[0-9]+)\b')
_GSON_VER_RE = re.compile(r'\bGSON\s+([0-9]+\.[0-9]+\.[0-9]+)\b')
_PODFILE_LOCK_ITEM_RE = re.compile(
    r'^  - ([A-Za-z0-9_+-]+)(?:/[A-Za-z0-9_+-]+)* \(([0-9][0-9A-Za-z._+-]*)\)')
_CARTFILE_RESOLVED_RE = re.compile(
    r'^\s*github\s+"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"\s+"v?([0-9][0-9A-Za-z._+-]*)"')
_GITHUB_REPO_RE = re.compile(
    r'github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$')

# Common iOS/CocoaPods frameworks to GitHub repositories for offline/fast OSV
_KNOWN_IOS_REPOS = {
    'AFNetworking': 'AFNetworking/AFNetworking',
    'Alamofire': 'Alamofire/Alamofire',
    'CocoaLumberjack': 'CocoaLumberjack/CocoaLumberjack',
    'DTPagerController': 'tungvoduc/DTPagerController',
    'FSCalendar': 'WenchaoD/FSCalendar',
    'FirebaseAnalytics': 'firebase/firebase-ios-sdk',
    'FirebaseAuth': 'firebase/firebase-ios-sdk',
    'FirebaseCore': 'firebase/firebase-ios-sdk',
    'FirebaseCoreExtension': 'firebase/firebase-ios-sdk',
    'FirebaseCoreInternal': 'firebase/firebase-ios-sdk',
    'FirebaseCrashlytics': 'firebase/firebase-ios-sdk',
    'FirebaseFirestore': 'firebase/firebase-ios-sdk',
    'FirebaseInstallations': 'firebase/firebase-ios-sdk',
    'FirebaseMessaging': 'firebase/firebase-ios-sdk',
    'FirebaseRemoteConfig': 'firebase/firebase-ios-sdk',
    'FirebaseRemoteConfigInterop': 'firebase/firebase-ios-sdk',
    'FirebaseSessions': 'firebase/firebase-ios-sdk',
    'FirebaseStorage': 'firebase/firebase-ios-sdk',
    'GoogleDataTransport': 'google/GoogleDataTransport',
    'GoogleSignIn': 'google/GoogleSignIn-iOS',
    'GoogleUtilities': 'google/GoogleUtilities',
    'HMSegmentedControl': 'HeshamMegid/HMSegmentedControl',
    'IQKeyboardManager': 'hackiftekhar/IQKeyboardManager',
    'IQKeyboardManagerSwift': 'hackiftekhar/IQKeyboardManager',
    'JWTDecode': 'auth0/JWTDecode.swift',
    'KeychainAccess': 'kishikawakatsumi/KeychainAccess',
    'Kingfisher': 'onevcat/Kingfisher',
    'Lottie': 'airbnb/lottie-ios',
    'MBProgressHUD': 'jdg/MBProgressHUD',
    'MSAL': 'AzureAD/microsoft-authentication-library-for-objc',
    'Moya': 'Moya/Moya',
    'ObjectMapper': 'tristanhimmelman/ObjectMapper',
    'OneSignal': 'OneSignal/OneSignal-iOS-SDK',
    'Promises': 'google/promises',
    'FBLPromises': 'google/promises',
    'Reachability': 'ashleymills/Reachability.swift',
    'Realm': 'realm/realm-swift',
    'RealmSwift': 'realm/realm-swift',
    'RxCocoa': 'ReactiveX/RxSwift',
    'RxSwift': 'ReactiveX/RxSwift',
    'SDWebImage': 'SDWebImage/SDWebImage',
    'SDWebImageSwiftUI': 'SDWebImage/SDWebImageSwiftUI',
    'SVProgressHUD': 'SVProgressHUD/SVProgressHUD',
    'SnapKit': 'SnapKit/SnapKit',
    'SocketIO': 'socketio/socket.io-client-swift',
    'Starscream': 'daltoniam/Starscream',
    'SwiftProtobuf': 'apple/swift-protobuf',
    'SwiftSoup': 'scinfu/SwiftSoup',
    'SwiftyJSON': 'SwiftyJSON/SwiftyJSON',
    'SwiftyRSA': 'TakeScoop/SwiftyRSA',
    'TrustKit': 'datatheorem/TrustKit',
    'Vapor': 'vapor/vapor',
    'XMLCoder': 'CoreOffice/XMLCoder',
    'nanopb': 'nanopb/nanopb',
    'netfox': 'kasketis/netfox',
}
_POD_REPO_CACHE = dict(_KNOWN_IOS_REPOS)


def _safe_read_text(root, path):
    """Safely read a bounded text file inside root."""
    try:
        rel = path.relative_to(root)
        if (not path.is_file()
                or is_pipe_or_link(path)
                or not is_safe_path(root, path, rel)
                or path.stat().st_size > _MAX_SBOM_FILE_SIZE):
            return None
        return path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return None


def _valid_version(version):
    """Return True if version is a valid concrete version string."""
    return bool(
        isinstance(version, str)
        and version != 'dynamic'
        and _VALID_VERSION_RE.match(version.strip()))


def _parse_version_stem(stem):
    """Parse META-INF/<stem>.version into (group, artifact)."""
    if stem.startswith('kotlinx_'):
        return 'org.jetbrains.kotlinx', stem.replace('_', '-')
    if '_' in stem:
        group, name = stem.split('_', 1)
        if '.' in group and name:
            return group, name
    name = stem.replace('_', '-')
    if name.startswith('kotlinx-'):
        return 'org.jetbrains.kotlinx', name
    return '', ''


def extract_android_components(app_dir, file_data=None):
    """Extract Android SBOM strings and structured OSV components."""
    root = Path(app_dir)
    versioned = set()
    components = {}

    def _add(ecosystem, pkg, version, display=None):
        version = version.strip()
        if not pkg:
            return
        if version == 'dynamic':
            versioned.add(f'{display or pkg}@dynamic')
            return
        if not _valid_version(version):
            return
        versioned.add(f'{display or pkg}@{version}')
        components[(ecosystem, pkg, version)] = {
            'ecosystem': ecosystem,
            'name': pkg,
            'version': version,
            'display': display or pkg,
        }

    if not root.exists():
        return [], []

    # 1. META-INF/*.version
    for vfile in root.rglob('*.version'):
        if 'META-INF' not in vfile.parts:
            continue
        text = _safe_read_text(root, vfile)
        if not text:
            continue
        raw_ver = text.strip()
        version = 'dynamic' if raw_ver.startswith('task') else raw_ver
        group, name = _parse_version_stem(vfile.stem)
        if group and name:
            _add('Maven', f'{group}:{name}', version)

    # 2. pom.properties and Google Play / Firebase client .properties
    for pfile in root.rglob('*.properties'):
        if 'apktool_out' in pfile.parts or 'java_source' in pfile.parts:
            continue
        text = _safe_read_text(root, pfile)
        if not text:
            continue
        kv = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            k, v = line.split('=', 1)
            kv[k.strip()] = v.strip()
        if pfile.name == 'pom.properties':
            g = kv.get('groupId', '')
            a = kv.get('artifactId', '')
            v = kv.get('version', '')
            if g and a and v:
                _add('Maven', f'{g}:{a}', v)
        elif 'client' in kv and 'version' in kv:
            client = kv['client']
            ver = kv['version']
            if client.startswith('firebase-'):
                group = 'com.google.firebase'
            elif (client.startswith('play-services-')
                    or client in {'integrity', 'billing'}):
                group = 'com.google.android.gms'
            elif client.startswith('transport-'):
                group = 'com.google.android.datatransport'
            else:
                continue
            _add('Maven', f'{group}:{client}', ver)

    # 3. META-INF/DEPENDENCIES
    for dep_file in root.rglob('DEPENDENCIES'):
        if 'META-INF' not in dep_file.parts or 'apktool_out' in dep_file.parts:
            continue
        text = _safe_read_text(root, dep_file)
        if not text:
            continue
        for match in _POM_DEP_LINE_RE.finditer(text):
            g, a, v = match.group(1), match.group(2), match.group(3)
            _add('Maven', f'{g}:{a}', v)

    # 4. Gradle version catalogs and build.gradle(.kts) for source ZIPs
    for toml_file in root.rglob('*.versions.toml'):
        text = _safe_read_text(root, toml_file)
        if not text:
            continue
        versions_map = dict(_TOML_VERSION_REF_RE.findall(text))
        for g, a, vref in _TOML_MODULE_RE.findall(text):
            ver = versions_map.get(vref, vref)
            _add('Maven', f'{g}:{a}', ver)
        for g, a, vref in _TOML_GROUP_NAME_RE.findall(text):
            ver = versions_map.get(vref, vref)
            _add('Maven', f'{g}:{a}', ver)

    for gfile in (*root.rglob('build.gradle'), *root.rglob('build.gradle.kts')):
        text = _safe_read_text(root, gfile)
        if not text:
            continue
        for g, a, v in _GRADLE_COORD_RE.findall(text):
            _add('Maven', f'{g}:{a}', v)

    # 5. Embedded SDK version constants in decompiled code (OkHttp & Gson)
    for item in file_data or ():
        if not isinstance(item, (tuple, list)) or len(item) < 2:
            continue
        fpath, content = item[0], item[1]
        if not isinstance(content, str):
            continue
        lower_path = fpath.lower()
        if ('okhttp' in lower_path or 'bridgeinterceptor' in lower_path
                or 'realconnection' in lower_path or 'util' in lower_path):
            for match in _OKHTTP_VER_RE.finditer(content):
                _add('Maven', 'com.squareup.okhttp3:okhttp', match.group(1))
        if 'gson' in lower_path or 'reflectionhelper' in lower_path:
            for match in _GSON_VER_RE.finditer(content):
                _add('Maven', 'com.google.code.gson:gson', match.group(1))

    return sorted(versioned), list(components.values())


def _resolve_pod_github_repo(pod_name):
    """Resolve a CocoaPod name to 'org/repo' on GitHub using cache or CDN."""
    if pod_name in _POD_REPO_CACHE:
        return _POD_REPO_CACHE[pod_name]
    if (not settings_enabled('SBOM_VULN_SCAN')
            or not is_internet_available()
            or not re.match(r'^[A-Za-z0-9_+-]{2,64}$', pod_name)):
        _POD_REPO_CACHE[pod_name] = None
        return None
    try:
        proxies, verify = upstream_proxy('https')
        md5_prefix = hashlib.md5(
            pod_name.encode('utf-8'),
            usedforsecurity=False).hexdigest()
        p1, p2, p3 = md5_prefix[0], md5_prefix[1], md5_prefix[2]
        shard_url = (
            f'{settings.COCOAPODS_CDN_URL}/'
            f'all_pods_versions_{p1}_{p2}_{p3}.txt')
        resp = requests.get(
            shard_url,
            timeout=5,
            proxies=proxies,
            verify=verify)
        if resp.status_code != 200:
            _POD_REPO_CACHE[pod_name] = None
            return None
        prefix = f'{pod_name}/'
        line = next(
            (ln for ln in resp.text.splitlines() if ln.startswith(prefix)),
            None)
        if not line:
            _POD_REPO_CACHE[pod_name] = None
            return None
        latest_ver = line.rsplit('/', 1)[-1].strip()
        spec_url = (
            f'{settings.COCOAPODS_CDN_URL}/Specs/'
            f'{p1}/{p2}/{p3}/{pod_name}/{latest_ver}/{pod_name}.podspec.json')
        spec_resp = requests.get(
            spec_url,
            timeout=5,
            proxies=proxies,
            verify=verify)
        if spec_resp.status_code != 200:
            _POD_REPO_CACHE[pod_name] = None
            return None
        spec = spec_resp.json()
        git_url = (spec.get('source') or {}).get('git') or spec.get('homepage', '')
        match = _GITHUB_REPO_RE.search(str(git_url))
        repo = match.group(1) if match else None
        _POD_REPO_CACHE[pod_name] = repo
        return repo
    except Exception:
        _POD_REPO_CACHE[pod_name] = None
        return None


def extract_ios_components(app_dic):
    """Extract iOS SBOM strings and structured OSV components."""
    scan_dir = app_dic.get('app_root') or app_dic.get('app_dir')
    if not scan_dir:
        return [], []
    root = Path(scan_dir)
    app_dir = Path(app_dic.get('app_dir', scan_dir))
    versioned = set()
    components = {}
    pods_to_resolve = set()

    def _add_repo(repo, version, display_name=None):
        version = version.strip().lstrip('v')
        if not repo or not _valid_version(version):
            return
        disp = display_name or repo
        versioned.add(f'{disp}@{version}')
        for eco, qname, qver in (
            ('SwiftURL', f'github.com/{repo}', version),
            ('GIT', f'https://github.com/{repo}', version),
            ('GIT', f'https://github.com/{repo}', f'v{version}'),
        ):
            components[(eco, qname, qver)] = {
                'ecosystem': eco,
                'name': qname,
                'version': qver,
                'display': disp,
                'installed_version': version,
            }

    # 1. Embedded .framework/Info.plist inside IPA
    if root.exists():
        for plist_path in sorted(root.rglob('*.framework/Info.plist')):
            try:
                rel = plist_path.relative_to(root)
                if (not plist_path.is_file()
                        or is_pipe_or_link(plist_path)
                        or not is_safe_path(root, plist_path, rel)
                        or any(p.endswith('.bundle') for p in plist_path.parts)):
                    continue
                with open(plist_path, 'rb') as fp:
                    plist_obj = plist_load(fp)
                if not isinstance(plist_obj, dict):
                    continue
                bid = str(plist_obj.get('CFBundleIdentifier') or '').strip()
                if bid.startswith('com.apple.'):
                    continue
                fw_name = (
                    plist_obj.get('CFBundleExecutable')
                    or plist_obj.get('CFBundleName')
                    or plist_path.parent.stem)
                fw_name = str(fw_name).strip()
                ver = str(
                    plist_obj.get('CFBundleShortVersionString')
                    or plist_obj.get('CFBundleVersion')
                    or '').strip()
                if (not fw_name
                        or fw_name in {'App', 'Flutter'}
                        or not _valid_version(ver)):
                    continue
                versioned.add(f'{fw_name}@{ver}')
                pods_to_resolve.add((fw_name, ver))
            except Exception:
                continue

    # 2. Podfile.lock, Package.resolved, Cartfile.resolved in source ZIPs
    for search_root in {root, app_dir}:
        if not search_root.exists():
            continue
        for podlock in search_root.rglob('Podfile.lock'):
            text = _safe_read_text(search_root, podlock)
            if not text:
                continue
            for line in text.splitlines():
                if line.startswith('DEPENDENCIES:'):
                    break
                match = _PODFILE_LOCK_ITEM_RE.match(line)
                if match:
                    pod_name, ver = match.group(1), match.group(2)
                    if _valid_version(ver):
                        versioned.add(f'{pod_name}@{ver}')
                        pods_to_resolve.add((pod_name, ver))

        for pkg_res in search_root.rglob('Package.resolved'):
            text = _safe_read_text(search_root, pkg_res)
            if not text:
                continue
            try:
                obj = json.loads(text)
                pins = (
                    obj.get('pins')
                    or (obj.get('object') or {}).get('pins')
                    or [])
                for pin in pins:
                    loc = (
                        pin.get('location')
                        or pin.get('repositoryURL')
                        or '')
                    state = pin.get('state') or {}
                    ver = state.get('version') or ''
                    ident = (
                        pin.get('identity')
                        or pin.get('package')
                        or '')
                    match = _GITHUB_REPO_RE.search(str(loc))
                    if match and ver:
                        _add_repo(
                            match.group(1),
                            str(ver),
                            display_name=ident or match.group(1))
            except Exception:
                continue

        for cartfile in search_root.rglob('Cartfile.resolved'):
            text = _safe_read_text(search_root, cartfile)
            if not text:
                continue
            for line in text.splitlines():
                match = _CARTFILE_RESOLVED_RE.match(line)
                if match:
                    _add_repo(match.group(1), match.group(2))

    for pod_name, ver in sorted(pods_to_resolve):
        repo = _resolve_pod_github_repo(pod_name)
        if repo:
            _add_repo(repo, ver, display_name=pod_name)

    return sorted(versioned), list(components.values())


def _extract_severity_and_fixed(vuln_detail, pkg_version=None):
    """Extract normalized MobSF severity and fixed version from OSV detail."""
    db_spec = vuln_detail.get('database_specific') or {}
    raw_sev = str(db_spec.get('severity') or '').upper()
    if not raw_sev:
        for aff in vuln_detail.get('affected') or ():
            eco_spec = aff.get('ecosystem_specific') or {}
            if eco_spec.get('severity'):
                raw_sev = str(eco_spec['severity']).upper()
                break
    if raw_sev in {'CRITICAL', 'HIGH'}:
        severity = 'high'
    elif raw_sev in {'MODERATE', 'MEDIUM'}:
        severity = 'warning'
    elif raw_sev == 'LOW':
        severity = 'info'
    else:
        severity = 'warning'

    fixed_versions = []
    for aff in vuln_detail.get('affected') or ():
        for rng in aff.get('ranges') or ():
            for ev in rng.get('events') or ():
                fx = ev.get('fixed')
                if fx and fx not in fixed_versions:
                    fixed_versions.append(str(fx))
    fixed = ', '.join(fixed_versions[:3]) if fixed_versions else 'N/A'
    return severity, fixed


def check_osv_vulnerabilities(components):
    """Query OSV.dev querybatch for vulnerable SBOM components."""
    if (not components
            or not settings_enabled('SBOM_VULN_SCAN')
            or not is_internet_available()):
        return []

    batch = components[:_MAX_OSV_QUERIES]
    payload = {
        'queries': [
            {
                'package': {
                    'ecosystem': c['ecosystem'],
                    'name': c['name'],
                },
                'version': c['version'],
            }
            for c in batch
        ],
    }

    try:
        proxies, verify = upstream_proxy('https')
        resp = requests.post(
            settings.OSV_BATCH_URL,
            json=payload,
            timeout=15,
            proxies=proxies,
            verify=verify)
        if resp.status_code != 200:
            logger.warning(
                'OSV querybatch returned HTTP %s', resp.status_code)
            return []
        results = (resp.json() or {}).get('results') or []
    except Exception:
        logger.exception('Failed to query OSV.dev batch API')
        return []

    vuln_details_cache = {}
    findings = []
    seen_pkg_vulns = set()

    for comp, res in zip(batch, results):
        for vuln_stub in res.get('vulns') or ():
            vid = str(vuln_stub.get('id') or '').strip()
            if not _VALID_OSV_ID_RE.match(vid):
                continue
            disp_pkg = comp.get('display') or comp['name']
            inst_ver = comp.get('installed_version') or comp['version']
            if (disp_pkg, inst_ver, vid) in seen_pkg_vulns:
                continue

            if (vid not in vuln_details_cache
                    and len(vuln_details_cache) < _MAX_OSV_VULN_FETCH):
                try:
                    vresp = requests.get(
                        f'{settings.OSV_VULN_URL}{vid}',
                        timeout=10,
                        proxies=proxies,
                        verify=verify)
                    if vresp.status_code == 200:
                        vuln_details_cache[vid] = vresp.json()
                    else:
                        vuln_details_cache[vid] = {}
                except Exception:
                    vuln_details_cache[vid] = {}

            detail = vuln_details_cache.get(vid) or {}
            aliases = [
                str(a) for a in (detail.get('aliases') or ())
                if isinstance(a, str)
            ]
            # Deduplicate if the same CVE/GHSA was already reported via alias
            canonical_ids = {vid, *aliases}
            if any(
                (disp_pkg, inst_ver, cid) in seen_pkg_vulns
                for cid in canonical_ids
            ):
                continue
            for cid in canonical_ids:
                seen_pkg_vulns.add((disp_pkg, inst_ver, cid))

            severity, fixed = _extract_severity_and_fixed(detail, inst_ver)
            summary = (
                detail.get('summary')
                or (detail.get('details') or '')[:200]
                or 'Known vulnerability reported in OSV database.')

            findings.append({
                'package': disp_pkg,
                'version': inst_ver,
                'ecosystem': comp['ecosystem'],
                'id': vid,
                'aliases': aliases,
                'severity': severity,
                'summary': summary,
                'fixed': fixed,
            })

    return findings


def ios_sbom(app_dic):
    """Extract iOS SBOM and run OSV vulnerability scan."""
    versioned, components = extract_ios_components(app_dic)
    vulns = check_osv_vulnerabilities(components)
    return {
        'sbom_versioned': versioned,
        'sbom_packages': [],
        'sbom_vulnerabilities': vulns,
    }
