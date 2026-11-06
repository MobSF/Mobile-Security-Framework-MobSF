# -*- coding: utf_8 -*-
"""Offline SBOM component extraction for Android and iOS."""
import json
from pathlib import Path
from plistlib import load as plist_load
import re
import tomllib

from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)

_MAX_SBOM_FILE_SIZE = 2 * 1024 * 1024
_MAX_LOCK_NODES = 5000
_VALID_VERSION_RE = re.compile(r'^\d[\w.+-]{0,63}$', re.ASCII)
_POM_DEP_LINE_RE = re.compile(
    r'([\w.-]+):([\w.-]+):(?:jar|aar):(\d[\w.+-]*)', re.ASCII)
_GRADLE_COORD_RE = re.compile(
    r'["\']([\w.-]+):([\w.-]+):(\d[\w.+-]*)["\']', re.ASCII)
_GRADLE_LOCK_LINE_RE = re.compile(
    r'^\s*([\w.-]+):([\w.-]+):(\d[\w.+-]*)=', re.ASCII)
_PODFILE_LOCK_ITEM_RE = re.compile(
    r'^ {2}- ([\w.+-]+)(?:/[\w.+-]+)* \((\d[\w.+-]*)\)', re.ASCII)
_CARTFILE_RESOLVED_RE = re.compile(
    r'^\s*(github|git)\s+"([^"\n]{1,256})"\s+"v?(\d[\w.+-]*)"', re.ASCII)
_GITHUB_REPO_RE = re.compile(
    r'github\.com[:/]([\w.-]+/[\w.-]+?)(?:\.git)?/?$', re.ASCII)
_PUBSPEC_PKG_HEADER_RE = re.compile(r'^ {2}(\w+):$', re.ASCII)
_PUBSPEC_PKG_VERSION_RE = re.compile(
    r'^ {4}version:\s*["\']?(\d[\w.+-]*)["\']?$', re.ASCII)
_CLIENT_PROP_GROUPS = {
    'integrity': 'com.google.android.play',
    'billing': 'com.android.billingclient',
}
_CLIENT_PROP_PREFIXES = (
    ('firebase-', 'com.google.firebase'),
    ('play-services-', 'com.google.android.gms'),
    ('transport-', 'com.google.android.datatransport'),
)


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
    if not isinstance(version, str):
        return False
    ver = version.strip()
    return bool(
        ver
        and ver != 'dynamic'
        and not ver.endswith('+')
        and _VALID_VERSION_RE.match(ver))


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


def _resolve_toml_version_entry(val):
    """Extract a concrete version string from a TOML version entry."""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return str(val.get('strictly') or val.get('require') or '')
    return ''


def _extract_toml_versions_map(raw_versions):
    """Build a version reference map from a TOML [versions] table."""
    if not isinstance(raw_versions, dict):
        return {}
    versions_map = {}
    for key, val in raw_versions.items():
        ver = _resolve_toml_version_entry(val)
        if ver:
            versions_map[key] = ver
    return versions_map


def _parse_toml_library(lib, versions_map, add_fn):
    """Parse one entry under [libraries] in libs.versions.toml."""
    if isinstance(lib, str):
        parts = lib.split(':')
        if len(parts) == 3 and all(parts):
            add_fn(f'{parts[0]}:{parts[1]}', parts[2])
        return
    if not isinstance(lib, dict):
        return
    module = lib.get('module')
    if isinstance(module, str) and ':' in module:
        group, name = module.split(':', 1)
    else:
        group = str(lib.get('group') or '')
        name = str(lib.get('name') or '')
    if not (group and name):
        return
    ver_obj = lib.get('version')
    if isinstance(ver_obj, dict) and isinstance(ver_obj.get('ref'), str):
        ver = versions_map.get(ver_obj['ref'], '')
    else:
        ver = _resolve_toml_version_entry(ver_obj)
    if ver:
        add_fn(f'{group}:{name}', ver)


def _parse_toml_catalog(text, add_fn):
    """Parse a Gradle libs.versions.toml catalog using stdlib tomllib."""
    try:
        data = tomllib.loads(text)
    except Exception:
        return
    if not isinstance(data, dict):
        return
    versions_map = _extract_toml_versions_map(data.get('versions'))
    libraries = data.get('libraries')
    if not isinstance(libraries, dict):
        return
    for lib in libraries.values():
        _parse_toml_library(lib, versions_map, add_fn)


def _parse_pubspec_lock(text, add_fn):
    """Parse Dart/Flutter pubspec.lock line by line without multiline regex."""
    current_pkg = None
    for line in text.splitlines():
        if not line.startswith(' '):
            current_pkg = None
            continue
        hdr = _PUBSPEC_PKG_HEADER_RE.match(line)
        if hdr:
            current_pkg = hdr.group(1)
            continue
        if current_pkg:
            ver_match = _PUBSPEC_PKG_VERSION_RE.match(line)
            if ver_match:
                add_fn(current_pkg, ver_match.group(1))
                current_pkg = None


def _walk_npm_v1_deps(root_deps, add_fn):
    """Traverse top-level and nested v1 dependencies maps iteratively."""
    queue = [root_deps]
    visited = 0
    while queue and visited < _MAX_LOCK_NODES:
        deps = queue.pop()
        if not isinstance(deps, dict):
            continue
        for pkg, meta in deps.items():
            visited += 1
            if visited > _MAX_LOCK_NODES:
                break
            if not isinstance(meta, dict):
                continue
            if meta.get('version'):
                add_fn(pkg, str(meta['version']))
            if isinstance(meta.get('dependencies'), dict):
                queue.append(meta['dependencies'])


def _walk_npm_v2_packages(packages, add_fn):
    """Extract packages from a package-lock.json v2/v3 packages map."""
    if not isinstance(packages, dict):
        return
    for pkg_path, meta in packages.items():
        if (not isinstance(pkg_path, str)
                or not isinstance(meta, dict)
                or not meta.get('version')):
            continue
        if (not pkg_path.startswith('node_modules/')
                and '/node_modules/' not in pkg_path):
            continue
        name = meta.get('name')
        pkg = (
            name.strip()
            if isinstance(name, str) and name.strip()
            else pkg_path.split('node_modules/')[-1]
        )
        if pkg:
            add_fn(pkg, str(meta['version']))


def _extract_cross_platform_lockfiles(root, add_fn):
    """Extract standard Dart/Flutter (pubspec.lock) and npm (package-lock.json)."""
    for publock in root.rglob('pubspec.lock'):
        text = _safe_read_text(root, publock)
        if text:
            _parse_pubspec_lock(text, add_fn)

    for pkglock in root.rglob('package-lock.json'):
        if 'node_modules' in pkglock.parts:
            continue
        text = _safe_read_text(root, pkglock)
        if not text:
            continue
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                _walk_npm_v1_deps(obj.get('dependencies'), add_fn)
                _walk_npm_v2_packages(obj.get('packages'), add_fn)
        except Exception:
            continue


def _extract_meta_inf_versions(root, add_fn):
    """Extract META-INF/*.version files."""
    for vfile in root.rglob('*.version'):
        if 'META-INF' not in vfile.parts or 'apktool_out' in vfile.parts:
            continue
        text = _safe_read_text(root, vfile)
        if not text:
            continue
        raw_ver = text.strip()
        version = 'dynamic' if raw_ver.startswith('task') else raw_ver
        group, name = _parse_version_stem(vfile.stem)
        if group and name:
            add_fn(f'{group}:{name}', version)


def _client_group(client):
    """Resolve Maven group for a client .properties identifier."""
    if client in _CLIENT_PROP_GROUPS:
        return _CLIENT_PROP_GROUPS[client]
    for prefix, group in _CLIENT_PROP_PREFIXES:
        if client.startswith(prefix):
            return group
    return ''


def _parse_kv_properties(text):
    """Parse key=value lines from a .properties file."""
    kv = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            kv[k.strip()] = v.strip()
    return kv


def _extract_android_properties(root, add_fn):
    """Extract pom.properties and Google Play / Firebase client .properties."""
    for pfile in root.rglob('*.properties'):
        if 'apktool_out' in pfile.parts or 'java_source' in pfile.parts:
            continue
        text = _safe_read_text(root, pfile)
        if not text:
            continue
        kv = _parse_kv_properties(text)
        if pfile.name == 'pom.properties':
            g, a, v = kv.get('groupId', ''), kv.get(
                'artifactId', ''), kv.get('version', '')
            if g and a and v:
                add_fn(f'{g}:{a}', v)
        elif 'client' in kv and 'version' in kv:
            group = _client_group(kv['client'])
            if group:
                add_fn(f'{group}:{kv["client"]}', kv['version'])


def _extract_android_gradle_files(root, add_fn):
    """Extract dependencies from DEPENDENCIES, versions.toml, and Gradle files."""
    for dep_file in root.rglob('DEPENDENCIES'):
        if 'META-INF' not in dep_file.parts or 'apktool_out' in dep_file.parts:
            continue
        text = _safe_read_text(root, dep_file)
        if text:
            for match in _POM_DEP_LINE_RE.finditer(text):
                add_fn(f'{match.group(1)}:{match.group(2)}', match.group(3))

    for toml_file in root.rglob('*.versions.toml'):
        text = _safe_read_text(root, toml_file)
        if text:
            _parse_toml_catalog(text, add_fn)

    for gfile in (*root.rglob('build.gradle'), *root.rglob('build.gradle.kts')):
        text = _safe_read_text(root, gfile)
        if text:
            for g, a, v in _GRADLE_COORD_RE.findall(text):
                add_fn(f'{g}:{a}', v)

    for lockfile in root.rglob('*gradle.lockfile'):
        text = _safe_read_text(root, lockfile)
        if not text:
            continue
        for line in text.splitlines():
            match = _GRADLE_LOCK_LINE_RE.match(line)
            if match:
                add_fn(f'{match.group(1)}:{match.group(2)}', match.group(3))


def extract_android_sbom(app_dir):
    """Extract sorted list of versioned Android SBOM packages."""
    root = Path(app_dir)
    if not root.exists():
        return []
    versioned = set()

    def _add(pkg, version):
        version = version.strip()
        if pkg and (version == 'dynamic' or _valid_version(version)):
            versioned.add(f'{pkg}@{version}')

    _extract_meta_inf_versions(root, _add)
    _extract_android_properties(root, _add)
    _extract_android_gradle_files(root, _add)
    _extract_cross_platform_lockfiles(root, _add)
    return sorted(versioned)


def _extract_ios_framework_plist(root, plist_path, add_fn):
    """Extract framework name and version from a single .framework/Info.plist."""
    try:
        rel = plist_path.relative_to(root)
        if (not plist_path.is_file()
                or is_pipe_or_link(plist_path)
                or not is_safe_path(root, plist_path, rel)
                or any(p.endswith('.bundle') for p in plist_path.parts)):
            return
        with open(plist_path, 'rb') as fp:
            plist_obj = plist_load(fp)
        if not isinstance(plist_obj, dict):
            return
        bid = str(plist_obj.get('CFBundleIdentifier') or '').strip()
        if bid.startswith('com.apple.'):
            return
        fw_name = str(
            plist_obj.get('CFBundleExecutable')
            or plist_obj.get('CFBundleName')
            or plist_path.parent.stem).strip()
        ver = str(
            plist_obj.get('CFBundleShortVersionString')
            or plist_obj.get('CFBundleVersion')
            or '').strip()
        if fw_name and fw_name not in {'App', 'Flutter'}:
            add_fn(fw_name, ver)
    except Exception:
        return


def _parse_package_resolved(text, add_fn):
    """Parse SwiftPM Package.resolved JSON (v1, v2, v3)."""
    try:
        obj = json.loads(text)
    except Exception:
        return
    if not isinstance(obj, dict):
        return
    legacy_obj = obj.get('object')
    pins = obj.get('pins')
    if not isinstance(pins, list) and isinstance(legacy_obj, dict):
        pins = legacy_obj.get('pins')
    if not isinstance(pins, list):
        return
    for pin in pins:
        if not isinstance(pin, dict):
            continue
        state = pin.get('state')
        if not isinstance(state, dict):
            continue
        loc = str(pin.get('location') or pin.get('repositoryURL') or '')
        ver = str(state.get('version') or '')
        ident = str(pin.get('identity') or pin.get('package') or '')
        match = _GITHUB_REPO_RE.search(loc)
        name = ident or (match.group(1) if match else '')
        if name and ver:
            add_fn(name, ver)


def _normalize_cartfile_spec(kind, spec):
    """Normalize a Cartfile.resolved dependency specifier."""
    if kind == 'github':
        return spec.strip().strip('/')
    match = _GITHUB_REPO_RE.search(spec)
    if match:
        return match.group(1)
    cleaned = spec.strip().removesuffix('.git').rstrip('/')
    if '://' in cleaned:
        cleaned = cleaned.split('://', 1)[1]
    return cleaned


def _extract_ios_lockfiles_in_dir(search_root, add_fn):
    """Extract Podfile.lock, Package.resolved, Cartfile.resolved in search_root."""
    for podlock in search_root.rglob('Podfile.lock'):
        text = _safe_read_text(search_root, podlock)
        if not text:
            continue
        for line in text.splitlines():
            if line.startswith('DEPENDENCIES:'):
                break
            match = _PODFILE_LOCK_ITEM_RE.match(line)
            if match:
                add_fn(match.group(1), match.group(2))

    for pkg_res in search_root.rglob('Package.resolved'):
        text = _safe_read_text(search_root, pkg_res)
        if text:
            _parse_package_resolved(text, add_fn)

    for cartfile in search_root.rglob('Cartfile.resolved'):
        text = _safe_read_text(search_root, cartfile)
        if not text:
            continue
        for line in text.splitlines():
            match = _CARTFILE_RESOLVED_RE.match(line)
            if match:
                pkg = _normalize_cartfile_spec(match.group(1), match.group(2))
                add_fn(pkg, match.group(3))

    _extract_cross_platform_lockfiles(search_root, add_fn)


def extract_ios_sbom(app_dic):
    """Extract sorted list of versioned iOS SBOM packages."""
    scan_dir = app_dic.get('app_root') or app_dic.get('app_dir')
    if not scan_dir:
        return []
    root = Path(scan_dir)
    app_dir = Path(app_dic.get('app_dir', scan_dir))
    versioned = set()

    def _add(pkg, version):
        version = version.strip().lstrip('v')
        if pkg and _valid_version(version):
            versioned.add(f'{pkg}@{version}')

    if root.exists():
        for plist_path in sorted(root.rglob('*.framework/Info.plist')):
            _extract_ios_framework_plist(root, plist_path, _add)

    for search_root in {root, app_dir}:
        if search_root.exists():
            _extract_ios_lockfiles_in_dir(search_root, _add)

    return sorted(versioned)


def ios_sbom(app_dic):
    """Extract iOS SBOM dictionary."""
    return {
        'sbom_versioned': extract_ios_sbom(app_dic),
        'sbom_packages': [],
    }
