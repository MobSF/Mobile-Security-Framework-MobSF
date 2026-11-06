# -*- coding: utf_8 -*-
"""Offline SBOM component extraction for Android and iOS."""
import json
from pathlib import Path
from plistlib import load as plist_load
import re

from mobsf.MobSF.security import (
    is_pipe_or_link,
    is_safe_path,
)

_MAX_SBOM_FILE_SIZE = 2 * 1024 * 1024
_VALID_VERSION_RE = re.compile(r'^[0-9][0-9A-Za-z._+-]{0,63}$')
_POM_DEP_LINE_RE = re.compile(
    r'([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):(?:jar|aar):([0-9][0-9A-Za-z._+-]*)')
_GRADLE_COORD_RE = re.compile(
    r'["\']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][0-9A-Za-z._+-]+)["\']')
_GRADLE_LOCK_LINE_RE = re.compile(
    r'^\s*([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([0-9][0-9A-Za-z._+-]*)=')
_TOML_VERSION_REF_RE = re.compile(
    r'^\s*([A-Za-z0-9_.-]+)\s*=\s*["\']([0-9][0-9A-Za-z._+-]+)["\']',
    re.MULTILINE)
_TOML_MODULE_RE = re.compile(
    r'module\s*=\s*["\']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)["\']'
    r'[^}\n]*?version(?:\.ref)?\s*=\s*["\']([A-Za-z0-9_.-]+)["\']')
_TOML_GROUP_NAME_RE = re.compile(
    r'group\s*=\s*["\']([A-Za-z0-9_.-]+)["\'][^}\n]*?'
    r'name\s*=\s*["\']([A-Za-z0-9_.-]+)["\'][^}\n]*?'
    r'version(?:\.ref)?\s*=\s*["\']([A-Za-z0-9_.-]+)["\']')
_PODFILE_LOCK_ITEM_RE = re.compile(
    r'^  - ([A-Za-z0-9_+-]+)(?:/[A-Za-z0-9_+-]+)* \(([0-9][0-9A-Za-z._+-]*)\)')
_CARTFILE_RESOLVED_RE = re.compile(
    r'^\s*github\s+"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"\s+"v?([0-9][0-9A-Za-z._+-]*)"')
_GITHUB_REPO_RE = re.compile(
    r'github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$')
_PUBSPEC_LOCK_PKG_RE = re.compile(
    r'^  ([a-zA-Z0-9_]+):\n(?:    [^\n]+\n)*?    version: "([0-9][0-9A-Za-z._+-]*)"',
    re.MULTILINE)


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


def _extract_cross_platform_lockfiles(root, add_fn):
    """Extract standard Dart/Flutter (pubspec.lock) and npm (package-lock.json)."""
    for publock in root.rglob('pubspec.lock'):
        text = _safe_read_text(root, publock)
        if not text:
            continue
        for pkg, ver in _PUBSPEC_LOCK_PKG_RE.findall(text):
            add_fn(pkg, ver)

    for pkglock in root.rglob('package-lock.json'):
        if 'node_modules' in pkglock.parts:
            continue
        text = _safe_read_text(root, pkglock)
        if not text:
            continue
        try:
            obj = json.loads(text)
            deps = obj.get('dependencies') or {}
            for pkg, meta in deps.items():
                if isinstance(meta, dict) and meta.get('version'):
                    add_fn(pkg, str(meta['version']))
            packages = obj.get('packages') or {}
            for pkg_path, meta in packages.items():
                if (not pkg_path.startswith('node_modules/')
                        or not isinstance(meta, dict)
                        or not meta.get('version')):
                    continue
                pkg = pkg_path.split('node_modules/')[-1]
                if pkg:
                    add_fn(pkg, str(meta['version']))
        except Exception:
            continue


def extract_android_sbom(app_dir):
    """Extract sorted list of versioned Android SBOM packages."""
    root = Path(app_dir)
    versioned = set()

    def _add(pkg, version):
        version = version.strip()
        if not pkg:
            return
        if version == 'dynamic' or _valid_version(version):
            versioned.add(f'{pkg}@{version}')

    if not root.exists():
        return []

    # 1. META-INF/*.version (standard Gradle/Jetpack/KotlinX version files)
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
            _add(f'{group}:{name}', version)

    # 2. Standard pom.properties and client .properties
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
                _add(f'{g}:{a}', v)
        elif 'client' in kv and 'version' in kv:
            client = kv['client']
            ver = kv['version']
            if client.startswith('firebase-'):
                group = 'com.google.firebase'
            elif client.startswith('play-services-'):
                group = 'com.google.android.gms'
            elif client == 'integrity':
                group = 'com.google.android.play'
            elif client == 'billing':
                group = 'com.android.billingclient'
            elif client.startswith('transport-'):
                group = 'com.google.android.datatransport'
            else:
                continue
            _add(f'{group}:{client}', ver)

    # 3. META-INF/DEPENDENCIES (standard Maven Shade/Assembly manifest)
    for dep_file in root.rglob('DEPENDENCIES'):
        if 'META-INF' not in dep_file.parts or 'apktool_out' in dep_file.parts:
            continue
        text = _safe_read_text(root, dep_file)
        if not text:
            continue
        for match in _POM_DEP_LINE_RE.finditer(text):
            g, a, v = match.group(1), match.group(2), match.group(3)
            _add(f'{g}:{a}', v)

    # 4. Source build manifests: *.versions.toml, build.gradle(.kts), gradle.lockfile
    for toml_file in root.rglob('*.versions.toml'):
        text = _safe_read_text(root, toml_file)
        if not text:
            continue
        versions_map = dict(_TOML_VERSION_REF_RE.findall(text))
        for g, a, vref in _TOML_MODULE_RE.findall(text):
            ver = versions_map.get(vref, vref)
            _add(f'{g}:{a}', ver)
        for g, a, vref in _TOML_GROUP_NAME_RE.findall(text):
            ver = versions_map.get(vref, vref)
            _add(f'{g}:{a}', ver)

    for gfile in (*root.rglob('build.gradle'), *root.rglob('build.gradle.kts')):
        text = _safe_read_text(root, gfile)
        if not text:
            continue
        for g, a, v in _GRADLE_COORD_RE.findall(text):
            _add(f'{g}:{a}', v)

    for lockfile in root.rglob('*gradle.lockfile'):
        text = _safe_read_text(root, lockfile)
        if not text:
            continue
        for line in text.splitlines():
            match = _GRADLE_LOCK_LINE_RE.match(line)
            if match:
                g, a, v = match.group(1), match.group(2), match.group(3)
                _add(f'{g}:{a}', v)

    # 5. Cross-platform lockfiles (pubspec.lock, package-lock.json)
    _extract_cross_platform_lockfiles(root, _add)

    return sorted(versioned)


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
                if fw_name and fw_name not in {'App', 'Flutter'}:
                    _add(fw_name, ver)
            except Exception:
                continue

    # 2. Podfile.lock, Package.resolved, Cartfile.resolved, and cross-platform locks
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
                    _add(match.group(1), match.group(2))

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
                    ver = str(state.get('version') or '')
                    ident = (
                        pin.get('identity')
                        or pin.get('package')
                        or '')
                    match = _GITHUB_REPO_RE.search(str(loc))
                    name = ident or (match.group(1) if match else '')
                    if name and ver:
                        _add(name, ver)
            except Exception:
                continue

        for cartfile in search_root.rglob('Cartfile.resolved'):
            text = _safe_read_text(search_root, cartfile)
            if not text:
                continue
            for line in text.splitlines():
                match = _CARTFILE_RESOLVED_RE.match(line)
                if match:
                    _add(match.group(1), match.group(2))

        _extract_cross_platform_lockfiles(search_root, _add)

    return sorted(versioned)


def ios_sbom(app_dic):
    """Extract iOS SBOM dictionary."""
    return {
        'sbom_versioned': extract_ios_sbom(app_dic),
        'sbom_packages': [],
    }
