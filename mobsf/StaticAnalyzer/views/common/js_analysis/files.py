# -*- coding: utf_8 -*-
"""JavaScript source discovery and listing."""
import os
from pathlib import Path

from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
)
from mobsf.MobSF.utils import python_dict
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.StaticAnalyzer.views.common.js_analysis.constants import (
    BUNDLE_EXTS,
    HYBRID_CONFIG_FILES,
    JS_SOURCE_EXTS,
    SKIP_JS_DIRS,
    SKIP_VENDOR_FILES,
    WEB_ROOT_DIRS,
)
from mobsf.StaticAnalyzer.views.common.js_analysis.hermes import (
    is_hermes_bytecode,
)


def is_valid_candidate(scan_root, pfile):
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


def iter_files(root):
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


def is_analysis_name(name):
    """Return True if a filename is relevant to JS/hybrid analysis."""
    low = name.lower()
    return (_is_js_name(low)
            or low in HYBRID_CONFIG_FILES
            or low.endswith('.map'))


def collect_roots_for_scan(scan_root, scan_type, app_root=None):
    """Return directories to search for JS/hybrid files."""
    if scan_type == 'apk':
        roots = [scan_root / 'assets', scan_root / 'res' / 'raw']
        return [r for r in roots if r.is_dir() and not is_pipe_or_link(r)]
    if scan_type == 'ipa' and app_root:
        aroot = Path(app_root)
        if aroot.is_dir() and not is_pipe_or_link(aroot):
            return [aroot]
    return [scan_root]


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
    for pfile in iter_files(base_dir):
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
