# -*- coding: utf_8 -*-
"""Windows APPX/MSIX Static Analysis."""
import logging
import shutil
from pathlib import Path

from django.conf import settings
from django.shortcuts import render

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.security import (
    is_path_traversal,
    is_pipe_or_link,
    is_safe_path,
    sanitize_for_logging,
)
from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    is_md5,
    print_n_send_error_response,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)
from mobsf.MobSF.views.home import update_scan_timestamp
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerWindows,
)
from mobsf.StaticAnalyzer.views.common.secret_detection import get_secrets
from mobsf.StaticAnalyzer.views.common.shared_func import (
    hash_gen,
    unzip,
    url_n_email_extract,
)
from mobsf.StaticAnalyzer.views.windows.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update,
)
from mobsf.StaticAnalyzer.views.windows.manifest import (
    WARNING,
    analyze_signature,
    parse_manifest,
    read_xml,
)
from mobsf.StaticAnalyzer.views.windows.pe import PEChecksec
from mobsf.StaticAnalyzer.views.windows.strings import extract_strings

logger = logging.getLogger(__name__)

BUNDLE_EXTS = ('appxbundle', 'msixbundle')
PE_EXTS = {
    '.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.pyd', '.node',
}
MZ_MAGIC = b'MZ'
MAX_PE_FILES = 100
MAX_PE_SIZE = 200 * 1024 * 1024
MAX_STRINGS_PER_FILE = 20000
MAX_STRINGS_TOTAL = 100000
MAX_STORED_STRINGS = 20000
BUNDLE_DIR = 'bundle_package'
BUNDLE_MANIFEST = Path('AppxMetadata') / 'AppxBundleManifest.xml'
# Preferred architecture when a bundle carries several app packages.
ARCH_ORDER = ('x64', 'arm64', 'x86', 'neutral', 'arm')


@login_required
def staticanalyzer_windows(request, checksum, api=False):
    """Analyse a Windows APPX/MSIX package."""
    try:
        logger.info('Windows Static Analysis Started')
        if api:
            rescan = request.POST.get('re_scan', 0) == '1'
        else:
            rescan = request.GET.get('rescan', 0) == '1'
        if not is_md5(checksum):
            return print_n_send_error_response(request, 'Invalid Hash', api)
        robj = RecentScansDB.objects.filter(MD5=checksum).first()
        if not robj:
            return print_n_send_error_response(
                request, 'The file is not uploaded/available', api)
        typ = robj.SCAN_TYPE
        if typ not in settings.WINDOWS_EXTS:
            return print_n_send_error_response(
                request, 'File type not supported', api)
        app_dir = Path(settings.UPLD_DIR) / checksum
        app_path = app_dir / f'{checksum}.{typ}'
        db_entry = StaticAnalyzerWindows.objects.filter(MD5=checksum)
        if db_entry.exists() and not rescan:
            context = get_context_from_db_entry(db_entry)
        else:
            if not has_permission(request, Permissions.SCAN, api):
                return print_n_send_error_response(
                    request, 'Permission Denied', api)
            append_scan_status(checksum, 'init')
            analysis = analyze_package(
                checksum, app_path, app_dir, typ, robj.FILE_NAME)
            save_or_update(analysis)
            if rescan:
                update_scan_timestamp(checksum)
            context = get_context_from_analysis(analysis)
        context['virus_total'] = None
        if settings.VT_ENABLED:
            vt = VirusTotal.VirusTotal(checksum)
            context['virus_total'] = vt.get_result(app_path.as_posix())
        if api:
            return context
        return render(
            request,
            'static_analysis/windows_binary_analysis.html',
            context)
    except Exception as exp:
        msg = 'Error Performing Static Analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
        return print_n_send_error_response(request, msg, api)


def _safe_child(root, rel):
    """Return root/rel if it is a regular file contained in root."""
    if not rel or is_path_traversal(rel):
        return None
    path = Path(root) / rel
    if (not is_safe_path(root, path.as_posix(), rel)
            or not path.is_file()
            or is_pipe_or_link(path)):
        return None
    return path


def _reset_dir(path):
    """Remove anything at path, e.g. entries planted by the outer bundle."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _select_bundle_package(app_dir):
    """Pick the application package to analyze from a bundle."""
    root = read_xml(app_dir / BUNDLE_MANIFEST)
    if root is None:
        return None
    candidates = []
    for elem in root.iter():
        if not str(elem.tag).endswith('}Package'):
            continue
        if (elem.get('Type') or 'application').lower() != 'application':
            continue
        name = elem.get('FileName', '')
        if name.replace('\\', '/').split('/')[0].lower() == BUNDLE_DIR:
            continue
        arch = (elem.get('Architecture') or 'neutral').lower()
        rank = ARCH_ORDER.index(arch) if arch in ARCH_ORDER else len(
            ARCH_ORDER)
        candidates.append((rank, name))
    for _, name in sorted(candidates):
        path = _safe_child(app_dir, name)
        if path and path.suffix.lower() in ('.appx', '.msix'):
            return path
    return None


def _iter_pe_files(root, executables):
    """Yield (path, relative path) for PE images, main executables first."""
    root = Path(root)
    found = []
    for path in root.rglob('*'):
        if path.suffix.lower() not in PE_EXTS:
            continue
        if is_pipe_or_link(path) or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if not is_safe_path(root.as_posix(), path.as_posix(), rel):
            continue
        if path.stat().st_size > MAX_PE_SIZE:
            logger.warning(
                'Skipping large PE file: %s', sanitize_for_logging(rel))
            continue
        with path.open('rb') as fp:
            if fp.read(2) != MZ_MAGIC:
                continue
        found.append((path, rel))
    main = {e.replace('\\', '/').lower() for e in executables}
    found.sort(key=lambda item: (item[1].lower() not in main, item[1]))
    return found[:MAX_PE_FILES]


def _package_file_findings(files):
    """Findings derived from the packaged file list."""
    pdbs = sorted(f for f in files if f.lower().endswith('.pdb'))
    if not pdbs:
        return []
    shown = ', '.join(pdbs[:10])
    more = f' and {len(pdbs) - 10} more' if len(pdbs) > 10 else ''
    return [{
        'rule': 'debug_symbols_packaged',
        'title': 'Debug symbol files (.pdb) are packaged',
        'severity': WARNING,
        'description': (
            'The package ships program database files that contain '
            'function names, source file paths and type information, '
            f'which makes reverse engineering easier: {shown}{more}.'),
    }]


def _analyze_binaries(checksum, root, executables):
    """Run PE hardening checks and string extraction on all binaries."""
    pe_analysis = []
    all_strings = set()
    urls_list, urls, emails = [], [], []
    for path, rel in _iter_pe_files(root, executables):
        logger.info('Analyzing %s', sanitize_for_logging(rel))
        append_scan_status(checksum, f'Analyzing {rel}')
        try:
            result = PEChecksec(path, rel).checksec()
        except Exception as exp:
            append_scan_status(checksum, f'Failed to analyze {rel}', repr(exp))
            continue
        if not result:
            continue
        pe_analysis.append(result)
        if len(all_strings) >= MAX_STRINGS_TOTAL:
            continue
        try:
            strings = extract_strings(path, MAX_STRINGS_PER_FILE)
        except OSError:
            continue
        all_strings.update(strings)
        file_urls, url_nf, email_nf = url_n_email_extract(
            '\n'.join(strings), rel)
        urls_list.extend(file_urls)
        urls.extend(url_nf)
        emails.extend(email_nf)
    return {
        'pe_analysis': pe_analysis,
        'strings': sorted(all_strings),
        'urls_list': sorted(set(urls_list)),
        'urls': urls,
        'emails': emails,
    }


def analyze_package(checksum, app_path, app_dir, typ, file_name):
    """Analyze an APPX/MSIX package or bundle."""
    msg = 'Windows Package Analysis Started'
    logger.info(msg)
    append_scan_status(checksum, msg)
    analysis = {
        'md5': checksum,
        'file_name': file_name,
        'package_type': typ,
        'size': f'{file_size(app_path.as_posix())}MB',
    }
    analysis['sha1'], analysis['sha256'] = hash_gen(
        checksum, app_path.as_posix())
    budget = {'used': 0}
    files = unzip(checksum, app_path.as_posix(), app_dir.as_posix(), budget)
    root = app_dir
    if typ in BUNDLE_EXTS:
        inner = _select_bundle_package(app_dir)
        if not inner:
            raise ValueError('No application package found in bundle')
        logger.info(
            'Extracting %s from bundle', sanitize_for_logging(inner.name))
        append_scan_status(checksum, f'Extracting {inner.name} from bundle')
        root = app_dir / BUNDLE_DIR
        _reset_dir(root)
        files = unzip(checksum, inner.as_posix(), root.as_posix(), budget)
    analysis['files'] = sorted(
        f for f in files if f and not f.endswith(('/', '\\')))

    msg = 'Reading AppxManifest.xml'
    logger.info(msg)
    append_scan_status(checksum, msg)
    manifest = parse_manifest(root / 'AppxManifest.xml')
    signature = analyze_signature(app_dir, manifest['publisher'])
    analysis['manifest'] = manifest
    analysis['signature'] = signature
    analysis['manifest_analysis'] = (
        manifest['findings']
        + signature['findings']
        + _package_file_findings(analysis['files']))

    msg = 'Running PE Binary Analysis'
    logger.info(msg)
    append_scan_status(checksum, msg)
    binaries = _analyze_binaries(checksum, root, manifest['executables'])
    analysis.update(binaries)
    analysis['secrets'] = sorted(get_secrets(binaries['strings']))
    analysis['strings'] = binaries['strings'][:MAX_STORED_STRINGS]
    analysis['domains'] = MalwareDomainCheck().scan(
        checksum, binaries['urls_list'])
    analysis['trackers'] = Trackers.Trackers(
        checksum, None, None).get_trackers_domains_or_deps(
            analysis['domains'], [])
    msg = 'Windows Package Analysis Completed'
    logger.info(msg)
    append_scan_status(checksum, msg)
    return analysis
