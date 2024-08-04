# -*- coding: utf_8 -*-
"""Handle Static Library .a file (ELF and MachO)."""
import logging
import os
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.ios.binary_rule_matcher import (
    binary_rule_matcher,
)
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.ios.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    ar_extract,
    firebase_analysis,
    get_symbols,
    hash_gen,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)


def extract_n_get_files(checksum, src, dst):
    """Extract .a archive and get list of files."""
    files = []
    dst = Path(dst) / 'static_objects'
    dst.mkdir(parents=True, exist_ok=True)
    ar_extract(checksum, src, dst.as_posix())
    for i in dst.rglob('*.a'):
        files.append(
            os.path.relpath(dst, i.as_posix()))
    return files


def a_analysis(request, app_dict, rescan, api):
    """Independent shared library .a analysis."""
    checksum = app_dict['md5_hash']
    app_dir = Path(app_dict['app_dir'])
    app_dict['app_file'] = f'{checksum}.a'
    app_dict['app_path'] = app_dir / app_dict['app_file']
    app_dict['app_path'] = app_dict['app_path'].as_posix()
    # DB
    ipa_db = StaticAnalyzerIOS.objects.filter(MD5=checksum)
    if ipa_db.exists() and not rescan:
        context = get_context_from_db_entry(ipa_db)
    else:
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                False)
        append_scan_status(checksum, 'init')
        logger.info('Static Library Analysis Started')
        app_dict['size'] = str(
            file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
        app_dict['sha1'], app_dict['sha256'] = hash_gen(
            checksum,
            app_dict['app_path'])  # SHA1 & SHA256 HASHES
        app_dict['bin_dir'] = app_dict['app_dir']
        files = extract_n_get_files(
            checksum,
            app_dict['app_path'],
            app_dict['app_dir'],
        )
        # Get Files
        all_files = {
            'files_short': files,
            'files_long': [],
            'special_files': [],
        }
        infoplist_dict = {
            'bin_name': '',
            'bin': '',
            'id': app_dict['file_name'],
            'version': '',
            'build': '',
            'sdk': '',
            'pltfm': '',
            'min': '',
            'plist_xml': '',
            'permissions': {},
            'inseccon': {},
            'bundle_name': '',
            'build_version_name': '',
            'bundle_url_types': [],
            'bundle_supported_platforms': [],
            'bundle_version_name': '',
        }
        app_dict['appstore'] = ''
        app_dict['secrets'] = []
        bin_dict = {
            'checksec': {},
            'libraries': [],
            'bin_code_analysis': {},
            'strings': [],
            'bin_info': {
                'endian': '',
                'bit': '',
                'arch': '',
                'subarch': '',
            },
            'bin_type': 'A',
            'framework_analysis': {},
        }
        # Analyze static library
        slib = library_analysis(
            checksum,
            app_dict['bin_dir'],
            'ar')
        bin_dict['bin_info']['arch'] = slib['ar_a']
        bin_dict['dylib_analysis'] = slib['ar_analysis']
        # Store Symbols in File Analysis
        all_files['special_files'] = get_symbols(
            slib['ar_symbols'])
        # Binary code analysis on symbols
        binary_rule_matcher(
            checksum,
            bin_dict['bin_code_analysis'],
            all_files['special_files'],
            b'')
        # Extract String metadata
        code_dict = get_strings_metadata(
            app_dict,
            bin_dict,
            all_files,
            slib['ar_strings'])
        # Domain Extraction and Malware Check
        code_dict['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_dict['urls_list'])
        logger.info('Finished URL and Email Extraction')
        # Extract Trackers from Domains
        trk = Trackers.Trackers(
            checksum,
            None,
            app_dict['tools_dir'])
        trackers = trk.get_trackers_domains_or_deps(
            code_dict['domains'], [])
        code_dict['api'] = {}
        code_dict['code_anal'] = {}
        code_dict['firebase'] = firebase_analysis(
            checksum,
            code_dict['urls_list'])
        code_dict['trackers'] = trackers
        context = save_get_ctx(
            app_dict,
            infoplist_dict,
            code_dict,
            bin_dict,
            all_files,
            rescan)
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(
            app_dict['app_path'])
    context['appsec'] = {}
    context['average_cvss'] = None
    template = 'static_analysis/ios_binary_analysis.html'
    if api:
        return context
    else:
        return render(request, template, context)
