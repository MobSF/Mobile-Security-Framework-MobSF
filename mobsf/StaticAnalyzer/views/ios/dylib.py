# -*- coding: utf_8 -*-
"""Handle (.dylib) Dynamic library file."""
import logging
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
from mobsf.StaticAnalyzer.views.ios.binary_analysis import (
    get_bin_info,
)
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


def dylib_analysis(request, app_dict, rescan, api):
    """Independent Dylib (.dylib) analysis."""
    checksum = app_dict['md5_hash']
    app_dir = Path(app_dict['app_dir'])
    app_dict['app_file'] = f'{checksum}.dylib'
    app_dict['app_path'] = app_dir / app_dict['app_file']
    app_dict['app_path'] = app_dict['app_path'].as_posix()
    # DB
    ipa_db = StaticAnalyzerIOS.objects.filter(
        MD5=checksum)
    if ipa_db.exists() and not rescan:
        context = get_context_from_db_entry(ipa_db)
    else:
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                False)
        append_scan_status(checksum, 'init')
        msg = 'Dylib Analysis Started'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dict['size'] = str(
            file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
        app_dict['sha1'], app_dict['sha256'] = hash_gen(
            checksum,
            app_dict['app_path'])  # SHA1 & SHA256 HASHES
        app_dict['bin_dir'] = app_dict['app_dir']
        # Get Files
        all_files = {
            'files_short': [],
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
            'bin_info': get_bin_info(
                Path(app_dict['app_path'])),
            'bin_type': 'Dylib',
        }
        # Analyze dylib
        dy = library_analysis(
            checksum,
            app_dict['bin_dir'],
            'macho')
        bin_dict['dylib_analysis'] = dy['macho_analysis']
        bin_dict['framework_analysis'] = {}
        # Store Symbols in File Analysis
        all_files['special_files'] = get_symbols(
            dy['macho_symbols'])
        # Binary code analysis on dylib symbols
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
            dy['macho_strings'])
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
