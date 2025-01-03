# -*- coding: utf_8 -*-
"""iOS Analysis."""
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
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.ios.appstore import app_search
from mobsf.StaticAnalyzer.views.ios.binary_analysis import (
    binary_analysis,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.ios.code_analysis import ios_source_analysis
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.ios.file_analysis import ios_list_files
from mobsf.StaticAnalyzer.views.ios.icon_analysis import (
    get_icon_from_ipa,
    get_icon_source,
)
from mobsf.StaticAnalyzer.views.ios.plist_analysis import (
    get_plist_secrets,
    plist_analysis,
)
from mobsf.StaticAnalyzer.views.ios.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
    hash_gen,
    strings_and_entropies,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.firebase import (
    firebase_analysis,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_ios_dashboard,
)
from mobsf.StaticAnalyzer.views.common.async_task import (
    async_analysis,
    mark_task_completed,
    mark_task_started,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)


def initialize_app_dic(app_dic, file_ext):
    """Initialize App Dictionary."""
    checksum = app_dic['md5_hash']
    app_dic['app_file'] = f'{checksum}.{file_ext}'
    app_dic['app_path'] = (app_dic['app_dirp'] / app_dic['app_file']).as_posix()
    return checksum


def get_size_and_hashes(app_dic):
    app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'
    app_dic['sha1'], app_dic['sha256'] = hash_gen(
        app_dic['md5_hash'], app_dic['app_path'])


def extract_and_check_ipa(checksum, app_dic):
    """Extract and Check IPA."""
    # EXTRACT IPA
    msg = 'Extracting IPA'
    logger.info(msg)
    append_scan_status(checksum, msg)
    unzip(
        checksum,
        app_dic['app_path'],
        app_dic['app_dir'])
    # Identify Payload directory
    dirs = app_dic['app_dirp'].glob('**/*')
    for _dir in dirs:
        if 'payload' in _dir.as_posix().lower():
            app_dic['bin_dir'] = app_dic['app_dirp'] / _dir
            break
    else:
        return False
    app_dic['bin_dir'] = app_dic['bin_dir'].as_posix() + '/'
    return True


def common_analysis(scan_type, app_dic, checksum):
    """Common Analysis for ipa and zip."""
    location = app_dic['app_dir']
    if scan_type == 'ipa':
        location = app_dic['bin_dir']
    # Get Files
    app_dic['all_files'] = ios_list_files(
        checksum,
        location,
        scan_type)
    # Plist files are converted to xml/readable for ipa
    app_dic['infoplist'] = plist_analysis(
        checksum,
        location,
        scan_type)
    app_dic['appstore'] = app_search(
        checksum,
        app_dic['infoplist'].get('id'))
    app_dic['secrets'] = get_plist_secrets(
        checksum,
        location)


def common_firebase_and_trackers(code_dict, app_dic, checksum):
    """Common Firebase and Trackers."""
    # Firebase Analysis
    code_dict['firebase'] = firebase_analysis(
        checksum,
        code_dict)
    # Extract Trackers from Domains
    trk = Trackers.Trackers(
        checksum,
        None,
        app_dic['tools_dir'])
    code_dict['trackers'] = trk.get_trackers_domains_or_deps(
        code_dict['domains'], [])


def get_scan_subject(app_dic, bin_dict):
    """Get Scan Subject."""
    app_name = None
    pkg_name = None
    subject = 'iOS App'
    if bin_dict.get('bin_path'):
        app_name = bin_dict['bin_path'].name if bin_dict['bin_path'] else None
    if app_dic.get('infoplist'):
        pkg_name = app_dic['infoplist'].get('id')

    if app_name and pkg_name:
        subject = f'{app_name} ({pkg_name})'
    elif pkg_name:
        subject = pkg_name
    elif app_name:
        subject = app_name
    if subject == 'Failed':
        subject = f'({subject})'
    return subject


def ipa_analysis_task(checksum, app_dic, rescan, queue=False):
    """IPA Analysis Task."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        append_scan_status(checksum, 'init')
        msg = 'iOS Binary (IPA) Analysis Started'
        logger.info(msg)
        append_scan_status(checksum, msg)
        get_size_and_hashes(app_dic)

        if not extract_and_check_ipa(checksum, app_dic):
            msg = ('IPA is malformed! MobSF cannot find Payload directory')
            append_scan_status(checksum, 'IPA is malformed', msg)
            if queue:
                return mark_task_completed(
                    checksum, 'Failed', msg)
            return context, msg

        # Common Analysis
        common_analysis('ipa', app_dic, checksum)
        # IPA Binary Analysis
        bin_dict = binary_analysis(
            checksum,
            app_dic['bin_dir'],
            app_dic['tools_dir'],
            app_dic['app_dir'],
            app_dic['infoplist'].get('bin'))
        # Analyze dylibs and frameworks
        lb = library_analysis(
            checksum,
            app_dic['bin_dir'],
            'macho')
        bin_dict['dylib_analysis'] = lb['macho_analysis']
        bin_dict['framework_analysis'] = lb['framework_analysis']
        # Extract String metadata from binary
        code_dict = get_strings_metadata(
            app_dic,
            bin_dict,
            app_dic['all_files'],
            lb['macho_strings'])
        # Domain Extraction and Malware Check
        code_dict['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_dict['urls_list'])
        # Get Icon
        get_icon_from_ipa(app_dic)
        # Firebase and Trackers
        common_firebase_and_trackers(code_dict, app_dic, checksum)

        code_dict['api'] = {}
        code_dict['code_anal'] = {}
        context = save_get_ctx(
            app_dic,
            code_dict,
            bin_dict,
            rescan)
        if queue:
            subject = get_scan_subject(app_dic, bin_dict)
            return mark_task_completed(
                checksum, subject, 'Success')
        return context, None
    except Exception as exp:
        if queue:
            return mark_task_completed(
                checksum, 'Failed', repr(exp))
        return context, repr(exp)


def generate_dynamic_context(request, app_dic, context, checksum, api):
    """Generate Dynamic Context."""
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(app_dic['app_path'])
    context['appsec'] = get_ios_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['binary_analysis'])
    template = 'static_analysis/ios_binary_analysis.html'
    return context if api else render(request, template, context)


def ipa_analysis(request, app_dic, rescan, api):
    """IPA Analysis."""
    checksum = initialize_app_dic(app_dic, 'ipa')
    ipa_db = StaticAnalyzerIOS.objects.filter(MD5=checksum)
    if ipa_db.exists() and not rescan:
        context = get_context_from_db_entry(ipa_db)
        return generate_dynamic_context(request, app_dic, context, checksum, api)
    else:
        # IPA Analysis
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('file_name', ''),
                ipa_analysis_task, checksum, app_dic, rescan)
        context, err = ipa_analysis_task(checksum, app_dic, rescan)
        if err:
            return print_n_send_error_response(request, err, api)
        return generate_dynamic_context(request, app_dic, context, checksum, api)


def ios_analysis_task(checksum, app_dic, rescan, queue=False):
    """IOS Analysis Task."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
            mark_task_started(checksum)
        logger.info('iOS Source Code Analysis Started')
        get_size_and_hashes(app_dic)

        # ANALYSIS BEGINS - Already Unzipped
        # append_scan_status init done in android static analyzer
        common_analysis('zip', app_dic, checksum)

        # IOS Source Code Analysis
        code_dict = ios_source_analysis(
            checksum,
            app_dic['app_dir'])
        # Extract Strings and entropies from source code
        ios_strs = strings_and_entropies(
            checksum,
            Path(app_dic['app_dir']),
            ['.swift', '.m', '.h', '.plist', '.json'])
        if ios_strs['secrets']:
            app_dic['secrets'].extend(list(ios_strs['secrets']))
        # Get App Icon
        get_icon_source(app_dic)
        # Firebase and Trackers
        common_firebase_and_trackers(code_dict, app_dic, checksum)

        bin_dict = {
            'checksec': {},
            'libraries': [],
            'bin_code_analysis': {},
            'strings': list(ios_strs['strings']),
            'bin_info': {},
            'bin_type': code_dict['source_type'],
            'dylib_analysis': {},
            'framework_analysis': {},
        }
        context = save_get_ctx(
            app_dic,
            code_dict,
            bin_dict,
            rescan)
        if queue:
            subject = get_scan_subject(app_dic, bin_dict)
            return mark_task_completed(
                checksum, subject, 'Success')
    except Exception as exp:
        if queue:
            return mark_task_completed(
                checksum, 'Failed', repr(exp))
    return context


def generate_dynamic_ios_context(request, context, api):
    """Generate Dynamic Context for IOS."""
    context['appsec'] = get_ios_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis'])
    template = 'static_analysis/ios_source_analysis.html'
    return context if api else render(request, template, context)


def ios_analysis(request, app_dic, rescan, api):
    """IOS Source Code Analysis."""
    checksum = initialize_app_dic(app_dic, 'zip')
    ios_zip_db = StaticAnalyzerIOS.objects.filter(MD5=checksum)
    if ios_zip_db.exists() and not rescan:
        context = get_context_from_db_entry(ios_zip_db)
        return generate_dynamic_ios_context(request, context, api)
    else:
        # IOS Source Analysis
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('file_name', ''),
                ios_analysis_task, checksum, app_dic, rescan)
        context = ios_analysis_task(checksum, app_dic, rescan)
        return generate_dynamic_ios_context(request, context, api)
