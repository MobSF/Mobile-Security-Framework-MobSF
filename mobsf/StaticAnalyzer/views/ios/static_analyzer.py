# -*- coding: utf_8 -*-
"""iOS Static Code Analysis."""
import logging
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    is_md5,
    print_n_send_error_response,
    relative_path,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
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
from mobsf.StaticAnalyzer.views.ios.dylib import dylib_analysis
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
from mobsf.StaticAnalyzer.views.common.a import (
    a_analysis,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    firebase_analysis,
    get_avg_cvss,
    hash_gen,
    strings_and_entropies,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_ios_dashboard,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import (
    MalwareDomainCheck,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)
register.filter('relative_path', relative_path)

##############################################################
# iOS Static Code Analysis IPA and Source Code
##############################################################


@login_required
def static_analyzer_ios(request, checksum, api=False):
    """Module that performs iOS IPA/ZIP Static Analysis."""
    try:
        rescan = False
        if api:
            re_scan = request.POST.get('re_scan', 0)
        else:
            re_scan = request.GET.get('rescan', 0)
        if re_scan == '1':
            rescan = True
        app_dict = {}
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        robj = RecentScansDB.objects.filter(MD5=checksum)
        if not robj.exists():
            return print_n_send_error_response(
                request,
                'The file is not uploaded/available',
                api)
        file_type = robj[0].SCAN_TYPE
        filename = robj[0].FILE_NAME
        if file_type == 'dylib' and not Path(filename).suffix:
            # Force dylib extension on Frameworks
            filename = f'{filename}.dylib'
        ios_exts = tuple(f'.{i}' for i in settings.IOS_EXTS)
        allowed_exts = ios_exts + ('.zip', 'ios')
        allowed_types = settings.IOS_EXTS + ('zip', 'ios')
        if (not filename.lower().endswith(allowed_exts)
                or file_type not in allowed_types):
            return print_n_send_error_response(
                request,
                'Invalid file extension or file type',
                api)
        app_dict['directory'] = Path(settings.BASE_DIR)  # BASE DIR
        app_dict['file_name'] = filename  # APP ORIGINAL NAME
        app_dict['md5_hash'] = checksum  # MD5
        app_dir = Path(settings.UPLD_DIR) / checksum
        app_dict['app_dir'] = app_dir.as_posix() + '/'
        tools_dir = app_dict[
            'directory'] / 'StaticAnalyzer' / 'tools' / 'ios'
        app_dict['tools_dir'] = tools_dir.as_posix()
        app_dict['icon_path'] = ''
        if file_type == 'ipa':
            app_dict['app_file'] = f'{checksum}.ipa'
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
                msg = 'iOS Binary (IPA) Analysis Started'
                logger.info(msg)
                append_scan_status(checksum, msg)
                app_dict['size'] = str(
                    file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
                app_dict['sha1'], app_dict['sha256'] = hash_gen(
                    checksum,
                    app_dict['app_path'])  # SHA1 & SHA256 HASHES
                msg = 'Extracting IPA'
                logger.info(msg)
                append_scan_status(checksum, msg)
                # EXTRACT IPA
                unzip(
                    checksum,
                    app_dict['app_path'],
                    app_dict['app_dir'])
                # Identify Payload directory
                dirs = app_dir.glob('**/*')
                for _dir in dirs:
                    if 'payload' in _dir.as_posix().lower():
                        app_dict['bin_dir'] = app_dict['app_dir'] / _dir
                        break
                else:
                    msg = ('IPA is malformed! '
                           'MobSF cannot find Payload directory')
                    append_scan_status(checksum, 'IPA is malformed', msg)
                    return print_n_send_error_response(
                        request,
                        msg,
                        api)
                app_dict['bin_dir'] = app_dict['bin_dir'].as_posix() + '/'
                # Get Files
                all_files = ios_list_files(
                    checksum,
                    app_dict['bin_dir'],
                    True,
                    'ipa')
                # Plist files are converted to xml/readable
                infoplist_dict = plist_analysis(
                    checksum,
                    app_dict['bin_dir'],
                    False)
                app_dict['appstore'] = app_search(
                    checksum,
                    infoplist_dict.get('id'))
                app_dict['secrets'] = get_plist_secrets(
                    checksum,
                    app_dict['bin_dir'])
                bin_dict = binary_analysis(
                    checksum,
                    app_dict['bin_dir'],
                    app_dict['tools_dir'],
                    app_dict['app_dir'],
                    infoplist_dict.get('bin'))
                # Analyze dylibs and frameworks
                lb = library_analysis(
                    checksum,
                    app_dict['bin_dir'],
                    'macho')
                bin_dict['dylib_analysis'] = lb['macho_analysis']
                bin_dict['framework_analysis'] = lb['framework_analysis']
                # Get Icon
                get_icon_from_ipa(
                    app_dict,
                    infoplist_dict.get('bin'))
                # Extract String metadata
                code_dict = get_strings_metadata(
                    app_dict,
                    bin_dict,
                    all_files,
                    lb['macho_strings'])
                # Domain Extraction and Malware Check
                code_dict['domains'] = MalwareDomainCheck().scan(
                    checksum,
                    code_dict['urls_list'])
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
            context['appsec'] = get_ios_dashboard(context, True)
            context['average_cvss'] = get_avg_cvss(
                context['binary_analysis'])
            template = 'static_analysis/ios_binary_analysis.html'
            if api:
                return context
            else:
                return render(request, template, context)
        elif file_type == 'dylib':
            return dylib_analysis(request, app_dict, rescan, api)
        elif file_type == 'a':
            return a_analysis(request, app_dict, rescan, api)
        elif file_type in ('ios', 'zip'):
            ios_zip_db = StaticAnalyzerIOS.objects.filter(
                MD5=checksum)
            if ios_zip_db.exists() and not rescan:
                context = get_context_from_db_entry(ios_zip_db)
            else:
                if not has_permission(request, Permissions.SCAN, api):
                    return print_n_send_error_response(
                        request,
                        'Permission Denied',
                        False)
                logger.info('iOS Source Code Analysis Started')
                app_dict['app_file'] = app_dict[
                    'md5_hash'] + '.zip'  # NEW FILENAME
                app_dict['app_path'] = app_dir / app_dict['app_file']
                app_dict['app_path'] = app_dict['app_path'].as_posix()
                # ANALYSIS BEGINS - Already Unzipped
                # append_scan_status init done in android static analyzer
                app_dict['size'] = str(
                    file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
                app_dict['sha1'], app_dict['sha256'] = hash_gen(
                    checksum,
                    app_dict['app_path'])  # SHA1 & SHA256 HASHES
                all_files = ios_list_files(
                    checksum,
                    app_dict['app_dir'],
                    False,
                    'ios')
                infoplist_dict = plist_analysis(
                    checksum,
                    app_dict['app_dir'],
                    True)
                app_dict['appstore'] = app_search(
                    checksum,
                    infoplist_dict.get('id'))
                app_dict['secrets'] = get_plist_secrets(
                    checksum,
                    app_dict['app_dir'])
                code_analysis_dic = ios_source_analysis(
                    checksum,
                    app_dict['app_dir'])
                ios_strs = strings_and_entropies(
                    checksum,
                    Path(app_dict['app_dir']),
                    ['.swift', '.m', '.h', '.plist'])
                if ios_strs['secrets']:
                    app_dict['secrets'].extend(list(ios_strs['secrets']))
                # Get App Icon
                get_icon_source(app_dict)
                # Firebase DB Check
                code_analysis_dic['firebase'] = firebase_analysis(
                    checksum,
                    list(set(code_analysis_dic['urls_list'])))
                # Extract Trackers from Domains
                trk = Trackers.Trackers(
                    checksum,
                    None,
                    app_dict['tools_dir'])
                trackers = trk.get_trackers_domains_or_deps(
                    code_analysis_dic['domains'], [])
                code_analysis_dic['trackers'] = trackers
                fake_bin_dict = {
                    'checksec': {},
                    'libraries': [],
                    'bin_code_analysis': {},
                    'strings': list(ios_strs['strings']),
                    'bin_info': {},
                    'bin_type': code_analysis_dic['source_type'],
                    'dylib_analysis': {},
                    'framework_analysis': {},
                }
                context = save_get_ctx(
                    app_dict,
                    infoplist_dict,
                    code_analysis_dic,
                    fake_bin_dict,
                    all_files,
                    rescan)
            context['appsec'] = get_ios_dashboard(context, True)
            context['average_cvss'] = get_avg_cvss(
                context['code_analysis'])
            template = 'static_analysis/ios_source_analysis.html'
            if api:
                return context
            else:
                return render(request, template, context)
        else:
            err = ('File Type not supported, '
                   'Only IPA, A, DYLIB and ZIP are supported')
            logger.error(err)
            append_scan_status(checksum, err)
            raise Exception(err)
    except Exception as exp:
        msg = 'Error Performing Static Analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, repr(exp), api, exp_doc)
