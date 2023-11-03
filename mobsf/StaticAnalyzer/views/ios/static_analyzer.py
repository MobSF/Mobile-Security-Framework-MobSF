# -*- coding: utf_8 -*-
"""iOS Static Code Analysis."""
import logging
import re
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    file_size,
    print_n_send_error_response,
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

logger = logging.getLogger(__name__)

##############################################################
# iOS Static Code Analysis IPA and Source Code
##############################################################


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
        if not re.match('^[0-9a-f]{32}$', checksum):
            msg = 'Invalid checksum'
            return print_n_send_error_response(request, msg, api)
        robj = RecentScansDB.objects.filter(MD5=checksum)
        if not robj.exists():
            msg = 'The file is not uploaded/available'
            return print_n_send_error_response(request, msg, api)
        file_type = robj[0].SCAN_TYPE
        filename = robj[0].FILE_NAME
        allowed_exts = ('ios', '.ipa', '.zip', '.dylib', '.a')
        allowed_typ = [i.replace('.', '') for i in allowed_exts]
        if (not filename.lower().endswith(allowed_exts)
                or file_type not in allowed_typ):
            msg = 'Invalid file extension or file type'
            return print_n_send_error_response(request, msg, api)

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
            app_dict['app_file'] = app_dict[
                'md5_hash'] + '.ipa'  # NEW FILENAME
            app_dict['app_path'] = app_dir / app_dict['app_file']
            app_dict['app_path'] = app_dict['app_path'].as_posix()
            # DB
            ipa_db = StaticAnalyzerIOS.objects.filter(
                MD5=app_dict['md5_hash'])
            if ipa_db.exists() and not rescan:
                context = get_context_from_db_entry(ipa_db)
            else:
                logger.info('iOS Binary (IPA) Analysis Started')
                app_dict['size'] = str(
                    file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
                app_dict['sha1'], app_dict['sha256'] = hash_gen(
                    app_dict['app_path'])  # SHA1 & SHA256 HASHES
                logger.info('Extracting IPA')
                # EXTRACT IPA
                unzip(app_dict['app_path'], app_dict['app_dir'])
                # Identify Payload directory
                dirs = app_dir.glob('**/*')
                for _dir in dirs:
                    if 'payload' in _dir.as_posix().lower():
                        app_dict['bin_dir'] = app_dict['app_dir'] / _dir
                        break
                else:
                    msg = ('IPA is malformed! '
                           'MobSF cannot find Payload directory')
                    return print_n_send_error_response(
                        request,
                        msg,
                        api)
                app_dict['bin_dir'] = app_dict['bin_dir'].as_posix() + '/'
                # Get Files
                all_files = ios_list_files(
                    app_dict['bin_dir'], app_dict['md5_hash'], True, 'ipa')
                # Plist files are converted to xml/readable
                infoplist_dict = plist_analysis(app_dict['bin_dir'], False)
                app_dict['appstore'] = app_search(infoplist_dict.get('id'))
                app_dict['secrets'] = get_plist_secrets(
                    app_dict['bin_dir'])
                bin_dict = binary_analysis(
                    app_dict['bin_dir'],
                    app_dict['tools_dir'],
                    app_dict['app_dir'],
                    infoplist_dict.get('bin'))
                # Analyze dylibs and frameworks
                lb = library_analysis(app_dict['bin_dir'], 'macho')
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
                logger.info('Performing Malware Check on '
                            'extracted Domains')
                code_dict['domains'] = MalwareDomainCheck().scan(
                    code_dict['urls_list'])
                logger.info('Finished URL and Email Extraction')

                # Extract Trackers from Domains
                trk = Trackers.Trackers(
                    None, app_dict['tools_dir'])
                trackers = trk.get_trackers_domains_or_deps(
                    code_dict['domains'], [])

                code_dict['api'] = {}
                code_dict['code_anal'] = {}
                code_dict['firebase'] = firebase_analysis(
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
                vt = VirusTotal.VirusTotal()
                context['virus_total'] = vt.get_result(
                    app_dict['app_path'],
                    app_dict['md5_hash'])
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
                MD5=app_dict['md5_hash'])
            if ios_zip_db.exists() and not rescan:
                context = get_context_from_db_entry(ios_zip_db)
            else:
                logger.info('iOS Source Code Analysis Started')
                app_dict['app_file'] = app_dict[
                    'md5_hash'] + '.zip'  # NEW FILENAME
                app_dict['app_path'] = app_dir / app_dict['app_file']
                app_dict['app_path'] = app_dict['app_path'].as_posix()
                # ANALYSIS BEGINS - Already Unzipped
                app_dict['size'] = str(
                    file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
                app_dict['sha1'], app_dict['sha256'] = hash_gen(
                    app_dict['app_path'])  # SHA1 & SHA256 HASHES
                all_files = ios_list_files(
                    app_dict['app_dir'],
                    app_dict['md5_hash'],
                    False,
                    'ios')
                infoplist_dict = plist_analysis(app_dict['app_dir'], True)
                app_dict['appstore'] = app_search(infoplist_dict.get('id'))
                app_dict['secrets'] = get_plist_secrets(
                    app_dict['app_dir'])
                code_analysis_dic = ios_source_analysis(
                    app_dict['app_dir'])
                ios_strs = strings_and_entropies(
                    Path(app_dict['app_dir']),
                    ['.swift', '.m', '.h', '.plist'])
                if ios_strs['secrets']:
                    app_dict['secrets'].extend(list(ios_strs['secrets']))
                # Get App Icon
                get_icon_source(app_dict)
                # Firebase DB Check
                code_analysis_dic['firebase'] = firebase_analysis(
                    list(set(code_analysis_dic['urls_list'])))
                # Extract Trackers from Domains
                trk = Trackers.Trackers(
                    None, app_dict['tools_dir'])
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
            msg = ('File Type not supported, '
                   'Only IPA, A, DYLIB and ZIP are supported')
            return print_n_send_error_response(request, msg, api)
    except Exception as exp:
        logger.exception('Error Performing Static Analysis')
        msg = str(exp)
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, msg, api, exp_doc)
