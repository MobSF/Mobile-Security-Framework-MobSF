# -*- coding: utf_8 -*-
"""iOS Static Code Analysis."""
import logging
import re
from pathlib import Path

import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import (
    file_size,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS
from mobsf.StaticAnalyzer.views.ios.appstore import app_search
from mobsf.StaticAnalyzer.views.ios.binary_analysis import binary_analysis
from mobsf.StaticAnalyzer.views.ios.code_analysis import ios_source_analysis
from mobsf.StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update)
from mobsf.StaticAnalyzer.views.ios.file_analysis import ios_list_files
from mobsf.StaticAnalyzer.views.ios.file_recon import extract_urls_n_email
from mobsf.StaticAnalyzer.views.ios.icon_analysis import (
    get_icon,
    get_icon_source,
)
from mobsf.StaticAnalyzer.views.ios.plist_analysis import plist_analysis
from mobsf.StaticAnalyzer.views.shared_func import (
    firebase_analysis,
    hash_gen, score, unzip,
    update_scan_timestamp,
)

logger = logging.getLogger(__name__)

##############################################################
# iOS Static Code Analysis IPA and Source Code
##############################################################


def static_analyzer_ios(request, api=False):
    """Module that performs iOS IPA/ZIP Static Analysis."""
    try:
        logger.info('iOS Static Analysis Started')
        rescan = False
        if api:
            file_type = request.POST['scan_type']
            checksum = request.POST['hash']
            re_scan = request.POST.get('re_scan', 0)
            filename = request.POST['file_name']
        else:
            file_type = request.GET['type']
            checksum = request.GET['checksum']
            re_scan = request.GET.get('rescan', 0)
            filename = request.GET['name']
        if re_scan == '1':
            rescan = True
        md5_match = re.match('^[0-9a-f]{32}$', checksum)
        if ((md5_match)
                and (filename.lower().endswith('.ipa')
            or filename.lower().endswith('.zip'))
                and (file_type in ['ipa', 'ios'])):
            app_dict = {}
            app_dict['directory'] = Path(settings.BASE_DIR)  # BASE DIR
            app_dict['file_name'] = filename  # APP ORIGINAL NAME
            app_dict['md5_hash'] = checksum  # MD5
            app_dir = Path(settings.UPLD_DIR) / checksum
            tools_dir = app_dict[
                'directory'] / 'StaticAnalyzer' / 'tools' / 'ios'
            tools_dir = tools_dir.as_posix()
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
                    app_dict['app_dir'] = app_dir.as_posix() + '/'
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
                        if api:
                            return print_n_send_error_response(
                                request,
                                msg,
                                True)
                        else:
                            return print_n_send_error_response(
                                request,
                                msg,
                                False)
                    app_dict['bin_dir'] = app_dict['bin_dir'].as_posix() + '/'
                    # Get Files
                    all_files = ios_list_files(
                        app_dict['bin_dir'], app_dict['md5_hash'], True, 'ipa')
                    infoplist_dict = plist_analysis(app_dict['bin_dir'], False)
                    app_dict['appstore'] = app_search(infoplist_dict.get('id'))
                    bin_analysis_dict = binary_analysis(
                        app_dict['bin_dir'],
                        tools_dir,
                        app_dict['app_dir'],
                        infoplist_dict.get('bin'))
                    # Get Icon
                    app_dict['icon_found'] = get_icon(
                        app_dict['md5_hash'],
                        app_dict['bin_dir'],
                        infoplist_dict.get('bin'))
                    # IPA URL and Email Extract
                    recon = extract_urls_n_email(app_dict['bin_dir'],
                                                 all_files['files_long'],
                                                 bin_analysis_dict['strings'])
                    code_dict = {
                        'api': {},
                        'code_anal': {},
                        'urlnfile': recon['urlnfile'],
                        'domains': recon['domains'],
                        'emailnfile': recon['emailnfile'],
                        'firebase': firebase_analysis(recon['urls_list']),
                    }
                    # Saving to DB
                    logger.info('Connecting to DB')
                    if rescan:
                        logger.info('Updating Database...')
                        save_or_update(
                            'update',
                            app_dict,
                            infoplist_dict,
                            code_dict,
                            bin_analysis_dict,
                            all_files)
                        update_scan_timestamp(app_dict['md5_hash'])
                    else:
                        logger.info('Saving to Database')
                        save_or_update(
                            'save',
                            app_dict,
                            infoplist_dict,
                            code_dict,
                            bin_analysis_dict,
                            all_files)
                    context = get_context_from_analysis(
                        app_dict,
                        infoplist_dict,
                        code_dict,
                        bin_analysis_dict,
                        all_files)
                context['virus_total'] = None
                if settings.VT_ENABLED:
                    vt = VirusTotal.VirusTotal()
                    context['virus_total'] = vt.get_result(
                        app_dict['app_path'],
                        app_dict['md5_hash'])
                context['average_cvss'], context[
                    'security_score'] = score(context['binary_analysis'])
                template = 'static_analysis/ios_binary_analysis.html'
                if api:
                    return context
                else:
                    return render(request, template, context)
            elif file_type == 'ios':
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
                    app_dict['app_dir'] = app_dir.as_posix() + '/'
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
                    code_analysis_dic = ios_source_analysis(
                        app_dict['app_dir'])
                    # Get App Icon
                    app_dict['icon_found'] = get_icon_source(
                        app_dict['md5_hash'],
                        app_dict['app_dir'])
                    # Firebase DB Check
                    code_analysis_dic['firebase'] = firebase_analysis(
                        list(set(code_analysis_dic['urls_list'])))
                    fake_bin_dict = {
                        'checksec': {},
                        'libraries': [],
                        'bin_code_analysis': {},
                        'strings': [],
                        'bin_info': {},
                        'bin_type': code_analysis_dic['source_type'],
                    }
                    # Saving to DB
                    logger.info('Connecting to DB')
                    if rescan:
                        logger.info('Updating Database...')
                        save_or_update(
                            'update',
                            app_dict,
                            infoplist_dict,
                            code_analysis_dic,
                            fake_bin_dict,
                            all_files)
                        update_scan_timestamp(app_dict['md5_hash'])
                    else:
                        logger.info('Saving to Database')
                        save_or_update(
                            'save',
                            app_dict,
                            infoplist_dict,
                            code_analysis_dic,
                            fake_bin_dict,
                            all_files)
                    context = get_context_from_analysis(
                        app_dict,
                        infoplist_dict,
                        code_analysis_dic,
                        fake_bin_dict,
                        all_files)
                context['average_cvss'], context[
                    'security_score'] = score(context['code_analysis'])
                template = 'static_analysis/ios_source_analysis.html'
                if api:
                    return context
                else:
                    return render(request, template, context)
            else:
                msg = 'File Type not supported!'
                if api:
                    return print_n_send_error_response(request, msg, True)
                else:
                    return print_n_send_error_response(request, msg, False)
        else:
            msg = 'Hash match failed or Invalid file extension or file type'
            if api:
                return print_n_send_error_response(request, msg, True)
            else:
                return print_n_send_error_response(request, msg, False)
    except Exception as exp:
        logger.exception('Error Performing Static Analysis')
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)
