# -*- coding: utf_8 -*-
"""iOS Static Code Analysis."""
import logging
import os
import re

import MalwareAnalyzer.views.VirusTotal as VirusTotal

from django.conf import settings
from django.shortcuts import render

from MobSF.utils import (
    file_size,
    print_n_send_error_response,
)

from StaticAnalyzer.models import StaticAnalyzerIOS
from StaticAnalyzer.views.ios.appstore import app_search
from StaticAnalyzer.views.ios.binary_analysis import binary_analysis
from StaticAnalyzer.views.ios.code_analysis import ios_source_analysis
from StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_analysis,
    get_context_from_db_entry,
    save_or_update)
from StaticAnalyzer.views.ios.file_analysis import ios_list_files
from StaticAnalyzer.views.ios.file_recon import extract_urls_n_email
from StaticAnalyzer.views.ios.icon_analysis import (
    get_icon,
    get_icon_source,
)
from StaticAnalyzer.views.ios.plist_analysis import plist_analysis
from StaticAnalyzer.views.shared_func import (
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
        if api:
            file_type = request.POST['scan_type']
            checksum = request.POST['hash']
            rescan = str(request.POST.get('re_scan', 0))
            filename = request.POST['file_name']
        else:
            file_type = request.GET['type']
            checksum = request.GET['checksum']
            rescan = str(request.GET.get('rescan', 0))
            filename = request.GET['name']

        md5_match = re.match('^[0-9a-f]{32}$', checksum)
        if ((md5_match)
                and (filename.lower().endswith('.ipa')
            or filename.lower().endswith('.zip'))
                and (file_type in ['ipa', 'ios'])):
            app_dict = {}
            app_dict['directory'] = settings.BASE_DIR  # BASE DIR
            app_dict['file_name'] = filename  # APP ORGINAL NAME
            app_dict['md5_hash'] = checksum  # MD5
            app_dict['app_dir'] = os.path.join(
                settings.UPLD_DIR, app_dict['md5_hash'] + '/')  # APP DIRECTORY
            tools_dir = os.path.join(
                app_dict['directory'], 'StaticAnalyzer/tools/ios/')

            if file_type == 'ipa':
                # DB
                ipa_db = StaticAnalyzerIOS.objects.filter(
                    MD5=app_dict['md5_hash'])
                if ipa_db.exists() and rescan == '0':
                    context = get_context_from_db_entry(ipa_db)
                else:

                    logger.info('iOS Binary (IPA) Analysis Started')
                    app_dict['app_file'] = app_dict[
                        'md5_hash'] + '.ipa'  # NEW FILENAME
                    app_dict['app_path'] = (app_dict['app_dir']
                                            + app_dict['app_file'])
                    app_dict['bin_dir'] = os.path.join(
                        app_dict['app_dir'], 'Payload/')
                    app_dict['size'] = str(
                        file_size(app_dict['app_path'])) + 'MB'  # FILE SIZE
                    app_dict['sha1'], app_dict['sha256'] = hash_gen(
                        app_dict['app_path'])  # SHA1 & SHA256 HASHES
                    logger.info('Extracting IPA')
                    # EXTRACT IPA
                    unzip(app_dict['app_path'], app_dict['app_dir'])
                    # Get Files, normalize + to x,
                    # and convert binary plist -> xml
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
                    if rescan == '1':
                        logger.info('Updating Database...')
                        save_or_update(
                            'update',
                            app_dict,
                            infoplist_dict,
                            code_dict,
                            bin_analysis_dict,
                            all_files)
                        update_scan_timestamp(app_dict['md5_hash'])
                    elif rescan == '0':
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
                        os.path.join(app_dict['app_dir'], app_dict[
                                     'md5_hash']) + '.ipa',
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
                if ios_zip_db.exists() and rescan == '0':
                    context = get_context_from_db_entry(ios_zip_db)
                else:
                    logger.info('iOS Source Code Analysis Started')
                    app_dict['app_file'] = app_dict[
                        'md5_hash'] + '.zip'  # NEW FILENAME
                    app_dict['app_path'] = (app_dict['app_dir']
                                            + app_dict['app_file'])
                    # ANALYSIS BEGINS - Already Unzipped
                    logger.info('ZIP Already Extracted')
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
                        'bin_type': code_analysis_dic['source_type'],
                        'macho': {},
                        'bin_res': [],
                        'libs': [],
                        'strings': [],
                    }
                    # Saving to DB
                    logger.info('Connecting to DB')
                    if rescan == '1':
                        logger.info('Updating Database...')
                        save_or_update(
                            'update',
                            app_dict,
                            infoplist_dict,
                            code_analysis_dic,
                            fake_bin_dict,
                            all_files)
                        update_scan_timestamp(app_dict['md5_hash'])
                    elif rescan == '0':
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
        logger.exception('Error Perfroming Static Analysis')
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)
