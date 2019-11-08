# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

import logging
import os
import re
import shutil

import MalwareAnalyzer.views.Trackers as Trackers
import MalwareAnalyzer.views.VirusTotal as VirusTotal
from MalwareAnalyzer.views.apkid import apkid_analysis
from MalwareAnalyzer.views.domain_check import malware_check

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register

from MobSF.utils import (is_file_exists,
                         print_n_send_error_response)

from StaticAnalyzer.models import StaticAnalyzerAndroid
from StaticAnalyzer.views.android.binary_analysis import (elf_analysis,
                                                          res_analysis)
from StaticAnalyzer.views.android.cert_analysis import (
    cert_info, get_hardcoded_cert_keystore)
from StaticAnalyzer.views.android.code_analysis import code_analysis
from StaticAnalyzer.views.android.converter import (apk_2_java, dex_2_smali)
from StaticAnalyzer.views.android.db_interaction import (
    create_db_entry, get_context_from_analysis, get_context_from_db_entry,
    update_db_entry)
from StaticAnalyzer.views.android.icon_analysis import (find_icon_path_zip,
                                                        get_icon)
from StaticAnalyzer.views.android.manifest_analysis import (get_manifest,
                                                            manifest_analysis,
                                                            manifest_data)
from StaticAnalyzer.views.android.playstore import get_app_details
from StaticAnalyzer.views.android.strings import strings_jar
from StaticAnalyzer.views.shared_func import (file_size, firebase_analysis,
                                              hash_gen, score, unzip,
                                              update_scan_timestamp)

from androguard.core.bytecodes import apk

try:
    import io
    StringIO = io.StringIO  # noqa F401
except ImportError:
    from io import StringIO  # noqa F401


logger = logging.getLogger(__name__)


@register.filter
def key(data, key_name):
    """Return the data for a key_name."""
    return data.get(key_name)


def static_analyzer(request, api=False):
    """Do static analysis on an request and save to db."""
    try:
        if api:
            typ = request.POST['scan_type']
            checksum = request.POST['hash']
            filename = request.POST['file_name']
            rescan = str(request.POST.get('re_scan', 0))
        else:
            typ = request.GET['type']
            checksum = request.GET['checksum']
            filename = request.GET['name']
            rescan = str(request.GET.get('rescan', 0))
        # Input validation
        app_dic = {}
        match = re.match('^[0-9a-f]{32}$', checksum)
        if (
                (
                    match
                ) and (
                    filename.lower().endswith('.apk')
                    or filename.lower().endswith('.zip')
                ) and (
                    typ in ['zip', 'apk']
                )
        ):
            app_dic['dir'] = settings.BASE_DIR  # BASE DIR
            app_dic['app_name'] = filename  # APP ORGINAL NAME
            app_dic['md5'] = checksum  # MD5
            app_dic['app_dir'] = os.path.join(settings.UPLD_DIR, app_dic[
                                              'md5'] + '/')  # APP DIRECTORY
            app_dic['tools_dir'] = os.path.join(
                app_dic['dir'], 'StaticAnalyzer/tools/')  # TOOLS DIR
            logger.info('Starting Analysis on : %s', app_dic['app_name'])

            if typ == 'apk':
                # Check if in DB
                # pylint: disable=E1101
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists() and rescan == '0':
                    context = get_context_from_db_entry(db_entry)
                else:
                    app_dic['app_file'] = app_dic[
                        'md5'] + '.apk'  # NEW FILENAME
                    app_dic['app_path'] = (app_dic['app_dir']
                                           + app_dic['app_file'])  # APP PATH

                    # ANALYSIS BEGINS
                    app_dic['size'] = str(
                        file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic[
                        'sha256'] = hash_gen(app_dic['app_path'])

                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    if not app_dic['files']:
                        # Can't Analyze APK, bail out.
                        msg = 'APK file is invalid or corrupt'
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
                    app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                                   'files'])

                    logger.info('APK Extracted')

                    # Manifest XML
                    app_dic['parsed_xml'] = get_manifest(
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        '',
                        True,
                    )

                    # get app_name
                    app_dic['real_name'] = get_app_name(
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        True,
                    )

                    # Get icon
                    res_path = os.path.join(app_dic['app_dir'], 'res')
                    app_dic['icon_hidden'] = True
                    # Even if the icon is hidden, try to guess it by the
                    # default paths
                    app_dic['icon_found'] = False
                    app_dic['icon_path'] = ''
                    # TODO: Check for possible different names for resource
                    # folder?
                    if os.path.exists(res_path):
                        icon_dic = get_icon(
                            app_dic['app_path'], res_path)
                        if icon_dic:
                            app_dic['icon_hidden'] = icon_dic['hidden']
                            app_dic['icon_found'] = bool(icon_dic['path'])
                            app_dic['icon_path'] = icon_dic['path']

                    # Set Manifest link
                    app_dic['mani'] = ('../ManifestView/?md5='
                                       + app_dic['md5']
                                       + '&type=apk&bin=1')
                    man_data_dic = manifest_data(app_dic['parsed_xml'])
                    app_dic['playstore'] = get_app_details(
                        man_data_dic['packagename'])
                    man_an_dic = manifest_analysis(
                        app_dic['parsed_xml'],
                        man_data_dic)
                    bin_an_buff = []
                    bin_an_buff += elf_analysis(app_dic['app_dir'])
                    bin_an_buff += res_analysis(app_dic['app_dir'])
                    cert_dic = cert_info(
                        app_dic['app_dir'],
                        app_dic['app_file'])
                    apkid_results = apkid_analysis(app_dic[
                        'app_dir'], app_dic['app_path'], app_dic['app_name'])
                    tracker = Trackers.Trackers(
                        app_dic['app_dir'], app_dic['tools_dir'])
                    tracker_res = tracker.get_trackers()

                    apk_2_java(app_dic['app_path'], app_dic['app_dir'],
                               app_dic['tools_dir'])

                    dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])

                    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        man_an_dic['permissons'],
                        'apk')

                    # Get the strings
                    string_res = strings_jar(
                        app_dic['app_file'],
                        app_dic['app_dir'])
                    if string_res:
                        app_dic['strings'] = string_res['strings']
                        code_an_dic['urls_list'].extend(
                            string_res['urls_list'])
                        code_an_dic['urls'].extend(string_res['url_nf'])
                        code_an_dic['emails'].extend(string_res['emails_nf'])
                    else:
                        app_dic['strings'] = []

                    # Firebase DB Check
                    code_an_dic['firebase'] = firebase_analysis(
                        list(set(code_an_dic['urls_list'])))
                    # Domain Extraction and Malware Check
                    logger.info(
                        'Performing Malware Check on extracted Domains')
                    code_an_dic['domains'] = malware_check(
                        list(set(code_an_dic['urls_list'])))
                    # Copy App icon
                    copy_icon(app_dic['md5'], app_dic['icon_path'])
                    app_dic['zipped'] = '&type=apk'

                    logger.info('Connecting to Database')
                    try:
                        # SAVE TO DB
                        if rescan == '1':
                            logger.info('Updating Database...')
                            update_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff,
                                apkid_results,
                                tracker_res,
                            )
                            update_scan_timestamp(app_dic['md5'])
                        elif rescan == '0':
                            logger.info('Saving to Database')
                            create_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff,
                                apkid_results,
                                tracker_res,
                            )
                    except Exception:
                        logger.exception('Saving to Database Failed')
                    context = get_context_from_analysis(
                        app_dic,
                        man_data_dic,
                        man_an_dic,
                        code_an_dic,
                        cert_dic,
                        bin_an_buff,
                        apkid_results,
                        tracker_res,
                    )
                context['average_cvss'], context[
                    'security_score'] = score(context['findings'])
                context['dynamic_analysis_done'] = is_file_exists(
                    os.path.join(app_dic['app_dir'], 'logcat.txt'))

                context['VT_RESULT'] = None
                if settings.VT_ENABLED:
                    vt = VirusTotal.VirusTotal()
                    context['VT_RESULT'] = vt.get_result(
                        os.path.join(app_dic['app_dir'],
                                     app_dic['md5']) + '.apk',
                        app_dic['md5'])
                template = 'static_analysis/android_binary_analysis.html'
                if api:
                    return context
                else:
                    return render(request, template, context)
            elif typ == 'zip':
                # Check if in DB
                # pylint: disable=E1101
                cert_dic = {}
                cert_dic['cert_info'] = ''
                cert_dic['issued'] = ''
                cert_dic['sha256Digest'] = False
                bin_an_buff = []
                app_dic['strings'] = ''
                app_dic['zipped'] = ''
                # Above fields are only available for APK and not ZIP
                db_entry = StaticAnalyzerAndroid.objects.filter(
                    MD5=app_dic['md5'])
                if db_entry.exists() and rescan == '0':
                    context = get_context_from_db_entry(db_entry)
                else:
                    app_dic['app_file'] = app_dic[
                        'md5'] + '.zip'  # NEW FILENAME
                    app_dic['app_path'] = (app_dic['app_dir']
                                           + app_dic['app_file'])  # APP PATH
                    logger.info('Extracting ZIP')
                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    # Check if Valid Directory Structure and get ZIP Type
                    pro_type, valid = valid_android_zip(app_dic['app_dir'])
                    if valid and pro_type == 'ios':
                        logger.info('Redirecting to iOS Source Code Analyzer')
                        if api:
                            return {'type': 'ios'}
                        else:
                            return HttpResponseRedirect(
                                '/StaticAnalyzer_iOS/?name='
                                + app_dic['app_name']
                                + '&type=ios&checksum='
                                + app_dic['md5'])
                    app_dic['certz'] = get_hardcoded_cert_keystore(
                        app_dic['files'])
                    app_dic['zipped'] = pro_type
                    logger.info('ZIP Type - %s', pro_type)
                    if valid and (pro_type in ['eclipse', 'studio']):
                        # ANALYSIS BEGINS
                        app_dic['size'] = str(
                            file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                        app_dic['sha1'], app_dic[
                            'sha256'] = hash_gen(app_dic['app_path'])

                        # Manifest XML
                        app_dic['persed_xml'] = get_manifest(
                            '',
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            pro_type,
                            False,
                        )

                        # get app_name
                        app_dic['real_name'] = get_app_name(
                            app_dic['app_path'],
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            False,
                        )

                        # Set manifest view link
                        app_dic['mani'] = (
                            '../ManifestView/?md5='
                            + app_dic['md5'] + '&type='
                            + pro_type + '&bin=0'
                        )

                        man_data_dic = manifest_data(app_dic['persed_xml'])
                        app_dic['playstore'] = get_app_details(
                            man_data_dic['packagename'])
                        man_an_dic = manifest_analysis(
                            app_dic['persed_xml'],
                            man_data_dic,
                        )
                        # Get icon
                        eclipse_res_path = os.path.join(
                            app_dic['app_dir'], 'res')
                        studio_res_path = os.path.join(
                            app_dic['app_dir'], 'app', 'src', 'main', 'res')
                        if os.path.exists(eclipse_res_path):
                            res_path = eclipse_res_path
                        elif os.path.exists(studio_res_path):
                            res_path = studio_res_path
                        else:
                            res_path = ''

                        app_dic['icon_hidden'] = man_an_dic['icon_hidden']
                        app_dic['icon_found'] = False
                        app_dic['icon_path'] = ''
                        if res_path:
                            app_dic['icon_path'] = find_icon_path_zip(
                                res_path, man_data_dic['icons'])
                            if app_dic['icon_path']:
                                app_dic['icon_found'] = True

                        if app_dic['icon_path']:
                            if os.path.exists(app_dic['icon_path']):
                                shutil.copy2(
                                    app_dic['icon_path'],
                                    os.path.join(
                                        settings.DWD_DIR,
                                        app_dic['md5'] + '-icon.png'))

                        code_an_dic = code_analysis(
                            app_dic['app_dir'],
                            man_an_dic['permissons'],
                            pro_type,
                        )
                        # Firebase DB Check
                        code_an_dic['firebase'] = firebase_analysis(
                            list(set(code_an_dic['urls_list'])))
                        # Domain Extraction and Malware Check
                        logger.info(
                            'Performing Malware Check on extracted Domains')
                        code_an_dic['domains'] = malware_check(
                            list(set(code_an_dic['urls_list'])))
                        logger.info('Connecting to Database')
                        try:
                            # SAVE TO DB
                            if rescan == '1':
                                logger.info('Updating Database...')
                                update_db_entry(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff,
                                    {},
                                    {},
                                )
                                update_scan_timestamp(app_dic['md5'])
                            elif rescan == '0':
                                logger.info('Saving to Database')
                                create_db_entry(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff,
                                    {},
                                    {},
                                )
                        except Exception:
                            logger.exception('Saving to Database Failed')
                        context = get_context_from_analysis(
                            app_dic,
                            man_data_dic,
                            man_an_dic,
                            code_an_dic,
                            cert_dic,
                            bin_an_buff,
                            {},
                            {},
                        )
                    else:
                        msg = 'This ZIP Format is not supported'
                        if api:
                            return print_n_send_error_response(
                                request,
                                msg,
                                True)
                        else:
                            print_n_send_error_response(request, msg, False)
                            return HttpResponseRedirect('/zip_format/')
                context['average_cvss'], context[
                    'security_score'] = score(context['findings'])
                template = 'static_analysis/android_source_analysis.html'
                if api:
                    return context
                else:
                    return render(request, template, context)
            else:
                err = ('Only APK,IPA and Zipped '
                       'Android/iOS Source code supported now!')
                logger.error(err)
        else:
            msg = 'Hash match failed or Invalid file extension or file type'
            if api:
                return print_n_send_error_response(request, msg, True)
            else:
                return print_n_send_error_response(request, msg, False)

    except Exception as excep:
        logger.exception('Error Performing Static Analysis')
        msg = str(excep)
        exp = excep.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def valid_android_zip(app_dir):
    """Test if this is an valid android zip."""
    try:
        logger.info('Checking for ZIP Validity and Mode')
        # Eclipse
        man = os.path.isfile(os.path.join(app_dir, 'AndroidManifest.xml'))
        src = os.path.exists(os.path.join(app_dir, 'src/'))
        if man and src:
            return 'eclipse', True
        # Studio
        man = os.path.isfile(
            os.path.join(app_dir, 'app/src/main/AndroidManifest.xml'),
        )
        src = os.path.exists(os.path.join(app_dir, 'app/src/main/java/'))
        if man and src:
            return 'studio', True
        # iOS Source
        xcode = [f for f in os.listdir(app_dir) if f.endswith('.xcodeproj')]
        if xcode:
            return 'ios', True
        return '', False
    except Exception:
        logger.exception('Determining Upload type')


def copy_icon(md5, icon_path=''):
    """Copy app icon."""
    try:
        # Icon
        icon_path = icon_path.encode('utf-8')
        if icon_path:
            if os.path.exists(icon_path):
                shutil.copy2(icon_path, os.path.join(
                    settings.DWD_DIR, md5 + '-icon.png'))
    except Exception:
        logger.exception('Generating Downloads')


def get_app_name(app_path, app_dir, tools_dir, is_apk):
    """Get app name."""
    data = ''
    if is_apk:
        a = apk.APK(app_path)
        real_name = a.get_app_name()
        return real_name
    else:
        strings_path = os.path.join(app_dir,
                                    'app/src/main/res/values/strings.xml')
        eclipse_path = os.path.join(app_dir,
                                    'res/values/strings.xml')
        if os.path.exists(strings_path):
            strings_file = strings_path
        elif os.path.exists(eclipse_path):
            strings_file = eclipse_path
    if not os.path.exists(strings_file):
        logger.warning('Cannot find app name')
        return ''

    with open(strings_file, 'r', encoding='utf-8') as f:
        data = f.read()

    app_name_match = re.search(r'<string name=\"app_name\">(.*)</string>',
                               data)

    if len(app_name_match.groups()) <= 0:
        return ''
    return app_name_match.group(app_name_match.lastindex)
