# -*- coding: utf_8 -*-
"""
Android Static Code Analysis
"""

import re
import os
import zipfile
import shutil

try:
    import StringIO
    StringIO = StringIO.StringIO
except ImportError:
    from io import StringIO

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.template.defaulttags import register

from MobSF.utils import (
    print_n_send_error_response,
    PrintException,
    zipdir
)

from StaticAnalyzer.models import StaticAnalyzerAndroid
from StaticAnalyzer.views.shared_func import (
    file_size,
    hash_gen,
    unzip
)

from StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    get_context_from_analysis,
    update_db_entry,
    create_db_entry,
)

from StaticAnalyzer.views.android.code_analysis import code_analysis
from StaticAnalyzer.views.android.strings import strings
from StaticAnalyzer.views.android.converter import (
    dex_2_jar,
    dex_2_smali,
    jar_2_java
)
from StaticAnalyzer.views.android.cert_analysis import (
    get_hardcoded_cert_keystore,
    cert_info
)
from StaticAnalyzer.views.android.manifest_analysis import (
    manifest_data,
    manifest_analysis,
    get_manifest
)
from StaticAnalyzer.views.android.binary_analysis import (
    elf_analysis,
    res_analysis,
)
from StaticAnalyzer.views.android.icon_analysis import (
    get_icon,
    find_icon_path_zip,
)

import StaticAnalyzer.views.android.VirusTotal as VirusTotal

from MalwareAnalyzer.views import apkid_analysis


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
                    filename.lower().endswith('.apk') or
                    filename.lower().endswith('.zip')
                ) and (
                    typ in ['zip', 'apk']
                )
        ):
            app_dic['dir'] = settings.BASE_DIR  # BASE DIR
            app_dic['app_name'] = filename  # APP ORGINAL NAME
            app_dic['md5'] = checksum # MD5
            app_dic['app_dir'] = os.path.join(settings.UPLD_DIR, app_dic[
                                              'md5'] + '/')  # APP DIRECTORY
            app_dic['tools_dir'] = os.path.join(
                app_dic['dir'], 'StaticAnalyzer/tools/')  # TOOLS DIR
            # DWD_DIR = settings.DWD_DIR # not needed? Var is never used.
            print "[INFO] Starting Analysis on : " + app_dic['app_name']
            
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
                    app_dic['app_path'] = app_dic['app_dir'] + \
                        app_dic['app_file']  # APP PATH

                    # ANALYSIS BEGINS
                    app_dic['size'] = str(
                        file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic[
                        'sha256'] = hash_gen(app_dic['app_path'])

                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                                   'files'])

                    print "[INFO] APK Extracted"

                    # Manifest XML
                    app_dic['parsed_xml'] = get_manifest(
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        '',
                        True
                    )

                    # Get icon
                    res_path = os.path.join(app_dic['app_dir'], 'res')
                    app_dic['icon_hidden'] = True
                    app_dic['icon_found'] = False  # Even if the icon is hidden, try to guess it by the default paths
                    app_dic['icon_path'] = ''
                    if os.path.exists(res_path):  # TODO: Check for possible different names for resource folder?
                        icon_dic = get_icon(app_dic['app_path'], res_path, app_dic['tools_dir'])
                        if icon_dic:
                            app_dic['icon_hidden'] = icon_dic['hidden']
                            app_dic['icon_found'] = bool(icon_dic['path'])
                            app_dic['icon_path'] = icon_dic['path']



                    # Set Manifest link
                    app_dic['mani'] = '../ManifestView/?md5=' + \
                        app_dic['md5'] + '&type=apk&bin=1'
                    man_data_dic = manifest_data(app_dic['parsed_xml'])

                    man_an_dic = manifest_analysis(
                        app_dic['parsed_xml'],
                        man_data_dic
                    )
                    bin_an_buff = []
                    bin_an_buff += elf_analysis(
                        app_dic['app_dir'],
                        "apk"
                    )
                    bin_an_buff += res_analysis(
                        app_dic['app_dir'],
                        "apk"
                    )
                    cert_dic = cert_info(
                        app_dic['app_dir'], app_dic['tools_dir'])
                    apkid_results = apkid_analysis(app_dic[
                        'app_dir'])
                    dex_2_jar(app_dic['app_path'], app_dic[
                              'app_dir'], app_dic['tools_dir'])
                    dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])
                    jar_2_java(app_dic['app_dir'], app_dic['tools_dir'])
                    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        man_an_dic['permissons'],
                        "apk"
                    )
                    print "\n[INFO] Generating Java and Smali Downloads"
                    gen_downloads(app_dic['app_dir'], app_dic['md5'], app_dic['icon_path'])

                    # Get the strings
                    app_dic['strings'] = strings(
                        app_dic['app_file'],
                        app_dic['app_dir'],
                        app_dic['tools_dir']
                    )
                    app_dic['zipped'] = '&type=apk'

                    print "\n[INFO] Connecting to Database"
                    try:
                        # SAVE TO DB
                        if rescan == '1':
                            print "\n[INFO] Updating Database..."
                            update_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff,
                                apkid_results,
                            )
                        elif rescan == '0':
                            print "\n[INFO] Saving to Database"
                            create_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff,
                                apkid_results,
                            )
                    except:
                        PrintException("[ERROR] Saving to Database Failed")
                    context = get_context_from_analysis(
                        app_dic,
                        man_data_dic,
                        man_an_dic,
                        code_an_dic,
                        cert_dic,
                        bin_an_buff,
                        apkid_results,
                    )

                context['dynamic_analysis_done'] = os.path.exists(
                    os.path.join(app_dic['app_dir'], 'logcat.txt'))

                context['VT_RESULT'] = None
                if settings.VT_ENABLED:
                    vt = VirusTotal.VirusTotal()
                    context['VT_RESULT'] = vt.get_result(
                        os.path.join(app_dic['app_dir'], app_dic['md5']) + '.apk',
                        app_dic['md5']
                    )
                template = "static_analysis/static_analysis.html"
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
                    app_dic['app_path'] = app_dic['app_dir'] + \
                        app_dic['app_file']  # APP PATH
                    print "[INFO] Extracting ZIP"
                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    # Check if Valid Directory Structure and get ZIP Type
                    pro_type, valid = valid_android_zip(app_dic['app_dir'])
                    if valid and pro_type == 'ios':
                        print "[INFO] Redirecting to iOS Source Code Analyzer"
                        if api:
                            return {"type": "ios"}
                        else:
                            return HttpResponseRedirect(
                                '/StaticAnalyzer_iOS/?name=' + app_dic['app_name'] +
                                '&type=ios&checksum=' + app_dic['md5']
                            )
                    app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                                   'files'])
                    app_dic['zipped'] = pro_type
                    print "[INFO] ZIP Type - " + pro_type
                    if valid and (pro_type in ['eclipse', 'studio']):
                        # ANALYSIS BEGINS
                        app_dic['size'] = str(
                            file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                        app_dic['sha1'], app_dic[
                            'sha256'] = hash_gen(app_dic['app_path'])

                        # Manifest XML
                        app_dic['persed_xml'] = get_manifest(
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            pro_type,
                            False
                        )

                        # Set manifest view link
                        app_dic['mani'] = (
                            '../ManifestView/?md5=' +
                            app_dic['md5'] + '&type=' + pro_type + '&bin=0'
                        )

                        man_data_dic = manifest_data(app_dic['persed_xml'])

                        man_an_dic = manifest_analysis(
                            app_dic['persed_xml'],
                            man_data_dic
                        )

                        # Get icon
                        eclipse_res_path = os.path.join(app_dic['app_dir'], 'res')
                        studio_res_path = os.path.join(app_dic['app_dir'], 'app', 'src', 'main', 'res')
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
                            app_dic['icon_path'] = find_icon_path_zip(res_path, man_data_dic['icons'])
                            if app_dic['icon_path']:
                                app_dic['icon_found'] = True

                        if app_dic['icon_path']:
                            if os.path.exists(app_dic['icon_path']):
                                shutil.copy2(app_dic['icon_path'], os.path.join(settings.DWD_DIR, app_dic['md5'] + '-icon.png'))

                        code_an_dic = code_analysis(
                            app_dic['app_dir'],
                            man_an_dic['permissons'],
                            pro_type
                        )
                        print "\n[INFO] Connecting to Database"
                        try:
                            # SAVE TO DB
                            if rescan == '1':
                                print "\n[INFO] Updating Database..."
                                update_db_entry(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff,
                                    {},
                                )
                            elif rescan == '0':
                                print "\n[INFO] Saving to Database"
                                create_db_entry(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff,
                                    {},
                                )
                        except:
                            PrintException("[ERROR] Saving to Database Failed")
                        context = get_context_from_analysis(
                            app_dic,
                            man_data_dic,
                            man_an_dic,
                            code_an_dic,
                            cert_dic,
                            bin_an_buff,
                            {},
                        )
                    else:
                        msg = "This ZIP Format is not supported"
                        if api:
                            return print_n_send_error_response(request, msg, True)
                        else:
                            print_n_send_error_response(request, msg, False)
                            return HttpResponseRedirect('/zip_format/')
                template = "static_analysis/static_analysis_android_zip.html"
                if api:
                    return context     
                else:
                    return render(request, template, context)
            else:
                print "\n[ERROR] Only APK,IPA and Zipped Android/iOS Source code supported now!"
        else:
            msg = "Hash match failed or Invalid file extension or file type"
            if api:
                return print_n_send_error_response(request, msg, True)
            else:
                return print_n_send_error_response(request, msg, False)

    except Exception as excep:
        msg = str(excep)
        exp = excep.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def valid_android_zip(app_dir):
    """Test if this is an valid android zip."""
    try:
        print "[INFO] Checking for ZIP Validity and Mode"
        # Eclipse
        man = os.path.isfile(os.path.join(app_dir, "AndroidManifest.xml"))
        src = os.path.exists(os.path.join(app_dir, "src/"))
        if man and src:
            return 'eclipse', True
        # Studio
        man = os.path.isfile(
            os.path.join(
                app_dir, "app/src/main/AndroidManifest.xml"
            )
        )
        src = os.path.exists(os.path.join(app_dir, "app/src/main/java/"))
        if man and src:
            return 'studio', True
        # iOS Source
        xcode = [f for f in os.listdir(app_dir) if f.endswith(".xcodeproj")]
        if xcode:
            return 'ios', True
        return '', False
    except:
        PrintException("[ERROR] Determining Upload type")


def gen_downloads(app_dir, md5, icon_path=''):
    """Generate downloads for java and smali."""
    try:
        print "[INFO] Generating Downloads"
        # For Java
        directory = os.path.join(app_dir, 'java_source/')
        dwd_dir = os.path.join(settings.DWD_DIR, md5 + '-java.zip')
        zipf = zipfile.ZipFile(dwd_dir, 'w')
        zipdir(directory, zipf)
        zipf.close()
        # For Smali
        directory = os.path.join(app_dir, 'smali_source/')
        dwd_dir = os.path.join(settings.DWD_DIR, md5 + '-smali.zip')
        zipf = zipfile.ZipFile(dwd_dir, 'w')
        zipdir(directory, zipf)
        zipf.close()
        # Icon
        if icon_path:
            if os.path.exists(icon_path):
                shutil.copy2(icon_path, os.path.join(settings.DWD_DIR, md5 + '-icon.png'))


    except:
        PrintException("[ERROR] Generating Downloads")
