# -*- coding: utf_8 -*-
"""
Android Static Code Analysis
"""

import re
import os
import zipfile

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
    PrintException,
    zipdir
)

from StaticAnalyzer.models import StaticAnalyzerAndroid
from StaticAnalyzer.views.shared_func import (
    FileSize,
    HashGen,
    Unzip
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


@register.filter
def key(data, key_name):
    """Return the data for a key_name."""
    return data.get(key_name)


def static_analyzer(request):
    """Do static analysis on an request and save to db."""
    try:
        # Input validation
        app_dic = {}
        typ = request.GET['type']
        # output = request.GET['format'] # Later for json output
        match = re.match('^[0-9a-f]{32}$', request.GET['checksum'])
        if (
                (
                    match
                ) and (
                    request.GET['name'].lower().endswith('.apk') or
                    request.GET['name'].lower().endswith('.zip')
                ) and (
                    typ in ['zip', 'apk']
                )
        ):
            app_dic['dir'] = settings.BASE_DIR  # BASE DIR
            app_dic['app_name'] = request.GET['name']  # APP ORGINAL NAME
            app_dic['md5'] = request.GET['checksum']  # MD5
            app_dic['app_dir'] = os.path.join(settings.UPLD_DIR, app_dic[
                                              'md5'] + '/')  # APP DIRECTORY
            app_dic['tools_dir'] = os.path.join(
                app_dic['dir'], 'StaticAnalyzer/tools/')  # TOOLS DIR
            # DWD_DIR = settings.DWD_DIR # not needed? Var is never used.
            print "[INFO] Starting Analysis on : " + app_dic['app_name']
            rescan = str(request.GET.get('rescan', 0))
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
                        FileSize(app_dic['app_path'])) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic[
                        'sha256'] = HashGen(app_dic['app_path'])

                    app_dic['files'] = Unzip(
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
                    dex_2_jar(app_dic['app_path'], app_dic[
                              'app_dir'], app_dic['tools_dir'])
                    dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])
                    jar_2_java(app_dic['app_dir'], app_dic['tools_dir'])
                    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        app_dic['md5'],
                        man_an_dic['permissons'],
                        "apk"
                    )
                    print "\n[INFO] Generating Java and Smali Downloads"
                    gen_downloads(app_dic['app_dir'], app_dic['md5'])

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
                                bin_an_buff
                            )
                        elif rescan == '0':
                            print "\n[INFO] Saving to Database"
                            create_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic,
                                bin_an_buff
                            )
                    except:
                        PrintException("[ERROR] Saving to Database Failed")
                    context = get_context_from_analysis(
                        app_dic,
                        man_data_dic,
                        man_an_dic,
                        code_an_dic,
                        cert_dic,
                        bin_an_buff
                    )
                template = "static_analysis/static_analysis.html"
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
                #Above fields are only available for APK and not ZIP
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
                    app_dic['files'] = Unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    # Check if Valid Directory Structure and get ZIP Type
                    pro_type, valid = valid_android_zip(app_dic['app_dir'])
                    if valid and pro_type == 'ios':
                        print "[INFO] Redirecting to iOS Source Code Analyzer"
                        return HttpResponseRedirect(
                            '/StaticAnalyzer_iOS/?name=' + app_dic['app_name'] +
                            '&type=ios&checksum=' + app_dic['md5']
                        )
                    app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                                   'files'])
                    print "[INFO] ZIP Type - " + pro_type
                    if valid and (pro_type in ['eclipse', 'studio']):
                        # ANALYSIS BEGINS
                        app_dic['size'] = str(
                            FileSize(app_dic['app_path'])) + 'MB'  # FILE SIZE
                        app_dic['sha1'], app_dic[
                            'sha256'] = HashGen(app_dic['app_path'])

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

                        code_an_dic = code_analysis(
                            app_dic['app_dir'],
                            app_dic['md5'],
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
                                    bin_an_buff
                                )
                            elif rescan == '0':
                                print "\n[INFO] Saving to Database"
                                create_db_entry(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic,
                                    bin_an_buff
                                )
                        except:
                            PrintException("[ERROR] Saving to Database Failed")
                        context = get_context_from_analysis(
                            app_dic,
                            man_data_dic,
                            man_an_dic,
                            code_an_dic,
                            cert_dic,
                            bin_an_buff
                        )
                    else:
                        return HttpResponseRedirect('/zip_format/')
                template = "static_analysis/static_analysis_android_zip.html"
                return render(request, template, context)
            else:
                print "\n[ERROR] Only APK,IPA and Zipped Android/iOS Source code supported now!"
        else:
            return HttpResponseRedirect('/error/')

    except Exception as excep:
        PrintException("[ERROR] Static Analyzer")
        context = {
            'title': 'Error',
            'exp': excep.message,
            'doc': excep.__doc__
        }
        template = "general/error.html"
        return render(request, template, context)


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


def gen_downloads(app_dir, md5):
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
    except:
        PrintException("[ERROR] Generating Downloads")
