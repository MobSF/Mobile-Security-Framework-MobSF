# -*- coding: utf_8 -*-
"""
iOS Static Code Analysis
"""
import re
import os
import io
import shutil

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from StaticAnalyzer.views.ios.db_interaction import (
    get_context_from_analysis_ipa,
    get_context_from_db_entry_ipa,
    update_db_entry_ipa,
    create_db_entry_ipa,

    get_context_from_analysis_ios,
    get_context_from_db_entry_ios,
    update_db_entry_ios,
    create_db_entry_ios,
)


from StaticAnalyzer.views.ios.binary_analysis import (
    binary_analysis,
)
from StaticAnalyzer.views.ios.code_analysis import (
    ios_source_analysis,
)

from StaticAnalyzer.views.ios.plist_analysis import (
    plist_analysis,
    convert_bin_xml
)


from StaticAnalyzer.views.shared_func import (
    file_size,
    hash_gen,
    unzip,
    score
)
from StaticAnalyzer.models import StaticAnalyzerIPA, StaticAnalyzerIOSZIP

from MobSF.utils import (
    print_n_send_error_response,
    PrintException,
    isFileExists
)

import StaticAnalyzer.views.android.VirusTotal as VirusTotal

##############################################################
# Code to support iOS Static Code Analysis
##############################################################


def ios_list_files(src, md5_hash, binary_form, mode):
    """List iOS files"""
    try:
        print("[INFO] Get Files, BIN Plist -> XML, and Normalize")
        # Multi function, Get Files, BIN Plist -> XML, normalize + to x
        filez = []
        certz = []
        sfiles = []
        database = []
        plist = []
        for dirname, _, files in os.walk(src):
            for jfile in files:
                if not jfile.endswith(".DS_Store"):
                    file_path = os.path.join(src, dirname, jfile)
                    if "+" in jfile:
                        plus2x = os.path.join(
                            src, dirname, jfile.replace("+", "x"))
                        shutil.move(file_path, plus2x)
                        file_path = plus2x
                    fileparam = file_path.replace(src, '')
                    filez.append(fileparam)
                    ext = jfile.split('.')[-1]
                    if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                        certz.append({
                            'file_path': escape(file_path.replace(src, '')),
                            'type': None,
                            'hash': None
                        })

                    if re.search("db|sqlitedb|sqlite", ext):
                        database.append({
                            'file_path': escape(fileparam),
                            'type': mode,
                            'hash': md5_hash
                        })

                    if jfile.endswith(".plist"):
                        if binary_form:
                            convert_bin_xml(file_path)
                        plist.append({
                            'file_path': escape(fileparam),
                            'type': mode,
                            'hash': md5_hash
                        })

        if len(database) > 0:
            sfiles.append({"issue": "SQLite Files", "files": database})
        if len(plist) > 0:
            sfiles.append({"issue": "Plist Files", "files": plist})
        if len(certz) > 0:
            sfiles.append(
                {"issue": "Certificate/Key Files Hardcoded inside the App.", "files": certz})
        return filez, sfiles
    except:
        PrintException("[ERROR] iOS List Files")


def static_analyzer_ios(request, api=False):
    """Module that performs iOS IPA/ZIP Static Analysis"""
    try:
        print("[INFO] iOS Static Analysis Started")
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
        if ((md5_match) and
                (filename.lower().endswith('.ipa') or
                 filename.lower().endswith('.zip')
                 ) and
                (file_type in ['ipa', 'ios'])
            ):
            app_dict = {}
            app_dict["directory"] = settings.BASE_DIR  # BASE DIR
            app_dict["file_name"] = filename  # APP ORGINAL NAME
            app_dict["md5_hash"] = checksum  # MD5
            app_dict["app_dir"] = os.path.join(
                settings.UPLD_DIR, app_dict["md5_hash"] + '/')  # APP DIRECTORY
            tools_dir = os.path.join(
                app_dict["directory"], 'StaticAnalyzer/tools/mac/')  # TOOLS DIR
            if file_type == 'ipa':
                # DB
                ipa_db = StaticAnalyzerIPA.objects.filter(
                    MD5=app_dict["md5_hash"])
                if ipa_db.exists() and rescan == '0':
                    context = get_context_from_db_entry_ipa(ipa_db)
                else:
                    print("[INFO] iOS Binary (IPA) Analysis Started")
                    app_dict["app_file"] = app_dict[
                        "md5_hash"] + '.ipa'  # NEW FILENAME
                    app_dict["app_path"] = app_dict["app_dir"] + \
                        app_dict["app_file"]  # APP PATH
                    app_dict["bin_dir"] = os.path.join(
                        app_dict["app_dir"], "Payload/")
                    app_dict["size"] = str(
                        file_size(app_dict["app_path"])) + 'MB'  # FILE SIZE
                    app_dict["sha1"], app_dict["sha256"] = hash_gen(
                        app_dict["app_path"])  # SHA1 & SHA256 HASHES
                    print("[INFO] Extracting IPA")
                    # EXTRACT IPA
                    unzip(app_dict["app_path"], app_dict["app_dir"])
                    # Get Files, normalize + to x,
                    # and convert binary plist -> xml
                    files, sfiles = ios_list_files(
                        app_dict["bin_dir"], app_dict["md5_hash"], True, 'ipa')
                    infoplist_dict = plist_analysis(app_dict["bin_dir"], False)
                    bin_analysis_dict = binary_analysis(
                        app_dict["bin_dir"], tools_dir, app_dict["app_dir"], infoplist_dict.get("bin"))
                    # Saving to DB
                    print("\n[INFO] Connecting to DB")
                    if rescan == '1':
                        print("\n[INFO] Updating Database...")
                        update_db_entry_ipa(
                            app_dict, infoplist_dict, bin_analysis_dict, files, sfiles)
                    elif rescan == '0':
                        print("\n[INFO] Saving to Database")
                        create_db_entry_ipa(
                            app_dict, infoplist_dict, bin_analysis_dict, files, sfiles)
                    context = get_context_from_analysis_ipa(
                        app_dict, infoplist_dict, bin_analysis_dict, files, sfiles)

                context['VT_RESULT'] = None
                if settings.VT_ENABLED:
                    vt = VirusTotal.VirusTotal()
                    context['VT_RESULT'] = vt.get_result(
                        os.path.join(app_dict['app_dir'], app_dict[
                                     'md5_hash']) + '.ipa',
                        app_dict['md5_hash']
                    )

                template = "static_analysis/ios_binary_analysis.html"
                if api:
                    return context
                else:
                    return render(request, template, context)
            elif file_type == 'ios':
                ios_zip_db = StaticAnalyzerIOSZIP.objects.filter(
                    MD5=app_dict["md5_hash"])
                if ios_zip_db.exists() and rescan == '0':
                    context = get_context_from_db_entry_ios(ios_zip_db)
                else:
                    print("[INFO] iOS Source Code Analysis Started")
                    app_dict["app_file"] = app_dict[
                        "md5_hash"] + '.zip'  # NEW FILENAME
                    app_dict["app_path"] = app_dict["app_dir"] + \
                        app_dict["app_file"]  # APP PATH
                    # ANALYSIS BEGINS - Already Unzipped
                    print("[INFO] ZIP Already Extracted")
                    app_dict["size"] = str(
                        file_size(app_dict["app_path"])) + 'MB'  # FILE SIZE
                    app_dict["sha1"], app_dict["sha256"] = hash_gen(
                        app_dict["app_path"])  # SHA1 & SHA256 HASHES
                    files, sfiles = ios_list_files(
                        app_dict["app_dir"], app_dict["md5_hash"], False, 'ios')
                    infoplist_dict = plist_analysis(app_dict["app_dir"], True)
                    code_analysis_dic = ios_source_analysis(
                        app_dict["app_dir"])
                    # Saving to DB
                    print("\n[INFO] Connecting to DB")
                    if rescan == '1':
                        print("\n[INFO] Updating Database...")
                        update_db_entry_ios(
                            app_dict, infoplist_dict, code_analysis_dic, files, sfiles)
                    elif rescan == '0':
                        print("\n[INFO] Saving to Database")
                        create_db_entry_ios(
                            app_dict, infoplist_dict, code_analysis_dic, files, sfiles)
                    context = get_context_from_analysis_ios(
                        app_dict, infoplist_dict, code_analysis_dic, files, sfiles)
                context["average_cvss"], context[
                    "security_score"] = score(context["insecure"])
                template = "static_analysis/ios_source_analysis.html"
                if api:
                    return context
                else:
                    return render(request, template, context)
            else:
                msg = "File Type not supported!"
                if api:
                    return print_n_send_error_response(request, msg, True)
                else:
                    return print_n_send_error_response(request, msg, False)
        else:
            msg = "Hash match failed or Invalid file extension or file type"
            if api:
                return print_n_send_error_response(request, msg, True)
            else:
                return print_n_send_error_response(request, msg, False)
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)
