
"""Android APK and Source Analysis."""
import logging
import os
import shutil

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.android import (
    apkid,
    behaviour_analysis,
    permissions,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
    is_dir_exists,
    is_file_exists,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import (
    StaticAnalyzerAndroid,
    StaticAnalyzerIOS,
)
from mobsf.StaticAnalyzer.views.common.binary.lib_analysis import (
    library_analysis,
)
from mobsf.StaticAnalyzer.views.android.app import (
    get_app_name,
    parse_apk,
)
from mobsf.StaticAnalyzer.views.android.cert_analysis import (
    cert_info,
    get_hardcoded_cert_keystore,
)
from mobsf.StaticAnalyzer.views.android.code_analysis import code_analysis
from mobsf.StaticAnalyzer.views.android.converter import (
    apk_2_java,
    dex_2_smali,
)
from mobsf.StaticAnalyzer.views.android.db_interaction import (
    get_context_from_db_entry,
    save_get_ctx,
)
from mobsf.StaticAnalyzer.views.android.icon_analysis import (
    get_icon_apk,
    get_icon_from_src,
)
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    manifest_analysis,
)
from mobsf.StaticAnalyzer.views.android.manifest_utils import (
    get_manifest,
    manifest_data,
)
from mobsf.StaticAnalyzer.views.android.playstore import get_app_details
from mobsf.StaticAnalyzer.views.android.strings import (
    get_strings_metadata,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    get_avg_cvss,
    hash_gen,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.firebase import (
    firebase_analysis,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)
APK_TYPE = 'apk'


def apk_analysis(request, app_dic, rescan, api):
    """APK Analysis."""
    checksum = app_dic['md5']
    app_dic['app_file'] = f'{checksum}.apk'
    app_dic['app_path'] = (
        app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    # Check if in DB
    # pylint: disable=E1101
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
    else:
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                False)
        # ANALYSIS BEGINS
        append_scan_status(checksum, 'init')
        app_dic['size'] = str(
            file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
        app_dic['sha1'], app_dic['sha256'] = hash_gen(
            checksum,
            app_dic['app_path'])
        msg = 'Extracting APK'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dic['files'] = unzip(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'])
        logger.info('APK Extracted')
        if not app_dic['files']:
            # Can't Analyze APK, bail out.
            msg = 'APK file is invalid or corrupt'
            append_scan_status(checksum, msg)
            return print_n_send_error_response(
                request,
                msg,
                api)
        app_dic['certz'] = get_hardcoded_cert_keystore(
            checksum,
            app_dic['files'])
        # Parse APK with Androguard
        apk = parse_apk(
            checksum,
            app_dic['app_path'])
        # get app_name
        app_dic['real_name'] = get_app_name(
            apk,
            app_dic['app_dir'],
            True,
        )
        # Manifest XML
        mani_file, ns, mani_xml = get_manifest(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'],
            app_dic['tools_dir'],
            APK_TYPE,
            apk,
        )
        app_dic['manifest_file'] = mani_file
        app_dic['parsed_xml'] = mani_xml
        # Manifest data extraction
        man_data_dic = manifest_data(
            checksum,
            app_dic['parsed_xml'],
            ns)
        # Get App name
        app_name = app_dic['real_name']
        pkg_name = man_data_dic['packagename']
        if app_name or pkg_name:
            if app_name and pkg_name:
                subject = f'{app_name} ({pkg_name})'
            elif app_name:
                subject = app_name
            elif pkg_name:
                subject = pkg_name
            msg = f'Performing Static Analysis on: {subject}'
            logger.info(msg)
            append_scan_status(checksum, msg)
        app_dic['playstore'] = get_app_details(
            checksum,
            man_data_dic['packagename'])
        man_an_dic = manifest_analysis(
            checksum,
            app_dic['parsed_xml'],
            ns,
            man_data_dic,
            '',
            app_dic['app_dir'])
        # Malware Permission check
        mal_perms = permissions.check_malware_permission(
            checksum,
            man_data_dic['perm'])
        man_an_dic['malware_permissions'] = mal_perms
        # Get icon
        # apktool should run before this
        get_icon_apk(apk, app_dic)
        elf_dict = library_analysis(
            checksum,
            app_dic['app_dir'],
            'elf')
        cert_dic = cert_info(
            apk,
            app_dic,
            man_data_dic)
        apkid_results = apkid.apkid_analysis(
            checksum,
            app_dic['app_path'])
        tracker = Trackers.Trackers(
            checksum,
            app_dic['app_dir'],
            app_dic['tools_dir'])
        tracker_res = tracker.get_trackers()
        apk_2_java(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'],
            settings.DOWNLOADED_TOOLS_DIR)
        dex_2_smali(
            checksum,
            app_dic['app_dir'],
            app_dic['tools_dir'])
        code_an_dic = code_analysis(
            checksum,
            app_dic['app_dir'],
            APK_TYPE,
            app_dic['manifest_file'],
            man_data_dic['perm'])
        behaviour_an = behaviour_analysis.analyze(
            checksum,
            app_dic['app_dir'],
            APK_TYPE)
        # Get the strings and metadata
        get_strings_metadata(
            checksum,
            apk,
            app_dic['app_dir'],
            elf_dict['elf_strings'],
            APK_TYPE,
            ['.java'],
            code_an_dic)
        # Firebase DB Check
        code_an_dic['firebase'] = firebase_analysis(
            checksum,
            code_an_dic)
        # Domain Extraction and Malware Check
        code_an_dic['domains'] = MalwareDomainCheck().scan(
            checksum,
            code_an_dic['urls_list'])

        app_dic['zipped'] = APK_TYPE
        context = save_get_ctx(
            app_dic,
            man_data_dic,
            man_an_dic,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            behaviour_an,
            tracker_res,
            rescan,
        )
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(
        context['code_analysis'])
    context['dynamic_analysis_done'] = is_file_exists(
        os.path.join(app_dic['app_dir'], 'logcat.txt'))

    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(
            app_dic['app_path'])
    template = 'static_analysis/android_binary_analysis.html'
    if api:
        return context
    else:
        return render(request, template, context)


def src_analysis(request, app_dic, rescan, api):
    """Source Code Analysis."""
    checksum = app_dic['md5']
    ret = f'/static_analyzer_ios/{checksum}/'
    app_dic['app_file'] = f'{checksum}.zip'
    app_dic['app_path'] = (
        app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    db_entry = StaticAnalyzerAndroid.objects.filter(
        MD5=checksum)
    ios_db_entry = StaticAnalyzerIOS.objects.filter(
        MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
    elif ios_db_entry.exists() and not rescan:
        if api:
            return {'type': 'ios'}
        else:
            return HttpResponseRedirect(ret)
    else:
        append_scan_status(checksum, 'init')
        msg = 'Extracting ZIP'
        logger.info(msg)
        append_scan_status(checksum, msg)
        app_dic['files'] = unzip(
            checksum,
            app_dic['app_path'],
            app_dic['app_dir'])
        # Check if Valid Directory Structure and get ZIP Type
        pro_type, valid = valid_source_code(
            checksum,
            app_dic['app_dir'])
        msg = f'Source code type - {pro_type}'
        logger.info(msg)
        append_scan_status(checksum, msg)
        if valid and pro_type == 'ios':
            msg = 'Redirecting to iOS Source Code Analyzer'
            logger.info(msg)
            append_scan_status(checksum, msg)
            if api:
                return {'type': 'ios'}
            else:
                ret += f'?rescan={str(int(rescan))}'
                return HttpResponseRedirect(ret)
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                False)
        # Android ZIP Source Code Analysis Begins
        if valid and (pro_type in ['eclipse', 'studio']):
            cert_dic = {
                'certificate_info': '',
                'certificate_status': '',
                'description': '',
            }
            app_dic['strings'] = []
            app_dic['secrets'] = []
            # Above fields are only available for APK and not ZIP
            app_dic['zipped'] = pro_type
            app_dic['size'] = str(
                file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
            app_dic['sha1'], app_dic['sha256'] = hash_gen(
                checksum,
                app_dic['app_path'])
            app_dic['certz'] = get_hardcoded_cert_keystore(
                checksum,
                app_dic['files'])
            # get app_name
            app_dic['real_name'] = get_app_name(
                app_dic['app_path'],
                app_dic['app_dir'],
                False,
            )
            # Manifest XML
            mani_file, ns, mani_xml = get_manifest(
                checksum,
                '',
                app_dic['app_dir'],
                app_dic['tools_dir'],
                pro_type,
                None,
            )
            app_dic['manifest_file'] = mani_file
            app_dic['parsed_xml'] = mani_xml
            # Get manifest data
            man_data_dic = manifest_data(
                checksum,
                app_dic['parsed_xml'],
                ns)
            # Get app name
            app_name = app_dic['real_name']
            pkg_name = man_data_dic['packagename']
            if app_name or pkg_name:
                if app_name and pkg_name:
                    subject = f'{app_name} ({pkg_name})'
                elif app_name:
                    subject = app_name
                elif pkg_name:
                    subject = pkg_name
                msg = f'Performing Static Analysis on: {subject}'
                logger.info(msg)

            app_dic['playstore'] = get_app_details(
                checksum,
                man_data_dic['packagename'])
            man_an_dic = manifest_analysis(
                checksum,
                app_dic['parsed_xml'],
                ns,
                man_data_dic,
                pro_type,
                app_dic['app_dir'],
            )
            # Malware Permission check
            mal_perms = permissions.check_malware_permission(
                checksum,
                man_data_dic['perm'])
            man_an_dic['malware_permissions'] = mal_perms
            # Get icon
            get_icon_from_src(
                app_dic,
                man_data_dic['icons'])
            code_an_dic = code_analysis(
                checksum,
                app_dic['app_dir'],
                pro_type,
                app_dic['manifest_file'],
                man_data_dic['perm'])
            behaviour_an = behaviour_analysis.analyze(
                checksum,
                app_dic['app_dir'],
                pro_type)
            # Get the strings and metadata
            get_strings_metadata(
                checksum,
                None,
                app_dic['app_dir'],
                None,
                pro_type,
                ['.java', '.kt'],
                code_an_dic)
            # Firebase DB Check
            code_an_dic['firebase'] = firebase_analysis(
                checksum,
                code_an_dic)
            # Domain Extraction and Malware Check
            code_an_dic['domains'] = MalwareDomainCheck().scan(
                checksum,
                code_an_dic['urls_list'])
            # Extract Trackers from Domains
            trk = Trackers.Trackers(
                checksum,
                None,
                app_dic['tools_dir'])
            trackers = trk.get_trackers_domains_or_deps(
                code_an_dic['domains'], [])
            context = save_get_ctx(
                app_dic,
                man_data_dic,
                man_an_dic,
                code_an_dic,
                cert_dic,
                [],
                {},
                behaviour_an,
                trackers,
                rescan,
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
                ctx = {
                    'title': 'Invalid ZIP archive',
                    'version': settings.MOBSF_VER,
                }
                template = 'general/zip.html'
                return render(request, template, ctx)
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(
        context['code_analysis'])
    template = 'static_analysis/android_source_analysis.html'
    if api:
        return context
    else:
        return render(request, template, context)


def is_android_source(app_dir):
    """Detect Android Source and IDE Type."""
    # Eclipse
    man = os.path.isfile(os.path.join(app_dir, 'AndroidManifest.xml'))
    src = os.path.exists(os.path.join(app_dir, 'src/'))
    if man and src:
        return 'eclipse', True
    # Studio
    man = os.path.isfile(
        os.path.join(app_dir, 'app/src/main/AndroidManifest.xml'),
    )
    java = os.path.exists(os.path.join(app_dir, 'app/src/main/java/'))
    kotlin = os.path.exists(os.path.join(app_dir, 'app/src/main/kotlin/'))
    if man and (java or kotlin):
        return 'studio', True
    return None, False


def move_to_parent(inside, app_dir):
    """Move contents of inside to app dir."""
    for x in os.listdir(inside):
        full_path = os.path.join(inside, x)
        shutil.move(full_path, app_dir)
    shutil.rmtree(inside)


def valid_source_code(checksum, app_dir):
    """Test if this is an valid source code zip."""
    try:
        msg = 'Detecting source code type'
        logger.info(msg)
        append_scan_status(checksum, msg)
        ide, is_and = is_android_source(app_dir)
        if ide:
            return ide, is_and
        # Relaxed Android Source check, one level down
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            ide, is_and = is_android_source(obj)
            if ide:
                move_to_parent(obj, app_dir)
                return ide, is_and
        # iOS Source
        xcode = [f for f in os.listdir(app_dir) if f.endswith('.xcodeproj')]
        if xcode:
            return 'ios', True
        # Relaxed iOS Source Check
        for x in os.listdir(app_dir):
            obj = os.path.join(app_dir, x)
            if not is_dir_exists(obj):
                continue
            if [f for f in os.listdir(obj) if f.endswith('.xcodeproj')]:
                return 'ios', True
        return '', False
    except Exception as exp:
        msg = 'Error identifying source code type from zip'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
