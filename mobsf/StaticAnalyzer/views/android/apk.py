
"""Android APK and Source Analysis."""
import logging
import shutil
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.android import (
    apkid,
    permissions,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render

from mobsf.MobSF.utils import (
    append_scan_status,
    file_size,
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
from mobsf.StaticAnalyzer.views.common.async_task import (
    async_analysis,
    update_enqueued_task,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)

logger = logging.getLogger(__name__)


def initialize_app_dic(app_dic, file_ext):
    checksum = app_dic['md5']
    app_dic['app_file'] = f'{checksum}.{file_ext}'
    app_dic['app_path'] = (app_dic['app_dir'] / app_dic['app_file']).as_posix()
    app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
    return checksum


def get_size_and_hashes(app_dic):
    app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'
    app_dic['sha1'], app_dic['sha256'] = hash_gen(app_dic['md5'], app_dic['app_path'])


def get_manifest_data(checksum, app_dic, andro_apk=None):
    """Get Manifest Data."""
    # Manifest XML
    mani_file, ns, mani_xml = get_manifest(
        checksum,
        app_dic['app_path'],
        app_dic['app_dir'],
        app_dic['tools_dir'],
        app_dic['zipped'],
        andro_apk,
    )
    app_dic['manifest_file'] = mani_file
    app_dic['parsed_xml'] = mani_xml
    # Manifest data extraction
    man_data = manifest_data(
        checksum,
        app_dic['parsed_xml'],
        ns)
    # Manifest Analysis
    man_analysis = manifest_analysis(
        checksum,
        app_dic['parsed_xml'],
        ns,
        man_data,
        app_dic['zipped'],
        app_dic['app_dir'])
    return man_data, man_analysis


def print_scan_subject(checksum, app_dic, man_data):
    """Log scan subject."""
    app_name = app_dic['real_name']
    pkg_name = man_data['packagename']
    subject = 'Android App'
    if app_name and pkg_name:
        subject = f'{app_name} ({pkg_name})'
    elif pkg_name:
        subject = pkg_name
    elif app_name:
        subject = app_name
    msg = f'Performing Static Analysis on: {subject}'
    logger.info(msg)
    append_scan_status(checksum, msg)
    if subject == 'Failed':
        subject = f'({subject})'
    return subject


def apk_analysis_task(checksum, app_dic, rescan, queue=False):
    """APK Analysis Task."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
        append_scan_status(checksum, 'init')
        get_size_and_hashes(app_dic)
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
            logger.error(msg)
            append_scan_status(checksum, msg)
            if queue:
                return update_enqueued_task(
                    checksum, 'Failed', msg)
            return context, msg
        app_dic['zipped'] = 'apk'
        app_dic['certz'] = get_hardcoded_cert_keystore(
            checksum,
            app_dic['files'])
        # Parse APK with Androguard4
        andro_apk = parse_apk(
            checksum,
            app_dic['app_path'])
        # Manifest Data
        man_data, man_analysis = get_manifest_data(
            checksum,
            app_dic,
            andro_apk)
        # Get App name
        app_dic['real_name'] = get_app_name(
            andro_apk,
            app_dic['app_dir'],
            True)
        # Print scan subject
        subject = print_scan_subject(checksum, app_dic, man_data)
        app_dic['playstore'] = get_app_details(
            checksum,
            man_data['packagename'])
        # Malware Permission check
        mal_perms = permissions.check_malware_permission(
            checksum,
            man_data['perm'])
        man_analysis['malware_permissions'] = mal_perms
        # Get icon
        # apktool should run before this
        get_icon_apk(andro_apk, app_dic)
        elf_dict = library_analysis(
            checksum,
            app_dic['app_dir'],
            'elf')
        cert_dic = cert_info(
            andro_apk,
            app_dic,
            man_data)
        apkid_results = apkid.apkid_analysis(
            checksum,
            app_dic['app_path'])
        trackers = Trackers.Trackers(
            checksum,
            app_dic['app_dir'],
            app_dic['tools_dir']).get_trackers()
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
            app_dic['zipped'],
            app_dic['manifest_file'],
            man_data['perm'])
        # Get the strings and metadata
        get_strings_metadata(
            checksum,
            andro_apk,
            app_dic['app_dir'],
            elf_dict['elf_strings'],
            app_dic['zipped'],
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
        context = save_get_ctx(
            app_dic,
            man_data,
            man_analysis,
            code_an_dic,
            cert_dic,
            elf_dict['elf_analysis'],
            apkid_results,
            trackers,
            rescan,
        )
        if queue:
            return update_enqueued_task(
                checksum, subject, 'Success')
        return context, None
    except Exception as exp:
        if queue:
            return update_enqueued_task(
                checksum, 'Failed', repr(exp))
        return context, repr(exp)


def generate_dynamic_context(request, app_dic, checksum, context, api):
    """Generate Dynamic Context."""
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis'])
    logcat_file = Path(app_dic['app_dir']) / 'logcat.txt'
    context['dynamic_analysis_done'] = logcat_file.exists()
    context['virus_total'] = None
    if settings.VT_ENABLED:
        vt = VirusTotal.VirusTotal(checksum)
        context['virus_total'] = vt.get_result(app_dic['app_path'])
    template = 'static_analysis/android_binary_analysis.html'
    return context if api else render(request, template, context)


def apk_analysis(request, app_dic, rescan, api):
    """APK Analysis."""
    checksum = initialize_app_dic(app_dic, 'apk')
    db_entry = StaticAnalyzerAndroid.objects.filter(MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
        return generate_dynamic_context(request, app_dic, checksum, context, api)
    else:
        # APK Analysis
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(request, 'Permission Denied', False)
        if settings.ASYNC_ANALYSIS:
            return async_analysis(
                checksum,
                api,
                app_dic.get('app_name', ''),
                apk_analysis_task, checksum, app_dic, rescan)
        context, err = apk_analysis_task(checksum, app_dic, rescan)
        if err:
            return print_n_send_error_response(request, err, api)
        return generate_dynamic_context(request, app_dic, checksum, context, api)


def src_analysis_task(checksum, app_dic, rescan, pro_type, queue=False):
    """Android ZIP Source Code Analysis Begins."""
    context = None
    try:
        if queue:
            settings.ASYNC_ANALYSIS = True
        cert_dic = {
            'certificate_info': '',
            'certificate_status': '',
            'description': '',
        }
        app_dic['strings'] = []
        app_dic['secrets'] = []
        # Above fields are only available for APK and not ZIP
        app_dic['zipped'] = pro_type
        app_dic['certz'] = get_hardcoded_cert_keystore(
            checksum,
            app_dic['files'])
        # Manifest Data
        man_data, man_analysis = get_manifest_data(
            checksum,
            app_dic)
        # Get app name
        app_dic['real_name'] = get_app_name(
            None,
            app_dic['app_dir'],
            False)
        # Print scan subject
        subject = print_scan_subject(checksum, app_dic, man_data)
        app_dic['playstore'] = get_app_details(
            checksum,
            man_data['packagename'])
        # Malware Permission check
        mal_perms = permissions.check_malware_permission(
            checksum,
            man_data['perm'])
        man_analysis['malware_permissions'] = mal_perms
        # Get icon
        get_icon_from_src(
            app_dic,
            man_data['icons'])
        code_an_dic = code_analysis(
            checksum,
            app_dic['app_dir'],
            app_dic['zipped'],
            app_dic['manifest_file'],
            man_data['perm'])
        # Get the strings and metadata
        get_strings_metadata(
            checksum,
            None,
            app_dic['app_dir'],
            None,
            app_dic['zipped'],
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
        trackers = Trackers.Trackers(
            checksum,
            None,
            app_dic['tools_dir']).get_trackers_domains_or_deps(
                code_an_dic['domains'], [])
        context = save_get_ctx(
            app_dic,
            man_data,
            man_analysis,
            code_an_dic,
            cert_dic,
            [],
            {},
            trackers,
            rescan,
        )
        if queue:
            return update_enqueued_task(
                checksum, subject, 'Success')
    except Exception as exp:
        if queue:
            return update_enqueued_task(
                checksum, 'Failed', repr(exp))
    return context


def generate_dynamic_src_context(request, context, api):
    """Generate Dynamic Source Context."""
    context['appsec'] = get_android_dashboard(context, True)
    context['average_cvss'] = get_avg_cvss(context['code_analysis'])
    template = 'static_analysis/android_source_analysis.html'
    return context if api else render(request, template, context)


def src_analysis(request, app_dic, rescan, api):
    """Source Code Analysis."""
    checksum = initialize_app_dic(app_dic, 'zip')
    ret = f'/static_analyzer_ios/{checksum}/'
    db_entry = StaticAnalyzerAndroid.objects.filter(
        MD5=checksum)
    ios_db_entry = StaticAnalyzerIOS.objects.filter(
        MD5=checksum)
    if db_entry.exists() and not rescan:
        context = get_context_from_db_entry(db_entry)
        return generate_dynamic_src_context(request, context, api)
    elif ios_db_entry.exists() and not rescan:
        return {'type': 'ios'} if api else HttpResponseRedirect(ret)
    else:
        # Initialize for both Android and iOS Source Analysis
        append_scan_status(checksum, 'init')
        get_size_and_hashes(app_dic)
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
        # Handle iOS Source Code
        if valid and pro_type == 'ios':
            msg = 'Redirecting to iOS Source Code Analyzer'
            logger.info(msg)
            append_scan_status(checksum, msg)
            ret = f'{ret}?rescan={str(int(rescan))}'
            return {'type': 'ios'} if api else HttpResponseRedirect(ret)
        # Android Source Code Analysis
        if not has_permission(request, Permissions.SCAN, api):
            return print_n_send_error_response(
                request,
                'Permission Denied',
                False)
        if valid and (pro_type in ['eclipse', 'studio']):
            if settings.ASYNC_ANALYSIS:
                return async_analysis(
                    checksum,
                    api,
                    app_dic.get('app_name', ''),
                    src_analysis_task, checksum, app_dic, rescan, pro_type)
            context = src_analysis_task(checksum, app_dic, rescan, pro_type)
            return generate_dynamic_src_context(request, context, api)
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


def is_android_source(app_path):
    """Detect Android Source and IDE Type."""
    # Eclipse
    man = app_path / 'AndroidManifest.xml'
    src = app_path / 'src'
    if man.is_file() and src.exists():
        return 'eclipse', True

    # Studio
    man = app_path / 'app' / 'src' / 'main' / 'AndroidManifest.xml'
    java = app_path / 'app' / 'src' / 'main' / 'java'
    kotlin = app_path / 'app' / 'src' / 'main' / 'kotlin'
    if man.is_file() and (java.exists() or kotlin.exists()):
        return 'studio', True

    return None, False


def move_to_parent(inside_path, app_path):
    """Move contents of inside to app dir."""
    for item in inside_path.iterdir():
        shutil.move(str(item), str(app_path))
    shutil.rmtree(inside_path)


def valid_source_code(checksum, app_dir):
    """Test if this is a valid source code zip."""
    try:
        msg = 'Detecting source code type'
        logger.info(msg)
        append_scan_status(checksum, msg)

        app_path = Path(app_dir)
        ide, is_and = is_android_source(app_path)

        if ide:
            return ide, is_and

        # Relaxed Android Source check, one level down
        for subdir in app_path.iterdir():
            if subdir.is_dir() and subdir.exists():
                ide, is_and = is_android_source(subdir)
                if ide:
                    move_to_parent(subdir, app_path)
                    return ide, is_and

        # iOS Source
        xcode = [f for f in app_path.iterdir() if f.suffix == '.xcodeproj']
        if xcode:
            return 'ios', True

        # Relaxed iOS Source Check
        for subdir in app_path.iterdir():
            if subdir.is_dir() and subdir.exists():
                if any(f.suffix == '.xcodeproj' for f in subdir.iterdir()):
                    return 'ios', True

        return '', False
    except Exception as exp:
        msg = 'Error identifying source code type from zip'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
