# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

import logging
import os
import shutil
from pathlib import Path

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
import mobsf.MalwareAnalyzer.views.VirusTotal as VirusTotal
from mobsf.MalwareAnalyzer.views.android import (
    apkid,
    permissions,
    quark,
)
from mobsf.MalwareAnalyzer.views.MalwareDomainCheck import MalwareDomainCheck

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register

from mobsf.MobSF.utils import (
    android_component,
    file_size,
    is_dir_exists,
    is_file_exists,
    is_md5,
    key,
    print_n_send_error_response,
    relative_path,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
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
from mobsf.StaticAnalyzer.views.android.xapk import (
    handle_aab,
    handle_split_apk,
    handle_xapk,
)
from mobsf.StaticAnalyzer.views.android.jar_aar import (
    aar_analysis,
    jar_analysis,
)
from mobsf.StaticAnalyzer.views.android.so import (
    so_analysis,
)
from mobsf.StaticAnalyzer.views.common.shared_func import (
    firebase_analysis,
    get_avg_cvss,
    hash_gen,
    unzip,
)
from mobsf.StaticAnalyzer.views.common.appsec import (
    get_android_dashboard,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    has_permission,
)


logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('android_component', android_component)
register.filter('relative_path', relative_path)


@login_required
def static_analyzer(request, checksum, api=False):
    """Do static analysis on an request and save to db."""
    try:
        rescan = False
        if api:
            re_scan = request.POST.get('re_scan', 0)
        else:
            re_scan = request.GET.get('rescan', 0)
        if re_scan == '1':
            rescan = True
        # Input validation
        app_dic = {}
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
        typ = robj[0].SCAN_TYPE
        filename = robj[0].FILE_NAME
        allowed_exts = tuple(f'.{i}' for i in settings.ANDROID_EXTS)
        if (not filename.lower().endswith(allowed_exts)
                or typ not in settings.ANDROID_EXTS):
            return print_n_send_error_response(
                request,
                'Invalid file extension or file type',
                api)

        app_dic['dir'] = Path(settings.BASE_DIR)  # BASE DIR
        app_dic['app_name'] = filename  # APP ORIGINAL NAME
        app_dic['md5'] = checksum  # MD5
        logger.info('Scan Hash: %s', checksum)
        # APP DIRECTORY
        app_dic['app_dir'] = Path(settings.UPLD_DIR) / checksum
        app_dic['tools_dir'] = app_dic['dir'] / 'StaticAnalyzer' / 'tools'
        app_dic['tools_dir'] = app_dic['tools_dir'].as_posix()
        app_dic['icon_path'] = ''
        logger.info('Starting Analysis on: %s', app_dic['app_name'])
        if typ == 'xapk':
            # Handle XAPK
            # Base APK will have the MD5 of XAPK
            if not handle_xapk(app_dic):
                raise Exception('Invalid XAPK File')
            typ = 'apk'
        elif typ == 'apks':
            # Handle Split APK
            if not handle_split_apk(app_dic):
                raise Exception('Invalid Split APK File')
            typ = 'apk'
        elif typ == 'aab':
            # Convert AAB to APK
            if not handle_aab(app_dic):
                raise Exception('Invalid AAB File')
            typ = 'apk'
        if typ == 'apk':
            app_dic['app_file'] = app_dic['md5'] + '.apk'  # NEW FILENAME
            app_dic['app_path'] = (
                app_dic['app_dir'] / app_dic['app_file']).as_posix()
            app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
            # Check if in DB
            # pylint: disable=E1101
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=app_dic['md5'])
            if db_entry.exists() and not rescan:
                context = get_context_from_db_entry(db_entry)
            else:
                if not has_permission(request, Permissions.SCAN, api):
                    return print_n_send_error_response(
                        request,
                        'Permission Denied',
                        False)
                from mobsf.StaticAnalyzer.views.common.prompts import AndroidPrompts
                ap = AndroidPrompts()
                if ap:
                    libs = {'apktool_out/lib/x86/libglog.so', 'apktool_out/lib/arm64-v8a/libbugsnag-root-detection.so', 'lib/x86_64/libreanimated.so', 'apktool_out/lib/armeabi-v7a/libreact_render_leakchecker.so', 'lib/x86_64/libc++_shared.so', 'apktool_out/lib/armeabi-v7a/libbugsnag-plugin-android-anr.so', 'apktool_out/lib/x86_64/libreact_newarchdefaults.so', 'apktool_out/lib/arm64-v8a/libea4ea9.so', 'apktool_out/lib/x86/libreact_render_animations.so', 'lib/x86/libfabricjni.so', 'lib/x86_64/libhermes.so', 'lib/x86_64/libb750.so', 'apktool_out/lib/x86_64/libjsijniprofiler.so', 'apktool_out/lib/arm64-v8a/libjsinspector.so', 'lib/x86_64/libexpo-av.so', 'apktool_out/lib/x86/libhermes_executor.so', 'apktool_out/lib/x86_64/libfb.so', 'apktool_out/lib/x86_64/libreactnativejni.so', 'apktool_out/lib/arm64-v8a/libreact_render_imagemanager.so', 'apktool_out/lib/armeabi-v7a/libreact_render_telemetry.so', 'apktool_out/lib/x86/libreact_newarchdefaults.so', 'apktool_out/lib/x86/librrc_unimplementedview.so', 'lib/arm64-v8a/libreact_codegen_rncore.so', 'apktool_out/lib/arm64-v8a/libnative-imagetranscoder.so', 'lib/armeabi-v7a/libreact_nativemodule_core.so', 'lib/x86/librrc_view.so', 'lib/x86_64/libjsi.so', 'apktool_out/lib/arm64-v8a/libreact_render_telemetry.so', 'lib/arm64-v8a/libreact_config.so', 'lib/x86_64/libfabricjni.so', 'apktool_out/lib/armeabi-v7a/libreact_render_animations.so', 'apktool_out/lib/arm64-v8a/libreact_render_mounting.so', 'lib/arm64-v8a/libexpo-modules-core.so', 'lib/arm64-v8a/librsjni_androidx.so', 'apktool_out/lib/x86/libreact_render_debug.so', 'lib/x86_64/libreactperfloggerjni.so', 'apktool_out/lib/armeabi-v7a/libnative-filters.so', 'apktool_out/lib/x86_64/libbugsnag-ndk.so', 'lib/x86/libimagepipeline.so', 'lib/arm64-v8a/libimagepipeline.so', 'apktool_out/lib/armeabi-v7a/libreact_codegen_rncore.so', 'apktool_out/lib/x86/librsjni.so', 'apktool_out/lib/x86/libbugsnag-plugin-android-anr.so', 'lib/arm64-v8a/librrc_image.so', 'apktool_out/lib/x86_64/libmapbufferjni.so', 'lib/arm64-v8a/libreactperfloggerjni.so', 'lib/x86_64/libreact_render_textlayoutmanager.so', 'lib/armeabi-v7a/libturbomodulejsijni.so', 'lib/x86_64/libruntimeexecutor.so', 'lib/x86_64/liblogger.so', 'apktool_out/lib/arm64-v8a/libreact_render_componentregistry.so', 'apktool_out/lib/arm64-v8a/librsjni.so', 'lib/armeabi-v7a/librrc_image.so', 'apktool_out/lib/arm64-v8a/libreact_render_runtimescheduler.so', 'lib/x86_64/libyoga.so', 'lib/x86/libtool-checker.so', 'apktool_out/lib/armeabi-v7a/libexpo-modules-core.so', 'lib/x86/libturbomodulejsijni.so', 'lib/arm64-v8a/liblogger.so', 'lib/x86_64/librrc_view.so', 'lib/armeabi-v7a/librive-android.so', 'apktool_out/lib/arm64-v8a/libnative-filters.so', 'lib/armeabi-v7a/libfabricjni.so', 'lib/armeabi-v7a/libb750.so', 'apktool_out/lib/arm64-v8a/libreact_render_attributedstring.so', 'lib/armeabi-v7a/libbugsnag-root-detection.so', 'lib/armeabi-v7a/libreact_render_templateprocessor.so', 'apktool_out/lib/x86_64/libb750.so', 'lib/x86/libhermes_executor.so', 'apktool_out/lib/armeabi-v7a/libreact_render_attributedstring.so', 'lib/x86/libreact_debug.so', 'lib/armeabi-v7a/librsjni.so', 'lib/x86/libreact_newarchdefaults.so', 'apktool_out/lib/arm64-v8a/librsjni_androidx.so', 'lib/x86/libreact_nativemodule_core.so', 'lib/x86_64/libtool-checker.so', 'lib/arm64-v8a/libreact_utils.so', 'lib/x86/libreact_render_animations.so', 'apktool_out/lib/x86_64/libea4ea9.so', 'apktool_out/lib/arm64-v8a/libreact_render_templateprocessor.so', 'apktool_out/lib/x86_64/librrc_unimplementedview.so', 'lib/arm64-v8a/libturbomodulejsijni.so', 'apktool_out/lib/x86/libglog_init.so', 'apktool_out/lib/arm64-v8a/libhermes_executor.so', 'apktool_out/lib/x86/libreactperfloggerjni.so', 'lib/arm64-v8a/libreact_render_scheduler.so', 'apktool_out/lib/x86/libexpo-av.so', 'lib/x86/libreact_render_templateprocessor.so', 'apktool_out/lib/x86/libreact_render_telemetry.so', 'apktool_out/lib/armeabi-v7a/libbugsnag-root-detection.so', 'lib/x86/libreact_render_textlayoutmanager.so', 'lib/arm64-v8a/libreact_render_templateprocessor.so', 'lib/x86_64/libreact_nativemodule_core.so', 'lib/armeabi-v7a/librrc_view.so', 'apktool_out/lib/x86/libnative-imagetranscoder.so', 'apktool_out/lib/armeabi-v7a/libreact_render_core.so', 'lib/armeabi-v7a/liblogger.so', 'lib/x86/liblogger.so', 'apktool_out/lib/x86_64/libreact_render_leakchecker.so', 'apktool_out/lib/x86/libfb.so', 'lib/armeabi-v7a/libucrop.so', 'lib/x86_64/libreact_render_debug.so', 'lib/x86/libfolly_runtime.so', 'apktool_out/lib/x86/libreanimated.so', 'apktool_out/lib/x86_64/librrc_text.so', 'lib/x86/libreactperfloggerjni.so', 'lib/x86_64/libreact_render_telemetry.so', 'apktool_out/lib/armeabi-v7a/libjsijniprofiler.so', 'lib/x86_64/libbugsnag-root-detection.so', 'apktool_out/lib/x86_64/liblogger.so', 'apktool_out/lib/arm64-v8a/libreact_render_scheduler.so', 'lib/arm64-v8a/libnative-imagetranscoder.so', 'apktool_out/lib/arm64-v8a/liblogger.so', 'lib/x86_64/libjsijniprofiler.so', 'apktool_out/lib/x86/libreact_render_runtimescheduler.so', 'apktool_out/lib/armeabi-v7a/libreact_render_debug.so', 'apktool_out/lib/x86_64/libreact_render_textlayoutmanager.so', 'lib/x86/libreact_render_telemetry.so', 'apktool_out/lib/x86/libreact_debug.so', 'apktool_out/lib/arm64-v8a/librrc_text.so', 'lib/x86/librrc_scrollview.so', 'lib/arm64-v8a/libreact_debug.so', 'lib/arm64-v8a/libreact_render_uimanager.so', 'lib/x86_64/libreact_newarchdefaults.so', 'apktool_out/lib/x86_64/libexpo-modules-core.so', 'lib/armeabi-v7a/libreanimated.so', 'lib/x86/libhermes.so', 'apktool_out/lib/x86/libreact_render_imagemanager.so', 'lib/x86_64/libglog.so', 'apktool_out/lib/x86/librrc_textinput.so', 'apktool_out/lib/arm64-v8a/librrc_root.so', 'apktool_out/lib/x86_64/libreanimated.so', 'apktool_out/lib/x86/libmapbufferjni.so', 'apktool_out/lib/x86_64/libreact_render_mounting.so', 'apktool_out/lib/armeabi-v7a/libreact_render_graphics.so', 'lib/armeabi-v7a/libexpo-modules-core.so', 'lib/x86/libbugsnag-plugin-android-anr.so', 'lib/x86/librive-android.so', 'lib/x86_64/libreact_render_mounting.so', 'apktool_out/lib/x86/libRSSupport.so', 'lib/arm64-v8a/libbugsnag-ndk.so', 'lib/armeabi-v7a/libreact_codegen_rncore.so', 'lib/x86_64/libreact_render_animations.so', 'lib/arm64-v8a/libglog.so', 'lib/x86_64/libreact_render_templateprocessor.so', 'lib/x86_64/libglog_init.so', 'lib/arm64-v8a/libreact_newarchdefaults.so', 'apktool_out/lib/x86/libyoga.so', 'apktool_out/lib/x86/libreact_render_scheduler.so', 'apktool_out/lib/x86_64/libruntimeexecutor.so', 'lib/x86/libreactnativejni.so', 'lib/x86_64/libreact_utils.so', 'lib/arm64-v8a/libjsinspector.so', 'lib/x86_64/libexpo-modules-core.so', 'apktool_out/lib/x86_64/libreact_nativemodule_core.so', 'lib/x86/libexpo-modules-core.so', 'apktool_out/lib/armeabi-v7a/libfb.so', 'apktool_out/lib/x86/libfbjni.so', 'lib/x86_64/librrc_text.so', 'apktool_out/lib/armeabi-v7a/libbugsnag-ndk.so', 'lib/arm64-v8a/libreanimated.so', 'apktool_out/lib/arm64-v8a/libjsijniprofiler.so', 'lib/x86_64/libreact_config.so', 'lib/x86/librrc_root.so', 'lib/arm64-v8a/librrc_textinput.so', 'apktool_out/lib/arm64-v8a/libreact_nativemodule_core.so', 'lib/armeabi-v7a/libimagepipeline.so', 'apktool_out/lib/arm64-v8a/libreactnativeblob.so', 'apktool_out/lib/x86/libfolly_runtime.so', 'apktool_out/lib/armeabi-v7a/libturbomodulejsijni.so', 'apktool_out/lib/armeabi-v7a/librsjni.so', 'lib/armeabi-v7a/libed51b3.so', 'lib/arm64-v8a/libreact_render_mapbuffer.so', 'lib/x86_64/libTMXProfiling-RL-6.3-82-jni.so', 'lib/arm64-v8a/libhermes.so', 'lib/x86_64/libea4ea9.so', 'apktool_out/lib/armeabi-v7a/librrc_scrollview.so', 'lib/x86/librsjni_androidx.so', 'apktool_out/lib/armeabi-v7a/libreactnativejni.so', 'apktool_out/lib/armeabi-v7a/libmapbufferjni.so', 'apktool_out/lib/arm64-v8a/librrc_scrollview.so', 'apktool_out/lib/x86_64/libtool-checker.so', 'lib/armeabi-v7a/librsjni_androidx.so', 'lib/armeabi-v7a/libreact_render_mapbuffer.so', 'apktool_out/lib/armeabi-v7a/libtool-checker.so', 'lib/armeabi-v7a/libreact_render_debug.so', 'lib/arm64-v8a/libucrop.so', 'lib/armeabi-v7a/libc++_shared.so', 'apktool_out/lib/armeabi-v7a/libjsinspector.so', 'apktool_out/lib/x86_64/librrc_view.so', 'apktool_out/lib/x86/libjsi.so', 'apktool_out/lib/armeabi-v7a/libfbjni.so', 'lib/armeabi-v7a/libbugsnag-ndk.so', 'apktool_out/lib/x86/libexpo-modules-core.so', 'lib/armeabi-v7a/libRSSupport.so', 'apktool_out/lib/arm64-v8a/libfolly_runtime.so', 'apktool_out/lib/x86/libnative-filters.so', 'lib/arm64-v8a/librrc_unimplementedview.so', 'lib/armeabi-v7a/librrc_textinput.so', 'apktool_out/lib/arm64-v8a/librrc_unimplementedview.so', 'apktool_out/lib/arm64-v8a/libruntimeexecutor.so', 'apktool_out/lib/armeabi-v7a/libreact_render_componentregistry.so', 'lib/x86/librrc_unimplementedview.so', 'apktool_out/lib/x86/libreact_render_graphics.so', 'apktool_out/lib/x86_64/libreact_render_animations.so', 'apktool_out/lib/x86_64/libbugsnag-plugin-android-anr.so', 'lib/x86_64/libbugsnag-ndk.so', 'apktool_out/lib/x86_64/libreact_utils.so', 'lib/x86_64/libed51b3.so', 'apktool_out/lib/armeabi-v7a/librrc_view.so', 'lib/x86/libnative-imagetranscoder.so', 'apktool_out/lib/x86_64/libreact_render_mapbuffer.so', 'apktool_out/lib/x86/libjsijniprofiler.so', 'lib/arm64-v8a/libfolly_runtime.so', 'lib/arm64-v8a/libreactnativeblob.so', 'lib/x86_64/libe900.so', 'apktool_out/lib/armeabi-v7a/libreactperfloggerjni.so', 'apktool_out/lib/x86/libc++_shared.so', 'apktool_out/lib/arm64-v8a/libglog.so', 'apktool_out/lib/arm64-v8a/libhermes.so', 'apktool_out/lib/armeabi-v7a/libreanimated.so', 'apktool_out/lib/x86_64/libreact_render_templateprocessor.so', 'apktool_out/lib/x86/libreact_codegen_rncore.so', 'apktool_out/lib/x86_64/libreactnativeblob.so', 'apktool_out/lib/x86_64/libreact_render_componentregistry.so', 'lib/x86/libreact_config.so', 'lib/x86_64/librrc_textinput.so', 'lib/armeabi-v7a/libreact_utils.so', 'apktool_out/lib/armeabi-v7a/libreact_render_runtimescheduler.so', 'apktool_out/lib/armeabi-v7a/libea4ea9.so', 'lib/arm64-v8a/libjsijniprofiler.so', 'lib/arm64-v8a/libreact_render_core.so', 'apktool_out/lib/x86/libimagepipeline.so', 'apktool_out/lib/x86/libhermes.so', 'apktool_out/lib/x86/libucrop.so', 'lib/armeabi-v7a/librrc_unimplementedview.so', 'lib/arm64-v8a/libnative-filters.so', 'apktool_out/lib/x86_64/libreact_render_debug.so', 'apktool_out/lib/x86_64/libreact_codegen_rncore.so', 'apktool_out/lib/armeabi-v7a/librrc_unimplementedview.so', 'lib/armeabi-v7a/libreact_config.so', 'lib/x86_64/libnative-imagetranscoder.so', 'lib/arm64-v8a/librrc_text.so', 'apktool_out/lib/armeabi-v7a/libreactnativeblob.so', 'apktool_out/lib/x86_64/libTMXProfiling-RL-6.3-82-jni.so', 'lib/arm64-v8a/librrc_legacyviewmanagerinterop.so', 'lib/armeabi-v7a/libreact_render_textlayoutmanager.so', 'apktool_out/lib/x86/libed51b3.so', 'apktool_out/lib/arm64-v8a/librive-android.so', 'lib/x86_64/libreactnativejni.so', 'apktool_out/lib/x86_64/libreact_render_graphics.so', 'apktool_out/lib/x86_64/libexpo-av.so', 'apktool_out/lib/x86_64/libreact_render_telemetry.so', 'apktool_out/lib/x86_64/librsjni_androidx.so', 'lib/arm64-v8a/libfbjni.so', 'apktool_out/lib/x86/libreact_render_textlayoutmanager.so', 'lib/armeabi-v7a/libreact_render_mounting.so', 'lib/x86/libruntimeexecutor.so', 'apktool_out/lib/arm64-v8a/libexpo-modules-core.so', 'lib/x86/libjsi.so', 'apktool_out/lib/x86/libtool-checker.so', 'apktool_out/lib/x86/libe900.so', 'apktool_out/lib/x86_64/librive-android.so', 'apktool_out/lib/x86_64/libed51b3.so', 'lib/x86_64/libnative-filters.so', 'lib/armeabi-v7a/libreact_render_animations.so', 'apktool_out/lib/arm64-v8a/librrc_image.so', 'lib/arm64-v8a/libglog_init.so', 'lib/x86/libmapbufferjni.so', 'lib/x86/librrc_textinput.so', 'apktool_out/lib/arm64-v8a/libreactnativejni.so', 'lib/arm64-v8a/libreact_render_animations.so', 'apktool_out/lib/x86_64/libe900.so', 'lib/x86/libucrop.so', 'apktool_out/lib/armeabi-v7a/libe900.so', 'lib/x86_64/libfb.so', 'apktool_out/lib/armeabi-v7a/libhermes_executor.so', 'lib/armeabi-v7a/libreactnativeblob.so', 'apktool_out/lib/x86/librrc_legacyviewmanagerinterop.so', 'lib/x86_64/librive-android.so', 'lib/armeabi-v7a/libhermes_executor.so', 'lib/armeabi-v7a/libTMXProfiling-RL-6.3-82-jni.so', 'apktool_out/lib/x86_64/libreactperfloggerjni.so', 'lib/armeabi-v7a/libmapbufferjni.so', 'apktool_out/lib/armeabi-v7a/libexpo-av.so', 'lib/x86/libyoga.so', 'apktool_out/lib/arm64-v8a/libed51b3.so', 'apktool_out/lib/x86_64/libreact_render_runtimescheduler.so', 'lib/arm64-v8a/libb750.so', 'lib/x86/libTMXProfiling-RL-6.3-82-jni.so', 'lib/x86/librrc_text.so', 'apktool_out/lib/armeabi-v7a/libfabricjni.so', 'lib/x86_64/librrc_scrollview.so', 'apktool_out/lib/armeabi-v7a/libreact_config.so', 'apktool_out/lib/armeabi-v7a/librsjni_androidx.so', 'apktool_out/lib/x86/librive-android.so', 'lib/x86_64/librrc_image.so', 'lib/arm64-v8a/libexpo-av.so', 'lib/x86_64/libucrop.so', 'apktool_out/lib/armeabi-v7a/libglog.so', 'lib/armeabi-v7a/libreact_render_telemetry.so', 'apktool_out/lib/arm64-v8a/libTMXProfiling-RL-6.3-82-jni.so', 'lib/x86_64/libreact_render_scheduler.so', 'apktool_out/lib/x86_64/librrc_image.so', 'lib/x86/librrc_legacyviewmanagerinterop.so', 'apktool_out/lib/arm64-v8a/libreactperfloggerjni.so', 'apktool_out/lib/arm64-v8a/libexpo-av.so', 'lib/armeabi-v7a/libreact_render_uimanager.so', 'lib/x86/libreact_utils.so', 'lib/arm64-v8a/libtool-checker.so', 'apktool_out/lib/armeabi-v7a/libjsi.so', 'apktool_out/lib/x86_64/libturbomodulejsijni.so', 'apktool_out/lib/x86/libreact_render_attributedstring.so', 'apktool_out/lib/x86/libreact_nativemodule_core.so', 'apktool_out/lib/armeabi-v7a/libimagepipeline.so', 'apktool_out/lib/x86_64/libRSSupport.so', 'lib/armeabi-v7a/librrc_text.so', 'lib/x86/libc++_shared.so', 'lib/arm64-v8a/libhermes_executor.so', 'lib/arm64-v8a/librrc_view.so', 'lib/armeabi-v7a/libtool-checker.so', 'lib/armeabi-v7a/libreactnativejni.so', 'lib/arm64-v8a/libbugsnag-plugin-android-anr.so', 'lib/x86_64/libjsinspector.so', 'apktool_out/lib/x86_64/librrc_legacyviewmanagerinterop.so', 'lib/x86_64/librrc_legacyviewmanagerinterop.so', 'apktool_out/lib/arm64-v8a/libreact_render_mapbuffer.so', 'apktool_out/lib/armeabi-v7a/libreact_render_templateprocessor.so', 'lib/x86_64/librrc_root.so', 'apktool_out/lib/armeabi-v7a/libyoga.so', 'apktool_out/lib/x86/libreact_render_leakchecker.so', 'lib/arm64-v8a/libmapbufferjni.so', 'apktool_out/lib/armeabi-v7a/libed51b3.so', 'lib/x86/libreact_render_leakchecker.so', 'apktool_out/lib/x86_64/libhermes.so', 'apktool_out/lib/armeabi-v7a/libreact_render_textlayoutmanager.so', 'apktool_out/lib/arm64-v8a/librrc_view.so', 'lib/armeabi-v7a/libreactperfloggerjni.so', 'apktool_out/lib/arm64-v8a/libreact_newarchdefaults.so', 'lib/x86/libRSSupport.so', 'apktool_out/lib/armeabi-v7a/libreact_utils.so', 'lib/x86_64/libmapbufferjni.so', 'apktool_out/lib/armeabi-v7a/libucrop.so', 'apktool_out/lib/armeabi-v7a/libreact_render_scheduler.so', 'apktool_out/lib/armeabi-v7a/libruntimeexecutor.so', 'apktool_out/lib/armeabi-v7a/libreact_render_mounting.so', 'apktool_out/lib/x86/librrc_text.so', 'apktool_out/lib/arm64-v8a/libe900.so', 'lib/arm64-v8a/libreact_render_mounting.so', 'apktool_out/lib/arm64-v8a/libfb.so', 'apktool_out/lib/x86/libreact_render_componentregistry.so', 'apktool_out/lib/x86/librrc_root.so', 'apktool_out/lib/arm64-v8a/libreact_config.so', 'apktool_out/lib/x86_64/libfbjni.so', 'apktool_out/lib/arm64-v8a/libreact_render_core.so', 'lib/x86/libreact_render_graphics.so', 'lib/arm64-v8a/librsjni.so', 'lib/x86/libbugsnag-ndk.so', 'lib/x86/librsjni.so', 'apktool_out/lib/x86/libb750.so', 'lib/x86/libea4ea9.so', 'apktool_out/lib/armeabi-v7a/libreact_debug.so', 'lib/x86/libjsinspector.so', 'apktool_out/lib/arm64-v8a/libucrop.so', 'lib/armeabi-v7a/libnative-filters.so', 'lib/x86/libreact_render_imagemanager.so', 'lib/armeabi-v7a/libea4ea9.so', 'lib/arm64-v8a/libreact_render_graphics.so', 'apktool_out/lib/arm64-v8a/libjsi.so', 'lib/armeabi-v7a/libruntimeexecutor.so', 'apktool_out/lib/x86_64/libreact_render_uimanager.so', 'apktool_out/lib/arm64-v8a/libreact_render_leakchecker.so', 'lib/armeabi-v7a/libexpo-av.so', 'lib/arm64-v8a/libreact_render_attributedstring.so', 'apktool_out/lib/arm64-v8a/libbugsnag-plugin-android-anr.so', 'apktool_out/lib/x86/libbugsnag-ndk.so', 'lib/x86_64/libreact_render_runtimescheduler.so', 'lib/armeabi-v7a/libbugsnag-plugin-android-anr.so', 'apktool_out/lib/arm64-v8a/libimagepipeline.so', 'lib/arm64-v8a/libyoga.so', 'lib/armeabi-v7a/libglog_init.so', 'lib/armeabi-v7a/libreact_render_componentregistry.so', 'lib/x86_64/libreact_render_componentregistry.so', 'lib/x86/libreact_render_core.so', 'lib/armeabi-v7a/libreact_debug.so', 'apktool_out/lib/x86_64/libfabricjni.so', 'apktool_out/lib/x86_64/libreact_render_imagemanager.so', 'lib/armeabi-v7a/libreact_render_imagemanager.so', 'lib/x86_64/libreact_codegen_rncore.so', 'apktool_out/lib/x86_64/libjsi.so', 'apktool_out/lib/x86_64/libreact_render_scheduler.so', 'lib/armeabi-v7a/libjsijniprofiler.so', 'lib/arm64-v8a/libea4ea9.so', 'apktool_out/lib/arm64-v8a/libtool-checker.so', 'apktool_out/lib/armeabi-v7a/librrc_image.so', 'apktool_out/lib/arm64-v8a/libglog_init.so', 'lib/x86/libreact_render_runtimescheduler.so', 'lib/x86/libreact_render_uimanager.so', 'apktool_out/lib/x86/libfabricjni.so', 'apktool_out/lib/armeabi-v7a/librrc_textinput.so', 'apktool_out/lib/x86_64/libnative-filters.so', 'lib/x86/libe900.so', 'apktool_out/lib/x86/libreact_utils.so', 'lib/x86/libjsijniprofiler.so', 'lib/x86/libglog.so', 'apktool_out/lib/arm64-v8a/libreact_render_textlayoutmanager.so', 'apktool_out/lib/x86/libreact_config.so', 'lib/x86/libreact_codegen_rncore.so', 'lib/armeabi-v7a/libreact_render_scheduler.so', 'apktool_out/lib/x86_64/libucrop.so', 'lib/armeabi-v7a/librrc_legacyviewmanagerinterop.so', 'lib/arm64-v8a/libreact_nativemodule_core.so', 'apktool_out/lib/armeabi-v7a/libreact_newarchdefaults.so', 'lib/x86/libnative-filters.so', 'apktool_out/lib/x86/librsjni_androidx.so', 'lib/x86/libglog_init.so', 'lib/arm64-v8a/libreact_render_textlayoutmanager.so', 'lib/x86_64/libreactnativeblob.so', 'lib/arm64-v8a/libe900.so', 'lib/arm64-v8a/libjsi.so', 'lib/arm64-v8a/libTMXProfiling-RL-6.3-82-jni.so', 'apktool_out/lib/x86/librrc_view.so', 'apktool_out/lib/arm64-v8a/libb750.so', 'lib/x86/libreact_render_mounting.so', 'apktool_out/lib/x86_64/libreact_debug.so', 'lib/x86_64/libreact_render_attributedstring.so', 'apktool_out/lib/x86/libreact_render_templateprocessor.so', 'lib/arm64-v8a/librive-android.so', 'apktool_out/lib/x86/libturbomodulejsijni.so', 'lib/arm64-v8a/librrc_root.so', 'apktool_out/lib/x86/libreact_render_mapbuffer.so', 'lib/x86/libreact_render_mapbuffer.so', 'lib/x86_64/librsjni_androidx.so', 'apktool_out/lib/x86_64/libglog_init.so', 'apktool_out/lib/armeabi-v7a/librrc_legacyviewmanagerinterop.so', 'apktool_out/lib/armeabi-v7a/libTMXProfiling-RL-6.3-82-jni.so', 'lib/x86/libbugsnag-root-detection.so', 'apktool_out/lib/armeabi-v7a/libreact_nativemodule_core.so', 'apktool_out/lib/x86_64/librrc_root.so', 'lib/x86_64/libfolly_runtime.so', 'lib/x86_64/libbugsnag-plugin-android-anr.so', 'apktool_out/lib/x86_64/libfolly_runtime.so', 'apktool_out/lib/x86_64/libyoga.so', 'lib/arm64-v8a/libfabricjni.so', 'lib/x86/libreact_render_scheduler.so', 'apktool_out/lib/x86_64/libnative-imagetranscoder.so', 'lib/x86_64/librrc_unimplementedview.so', 'lib/x86/libreactnativeblob.so', 'apktool_out/lib/x86/libea4ea9.so', 'apktool_out/lib/armeabi-v7a/libb750.so', 'apktool_out/lib/arm64-v8a/libreact_render_graphics.so', 'lib/x86/libreact_render_debug.so', 'lib/arm64-v8a/libreact_render_imagemanager.so', 'apktool_out/lib/x86/libreactnativejni.so', 'lib/armeabi-v7a/libfbjni.so', 'apktool_out/lib/x86_64/libjsinspector.so', 'apktool_out/lib/x86_64/libreact_render_attributedstring.so', 'apktool_out/lib/arm64-v8a/libturbomodulejsijni.so', 'lib/armeabi-v7a/libe900.so', 'lib/arm64-v8a/libreact_render_runtimescheduler.so', 'lib/arm64-v8a/libruntimeexecutor.so', 'apktool_out/lib/armeabi-v7a/librive-android.so', 'apktool_out/lib/armeabi-v7a/libglog_init.so', 'lib/armeabi-v7a/libjsi.so', 'apktool_out/lib/x86_64/libhermes_executor.so', 'apktool_out/lib/arm64-v8a/libfabricjni.so', 'lib/x86/librrc_image.so', 'apktool_out/lib/arm64-v8a/libreact_render_uimanager.so', 'lib/x86_64/libreact_render_leakchecker.so', 'lib/x86/libfb.so', 'apktool_out/lib/armeabi-v7a/librrc_root.so', 'apktool_out/lib/x86/libreactnativeblob.so', 'apktool_out/lib/arm64-v8a/libyoga.so', 'lib/arm64-v8a/libreact_render_debug.so', 'apktool_out/lib/arm64-v8a/libreact_render_debug.so', 'apktool_out/lib/armeabi-v7a/libreact_render_uimanager.so', 'lib/armeabi-v7a/libreact_render_attributedstring.so', 'lib/x86/libexpo-av.so', 'apktool_out/lib/x86/libTMXProfiling-RL-6.3-82-jni.so', 'apktool_out/lib/x86/librrc_scrollview.so', 'lib/arm64-v8a/librrc_scrollview.so', 'lib/armeabi-v7a/libreact_render_runtimescheduler.so', 'apktool_out/lib/x86/liblogger.so', 'apktool_out/lib/x86/libreact_render_core.so', 'lib/x86_64/libreact_render_core.so', 'apktool_out/lib/arm64-v8a/librrc_textinput.so', 'lib/x86_64/libimagepipeline.so', 'apktool_out/lib/x86/libjsinspector.so', 'apktool_out/lib/x86_64/libbugsnag-root-detection.so', 'apktool_out/lib/armeabi-v7a/libreact_render_imagemanager.so', 'lib/x86/libfbjni.so', 'lib/x86_64/libturbomodulejsijni.so', 'apktool_out/lib/x86_64/libreact_render_core.so', 'lib/armeabi-v7a/libfolly_runtime.so', 'apktool_out/lib/armeabi-v7a/liblogger.so', 'apktool_out/lib/x86_64/librrc_scrollview.so', 'lib/x86/libb750.so', 'lib/arm64-v8a/libRSSupport.so', 'lib/x86_64/libreact_render_uimanager.so', 'lib/arm64-v8a/libreactnativejni.so', 'apktool_out/lib/arm64-v8a/libreact_utils.so', 'apktool_out/lib/x86_64/libreact_config.so', 'apktool_out/lib/x86/librrc_image.so', 'apktool_out/lib/armeabi-v7a/libc++_shared.so', 'apktool_out/lib/arm64-v8a/libreact_debug.so', 'apktool_out/lib/x86_64/libglog.so', 'lib/arm64-v8a/libbugsnag-root-detection.so', 'lib/x86/libed51b3.so', 'lib/armeabi-v7a/libreact_render_leakchecker.so', 'lib/arm64-v8a/libed51b3.so', 'apktool_out/lib/x86/libbugsnag-root-detection.so', 'lib/armeabi-v7a/libreact_newarchdefaults.so', 'apktool_out/lib/x86/libruntimeexecutor.so', 'lib/arm64-v8a/libreact_render_telemetry.so', 'lib/x86_64/libreact_render_graphics.so', 'apktool_out/lib/x86_64/librrc_textinput.so', 'lib/armeabi-v7a/libfb.so', 'lib/x86/libreact_render_componentregistry.so', 'apktool_out/lib/arm64-v8a/libfbjni.so', 'apktool_out/lib/arm64-v8a/libmapbufferjni.so', 'lib/x86_64/libreact_render_imagemanager.so', 'apktool_out/lib/armeabi-v7a/libhermes.so', 'lib/arm64-v8a/libreact_render_componentregistry.so', 'apktool_out/lib/x86_64/libimagepipeline.so', 'apktool_out/lib/armeabi-v7a/libnative-imagetranscoder.so', 'lib/arm64-v8a/libc++_shared.so', 'apktool_out/lib/armeabi-v7a/libRSSupport.so', 'lib/armeabi-v7a/libreact_render_graphics.so', 'apktool_out/lib/arm64-v8a/libreact_render_animations.so', 'apktool_out/lib/arm64-v8a/librrc_legacyviewmanagerinterop.so', 'apktool_out/lib/armeabi-v7a/libreact_render_mapbuffer.so', 'apktool_out/lib/x86/libreact_render_mounting.so', 'apktool_out/lib/arm64-v8a/libreact_codegen_rncore.so', 'lib/x86_64/libRSSupport.so', 'lib/armeabi-v7a/librrc_scrollview.so', 'lib/arm64-v8a/libfb.so', 'lib/arm64-v8a/libreact_render_leakchecker.so', 'lib/x86/libreanimated.so', 'lib/armeabi-v7a/libjsinspector.so', 'apktool_out/lib/arm64-v8a/libbugsnag-ndk.so', 'lib/armeabi-v7a/libhermes.so', 'apktool_out/lib/arm64-v8a/libc++_shared.so', 'lib/armeabi-v7a/libreact_render_core.so', 'lib/x86_64/libreact_render_mapbuffer.so', 'apktool_out/lib/arm64-v8a/libRSSupport.so', 'lib/armeabi-v7a/libnative-imagetranscoder.so', 'apktool_out/lib/x86_64/libc++_shared.so', 'lib/x86_64/libfbjni.so', 'apktool_out/lib/x86_64/librsjni.so', 'lib/x86_64/libreact_debug.so', 'apktool_out/lib/armeabi-v7a/libfolly_runtime.so', 'lib/armeabi-v7a/librrc_root.so', 'apktool_out/lib/arm64-v8a/libreanimated.so', 'lib/x86_64/libhermes_executor.so', 'lib/x86/libreact_render_attributedstring.so', 'lib/x86_64/librsjni.so', 'apktool_out/lib/x86/libreact_render_uimanager.so', 'lib/armeabi-v7a/libglog.so', 'lib/armeabi-v7a/libyoga.so', 'apktool_out/lib/armeabi-v7a/librrc_text.so'}
                    out = ap.shared_object_identifier(libs)
                    print(out)
                    import pdb; pdb.set_trace()

                # ANALYSIS BEGINS
                app_dic['size'] = str(
                    file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                app_dic['sha1'], app_dic[
                    'sha256'] = hash_gen(app_dic['app_path'])
                app_dic['files'] = unzip(
                    app_dic['app_path'], app_dic['app_dir'])
                logger.info('APK Extracted')
                if not app_dic['files']:
                    # Can't Analyze APK, bail out.
                    return print_n_send_error_response(
                        request,
                        'APK file is invalid or corrupt',
                        api)
                app_dic['certz'] = get_hardcoded_cert_keystore(app_dic[
                                                               'files'])
                # Manifest XML
                mani_file, ns, mani_xml = get_manifest(
                    app_dic['app_path'],
                    app_dic['app_dir'],
                    app_dic['tools_dir'],
                    'apk',
                )
                app_dic['manifest_file'] = mani_file
                app_dic['parsed_xml'] = mani_xml
                # Parse APK with Androguard
                apk = parse_apk(app_dic['app_path'])
                # get app_name
                app_dic['real_name'] = get_app_name(
                    apk,
                    app_dic['app_dir'],
                    True,
                )
                # Set Manifest link
                man_data_dic = manifest_data(app_dic['parsed_xml'], ns)

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
                    man_data_dic['packagename'])
                man_an_dic = manifest_analysis(
                    app_dic['parsed_xml'],
                    ns,
                    man_data_dic,
                    '',
                    app_dic['app_dir'],
                )
                # Malware Permission check
                mal_perms = permissions.check_malware_permission(
                    man_data_dic['perm'])
                man_an_dic['malware_permissions'] = mal_perms

                # Get icon
                # apktool should run before this
                get_icon_apk(apk, app_dic)

                elf_dict = library_analysis(
                    app_dic['app_dir'],
                    app_dic['md5'],
                    'elf')
                cert_dic = cert_info(
                    apk,
                    app_dic,
                    man_data_dic)
                apkid_results = apkid.apkid_analysis(app_dic[
                    'app_dir'], app_dic['app_path'], app_dic['app_name'])
                tracker = Trackers.Trackers(
                    app_dic['app_dir'], app_dic['tools_dir'])
                tracker_res = tracker.get_trackers()

                apk_2_java(app_dic['app_path'], app_dic['app_dir'],
                           app_dic['tools_dir'])

                dex_2_smali(app_dic['app_dir'], app_dic['tools_dir'])

                code_an_dic = code_analysis(
                    app_dic['app_dir'],
                    'apk',
                    app_dic['manifest_file'],
                    man_data_dic['perm'])

                quark_results = quark.quark_analysis(
                    app_dic['app_dir'],
                    app_dic['app_path'])

                # Get the strings and metadata
                get_strings_metadata(
                    apk,
                    app_dic['app_dir'],
                    elf_dict['elf_strings'],
                    'apk',
                    ['.java'],
                    code_an_dic)

                # Firebase DB Check
                code_an_dic['firebase'] = firebase_analysis(
                    code_an_dic['urls_list'])
                # Domain Extraction and Malware Check
                logger.info(
                    'Performing Malware Check on extracted Domains')
                code_an_dic['domains'] = MalwareDomainCheck().scan(
                    code_an_dic['urls_list'])

                app_dic['zipped'] = 'apk'
                context = save_get_ctx(
                    app_dic,
                    man_data_dic,
                    man_an_dic,
                    code_an_dic,
                    cert_dic,
                    elf_dict['elf_analysis'],
                    apkid_results,
                    quark_results,
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
                vt = VirusTotal.VirusTotal()
                context['virus_total'] = vt.get_result(
                    app_dic['app_path'],
                    app_dic['md5'])
            template = 'static_analysis/android_binary_analysis.html'
            if api:
                return context
            else:
                return render(request, template, context)
        elif typ == 'jar':
            return jar_analysis(request, app_dic, rescan, api)
        elif typ == 'aar':
            return aar_analysis(request, app_dic, rescan, api)
        elif typ == 'so':
            return so_analysis(request, app_dic, rescan, api)
        elif typ == 'zip':
            ret = f'/static_analyzer_ios/{checksum}/'
            # Check if in DB
            # pylint: disable=E1101
            cert_dic = {
                'certificate_info': '',
                'certificate_status': '',
                'description': '',
            }
            app_dic['strings'] = []
            app_dic['secrets'] = []
            app_dic['zipped'] = ''
            # Above fields are only available for APK and not ZIP
            app_dic['app_file'] = app_dic['md5'] + '.zip'  # NEW FILENAME
            app_dic['app_path'] = (
                app_dic['app_dir'] / app_dic['app_file']).as_posix()
            app_dic['app_dir'] = app_dic['app_dir'].as_posix() + '/'
            db_entry = StaticAnalyzerAndroid.objects.filter(
                MD5=app_dic['md5'])
            ios_db_entry = StaticAnalyzerIOS.objects.filter(
                MD5=app_dic['md5'])
            if db_entry.exists() and not rescan:
                context = get_context_from_db_entry(db_entry)
            elif ios_db_entry.exists() and not rescan:
                if api:
                    return {'type': 'ios'}
                else:
                    return HttpResponseRedirect(ret)
            else:
                logger.info('Extracting ZIP')
                app_dic['files'] = unzip(
                    app_dic['app_path'], app_dic['app_dir'])
                # Check if Valid Directory Structure and get ZIP Type
                pro_type, valid = valid_source_code(app_dic['app_dir'])
                logger.info('Source code type - %s', pro_type)
                if valid and pro_type == 'ios':
                    logger.info('Redirecting to iOS Source Code Analyzer')
                    if api:
                        return {'type': 'ios'}
                    else:
                        ret += f'?rescan={str(int(rescan))}'
                        return HttpResponseRedirect(ret)
                app_dic['certz'] = get_hardcoded_cert_keystore(
                    app_dic['files'])
                app_dic['zipped'] = pro_type
                if valid and (pro_type in ['eclipse', 'studio']):
                    if not has_permission(request, Permissions.SCAN, api):
                        return print_n_send_error_response(
                            request,
                            'Permission Denied',
                            False)
                    # ANALYSIS BEGINS
                    app_dic['size'] = str(
                        file_size(app_dic['app_path'])) + 'MB'  # FILE SIZE
                    app_dic['sha1'], app_dic[
                        'sha256'] = hash_gen(app_dic['app_path'])

                    # Manifest XML
                    mani_file, ns, mani_xml = get_manifest(
                        '',
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        pro_type,
                    )
                    app_dic['manifest_file'] = mani_file
                    app_dic['parsed_xml'] = mani_xml

                    # get app_name
                    app_dic['real_name'] = get_app_name(
                        app_dic['app_path'],
                        app_dic['app_dir'],
                        False,
                    )

                    # Set manifest view link
                    man_data_dic = manifest_data(app_dic['parsed_xml'], ns)

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
                        man_data_dic['packagename'])
                    man_an_dic = manifest_analysis(
                        app_dic['parsed_xml'],
                        ns,
                        man_data_dic,
                        pro_type,
                        app_dic['app_dir'],
                    )

                    # Malware Permission check
                    mal_perms = permissions.check_malware_permission(
                        man_data_dic['perm'])
                    man_an_dic['malware_permissions'] = mal_perms

                    # Get icon
                    get_icon_from_src(app_dic, man_data_dic['icons'])

                    code_an_dic = code_analysis(
                        app_dic['app_dir'],
                        pro_type,
                        app_dic['manifest_file'],
                        man_data_dic['perm'])

                    # Get the strings and metadata
                    get_strings_metadata(
                        None,
                        app_dic['app_dir'],
                        None,
                        pro_type,
                        ['.java', '.kt'],
                        code_an_dic)

                    # Firebase DB Check
                    code_an_dic['firebase'] = firebase_analysis(
                        code_an_dic['urls_list'])
                    # Domain Extraction and Malware Check
                    logger.info(
                        'Performing Malware Check on extracted Domains')
                    code_an_dic['domains'] = MalwareDomainCheck().scan(
                        code_an_dic['urls_list'])

                    # Extract Trackers from Domains
                    trk = Trackers.Trackers(
                        None, app_dic['tools_dir'])
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
                        [],
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
        else:
            err = ('Only APK, JAR, AAR, SO and Zipped '
                   'Android/iOS Source code supported now!')
            logger.error(err)
            raise Exception(err)
    except Exception as excep:
        logger.exception('Error Performing Static Analysis')
        msg = str(excep)
        exp = excep.__doc__
        return print_n_send_error_response(request, msg, api, exp)


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


def valid_source_code(app_dir):
    """Test if this is an valid source code zip."""
    try:
        logger.info('Detecting source code type')
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
    except Exception:
        logger.exception('Identifying source code from zip')


def move_to_parent(inside, app_dir):
    """Move contents of inside to app dir."""
    for x in os.listdir(inside):
        full_path = os.path.join(inside, x)
        shutil.move(full_path, app_dir)
    shutil.rmtree(inside)
