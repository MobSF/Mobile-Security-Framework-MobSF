# -*- coding: utf_8 -*-
"""Android Static Code Analysis."""

import logging
from pathlib import Path

from django.conf import settings
from django.template.defaulttags import register

from mobsf.MobSF.utils import (
    android_component,
    append_scan_status,
    is_md5,
    key,
    pathify,
    print_n_send_error_response,
    relative_path,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
)
from mobsf.StaticAnalyzer.views.android.xapk import (
    handle_aab,
    handle_split_apk,
    handle_xapk,
)
from mobsf.StaticAnalyzer.views.android.apk import (
    apk_analysis,
    src_analysis,
)
from mobsf.StaticAnalyzer.views.android.jar_aar import (
    aar_analysis,
    jar_analysis,
)
from mobsf.StaticAnalyzer.views.android.so import (
    so_analysis,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

APK_TYPE = 'apk'
logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('android_component', android_component)
register.filter('relative_path', relative_path)
register.filter('pathify', pathify)


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
        msg = f'Scan Hash: {checksum}'
        logger.info(msg)
        # APP DIRECTORY
        app_dic['app_dir'] = Path(settings.UPLD_DIR) / checksum
        app_dic['tools_dir'] = app_dic['dir'] / 'StaticAnalyzer' / 'tools'
        app_dic['tools_dir'] = app_dic['tools_dir'].as_posix()
        app_dic['icon_path'] = ''
        msg = f'Starting Analysis on: {filename}'
        logger.info(msg)
        if typ == 'xapk':
            # Handle XAPK
            # Base APK will have the MD5 of XAPK
            if not handle_xapk(app_dic):
                raise Exception('Invalid XAPK File')
            typ = APK_TYPE
        elif typ == 'apks':
            # Handle Split APK
            if not handle_split_apk(app_dic):
                raise Exception('Invalid Split APK File')
            typ = APK_TYPE
        elif typ == 'aab':
            # Convert AAB to APK
            if not handle_aab(app_dic):
                raise Exception('Invalid AAB File')
            typ = APK_TYPE
        # Route to respective analysis
        if typ == APK_TYPE:
            return apk_analysis(request, app_dic, rescan, api)
        elif typ == 'jar':
            return jar_analysis(request, app_dic, rescan, api)
        elif typ == 'aar':
            return aar_analysis(request, app_dic, rescan, api)
        elif typ == 'so':
            return so_analysis(request, app_dic, rescan, api)
        elif typ == 'zip':
            return src_analysis(request, app_dic, rescan, api)
        else:
            err = ('Only APK, JAR, AAR, SO and Zipped '
                   'Android/iOS Source code supported now!')
            logger.error(err)
            append_scan_status(checksum, err)
            raise Exception(err)
    except Exception as exp:
        errmsg = 'Error Performing Static Analysis'
        logger.exception(errmsg)
        exp = exp.__doc__
        append_scan_status(checksum, errmsg, repr(exp))
        return print_n_send_error_response(request, repr(exp), api, exp)
