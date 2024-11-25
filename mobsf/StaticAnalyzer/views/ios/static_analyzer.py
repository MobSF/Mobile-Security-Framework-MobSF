# -*- coding: utf_8 -*-
"""iOS Static Code Analysis."""
import logging
from pathlib import Path

from django.conf import settings
from django.template.defaulttags import register

from mobsf.MobSF.utils import (
    append_scan_status,
    is_md5,
    print_n_send_error_response,
    relative_path,
)
from mobsf.StaticAnalyzer.models import (
    RecentScansDB,
)
from mobsf.StaticAnalyzer.views.common.a import (
    a_analysis,
)
from mobsf.StaticAnalyzer.views.ios.dylib import (
    dylib_analysis,
)
from mobsf.StaticAnalyzer.views.ios.ipa import (
    ios_analysis,
    ipa_analysis,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)

logger = logging.getLogger(__name__)
register.filter('relative_path', relative_path)


@login_required
def static_analyzer_ios(request, checksum, api=False):
    """Module that performs iOS IPA/ZIP Static Analysis."""
    try:
        rescan = False
        if api:
            re_scan = request.POST.get('re_scan', 0)
        else:
            re_scan = request.GET.get('rescan', 0)
        if re_scan == '1':
            rescan = True
        app_dict = {}
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
        file_type = robj[0].SCAN_TYPE
        filename = robj[0].FILE_NAME
        if file_type == 'dylib' and not Path(filename).suffix:
            # Force dylib extension on Frameworks
            filename = f'{filename}.dylib'
        ios_exts = tuple(f'.{i}' for i in settings.IOS_EXTS)
        allowed_exts = ios_exts + ('.zip', 'ios')
        allowed_types = settings.IOS_EXTS + ('zip', 'ios')
        if (not filename.lower().endswith(allowed_exts)
                or file_type not in allowed_types):
            return print_n_send_error_response(
                request,
                'Invalid file extension or file type',
                api)
        app_dict['directory'] = Path(settings.BASE_DIR)  # BASE DIR
        app_dict['file_name'] = filename  # APP ORIGINAL NAME
        app_dict['md5_hash'] = checksum  # MD5
        app_dict['app_dirp'] = Path(settings.UPLD_DIR) / checksum
        app_dict['app_dir'] = app_dict['app_dirp'].as_posix() + '/'
        tools_dir = app_dict[
            'directory'] / 'StaticAnalyzer' / 'tools' / 'ios'
        app_dict['tools_dir'] = tools_dir.as_posix()
        app_dict['icon_path'] = ''
        if file_type == 'ipa':
            return ipa_analysis(request, app_dict, rescan, api)
        elif file_type == 'dylib':
            return dylib_analysis(request, app_dict, rescan, api)
        elif file_type == 'a':
            return a_analysis(request, app_dict, rescan, api)
        elif file_type in ('ios', 'zip'):
            return ios_analysis(request, app_dict, rescan, api)
        else:
            err = ('File Type not supported, '
                   'Only IPA, A, DYLIB and ZIP are supported')
            logger.error(err)
            append_scan_status(checksum, err)
            raise Exception(err)
    except Exception as exp:
        msg = 'Error Performing Static Analysis'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
        exp_doc = exp.__doc__
        return print_n_send_error_response(request, repr(exp), api, exp_doc)
