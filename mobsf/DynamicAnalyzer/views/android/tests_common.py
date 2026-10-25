# -*- coding: utf_8 -*-
"""Available Actions."""
import logging
import os
import re
from pathlib import Path

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.frida_core import (
    Frida,
    GADGET_SESSION_REQUIRED,
)
from mobsf.DynamicAnalyzer.views.android.tests_xposed import (
    download_xposed_log,
)
from mobsf.DynamicAnalyzer.views.android.tests_tls import (
    run_tls_tests,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    stop_httptools,
)
from mobsf.MobSF.security import (
    cmd_injection_check,
    is_safe_path,
)
from mobsf.MobSF.utils import (
    clear_analysis_state,
    get_device,
    get_gadget_analysis,
    is_gadget_analysis,
    is_md5,
    python_list,
    read_analysis_state,
    strict_package_check,
    valid_android_device_identifier,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)


def get_analysis_identifier(request, md5_hash):
    """Resolve the device bound to an active analysis."""
    if not is_md5(md5_hash):
        return None
    identifier = read_analysis_state(md5_hash).get('identifier')
    if not valid_android_device_identifier(identifier):
        marker_identifier = get_gadget_analysis(md5_hash)
        if valid_android_device_identifier(marker_identifier):
            identifier = marker_identifier
    if valid_android_device_identifier(identifier):
        return identifier
    return get_device(request)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def start_activity(request, api=False):
    """Launch a specific activity."""
    try:
        env = Environment(get_device(request))
        activity = request.POST['activity']
        md5_hash = request.POST['hash']

        valid_md5 = is_md5(md5_hash)
        valid_act = re.match(r'^[\w]+(\.[\w]+)*$', activity)
        if not valid_act or not valid_md5:
            return invalid_params(api)
        if Frida.gadget_needs_session(md5_hash):
            return send_response({
                'status': 'failed',
                'message': GADGET_SESSION_REQUIRED,
            }, api)

        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        logger.info('Launching Activity - %s', activity)
        outfile = ('{}act-{}.png'.format(screen_dir, activity))
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
        if (not isinstance(package, str)
                or not strict_package_check(package)):
            return invalid_params(api)
        env.launch_n_capture(package, activity, outfile)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Start Activity')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def start_deeplink(request, api=False):
    """Launch a specific deeplink."""
    try:
        env = Environment(get_device(request))
        url = request.POST['url']
        md5_hash = request.POST['hash']

        valid_md5 = is_md5(md5_hash)
        if cmd_injection_check(url) or not valid_md5:
            return invalid_params(api)
        if Frida.gadget_needs_session(md5_hash):
            return send_response({
                'status': 'failed',
                'message': GADGET_SESSION_REQUIRED,
            }, api)
        env.adb_command(
            ['am', 'start', '-a',
             'android.intent.action.VIEW',
             '-d', url], True)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Start Activity')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def activity_tester(request, api=False):
    """Exported & non exported activity Tester."""
    data = {}
    try:
        env = Environment(get_device(request))
        test = request.POST['test']
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        if Frida.gadget_needs_session(md5_hash):
            return send_response({
                'status': 'failed',
                'message': GADGET_SESSION_REQUIRED,
            }, api)
        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
        if (not isinstance(package, str)
                or not strict_package_check(package)):
            return invalid_params(api)
        iden = ''
        if test == 'exported':
            iden = 'Exported '
            logger.info('Exported activity tester')
            activities = python_list(static_android_db.EXPORTED_ACTIVITIES)
        else:
            logger.info('Activity tester')
            activities = python_list(static_android_db.ACTIVITIES)
        logger.info('Fetching %sactivities for %s', iden, package)
        if not activities:
            msg = 'No {}Activities found'.format(iden)
            logger.info(msg)
            data = {'status': 'failed',
                    'message': msg}
            return send_response(data, api)
        act_no = 0
        logger.info('Starting %sActivity Tester...', iden)
        logger.info('%s %sActivities Identified',
                    str(len(activities)), iden)
        for activity in activities:
            act_no += 1
            logger.info(
                'Launching %sActivity - %s. %s',
                iden,
                str(act_no),
                activity)
            if test == 'exported':
                file_iden = 'expact'
            else:
                file_iden = 'act'
            outfile = ('{}{}-{}.png'.format(
                screen_dir,
                file_iden,
                act_no))
            env.launch_n_capture(package, activity, outfile)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('%sActivity tester', iden)
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def download_data(request, api=False, identifier=None):
    """Download Application Data from Device."""
    logger.info('Downloading app data')
    data = {}
    try:
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        if identifier is None:
            identifier = get_analysis_identifier(request, md5_hash)
        if not valid_android_device_identifier(identifier):
            return invalid_params(api)
        env = Environment(identifier)
        package = get_package_name(md5_hash, env.identifier)
        if (not isinstance(package, str)
                or not strict_package_check(package)):
            data = {'status': 'failed',
                    'message': 'Invalid app details'}
            return send_response(data, api)
        apk_dir = Path(settings.UPLD_DIR) / md5_hash
        stop_httptools()
        logger.info('Archiving files created by app')
        archive_name = f'{package}.tar'
        output_file = apk_dir / archive_name
        if not is_safe_path(apk_dir, output_file, archive_name):
            return invalid_params(api)
        output_file.unlink(missing_ok=True)
        archive_status = env.archive_app_data(
            package, output_file.as_posix())
        if archive_status != 'ok':
            output_file.unlink(missing_ok=True)
        if archive_status == 'ok':
            data = {'status': 'ok', 'data_collected': True}
        elif archive_status == 'unsupported':
            data = {
                'status': 'ok',
                'data_collected': False,
                'message': (
                    'Application data is not accessible with the '
                    'selected device capabilities'
                ),
            }
        else:
            data = {
                'status': 'failed',
                'message': 'Failed to archive application data',
            }
    except Exception as exp:
        logger.exception('Downloading application data')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def collect_logs(request, api=False, identifier=None):
    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    data = {}
    try:
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        bound_identifier = read_analysis_state(md5_hash).get('identifier')
        if valid_android_device_identifier(bound_identifier):
            identifier = bound_identifier
        if not valid_android_device_identifier(identifier):
            identifier = get_analysis_identifier(request, md5_hash)
        if not valid_android_device_identifier(identifier):
            return invalid_params(api)
        env = Environment(identifier)
        package = get_package_name(md5_hash, env.identifier)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data, api)
        lout = os.path.join(apk_dir, 'logcat.txt')
        dout = os.path.join(apk_dir, 'dump.txt')
        try:
            logger.info('Downloading logcat logs')
            logcat = env.adb_command(['logcat',
                                      '-d',
                                      package + ':V',
                                      '*:*'])
            with open(lout, 'wb') as flip:
                flip.write(logcat or b'')
            logger.info('Downloading dumpsys logs')
            dumpsys = env.adb_command(['dumpsys'], True)
            with open(dout, 'wb') as flip:
                flip.write(dumpsys or b'')
            if env.get_android_version() < 5:
                download_xposed_log(apk_dir, env.identifier)
        finally:
            env.adb_command(['am', 'force-stop', package], True)
            logger.info('Stopping app')
            env.clear_proxy()
            Frida.close_active(md5_hash, env.identifier, package)
            env.stop_physical_frida_server()
            env.remove_frida_forward()
            clear_analysis_state(md5_hash)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Data Collection & Clean Up failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def tls_tests(request, api=False):
    """Perform TLS tests."""
    logger.info('Running TLS/SSL Security tests')
    data = {}
    env = None
    package = None
    resume_proxy = False
    try:
        test_duration = 25
        test_package = 'tls_tests'
        env = Environment(get_device(request))
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        if (is_gadget_analysis(md5_hash)
                or env.get_environment() == 'physical'):
            return send_response({
                'status': 'failed',
                'message': (
                    'TLS testing is unavailable when MobSF cannot '
                    'transition the device Root CA'
                ),
            }, api)
        package = get_package_name(md5_hash, env.identifier)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data, api)
        resume_proxy = True
        res = run_tls_tests(
            request,
            md5_hash,
            env,
            package,
            test_package,
            test_duration,
        )
        data = {'status': 'ok', 'tls_tests': res}
    except Exception as exp:
        logger.exception('Checking Application Security in Transit')
        data = {'status': 'failed', 'message': str(exp)}
    finally:
        if resume_proxy and env and package:
            logger.info('Test Completed. Resuming HTTPS Proxy')
            env.configure_proxy(package, request)
    return send_response(data, api)
