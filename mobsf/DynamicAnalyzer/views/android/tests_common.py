# -*- coding: utf_8 -*-
"""Available Actions."""
import json
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
from mobsf.DynamicAnalyzer.views.android.tests_xposed import (
    download_xposed_log,
)
from mobsf.DynamicAnalyzer.views.android.tests_tls import (
    run_tls_tests,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    stop_httptools,
)
from mobsf.MobSF.security import cmd_injection_check
from mobsf.MobSF.utils import (
    get_device,
    is_md5,
    python_list,
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

        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        logger.info('Launching Activity - %s', activity)
        outfile = ('{}act-{}.png'.format(screen_dir, activity))
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
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
        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=md5_hash)
        package = static_android_db.PACKAGE_NAME
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
def download_data(request, api=False):
    """Download Application Data from Device."""
    logger.info('Downloading app data')
    data = {}
    try:
        env = Environment(get_device(request))
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        package = get_package_name(md5_hash, env.identifier)
        if not package:
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return send_response(data, api)
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        stop_httptools(get_http_tools_url(request))
        logger.info('Archiving files created by app')
        output_file = os.path.join(apk_dir, package + '.tar')
        archive_status = env.archive_app_data(package, output_file)
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
def collect_logs(request, api=False):
    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    data = {}
    try:
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        state_file = Path(apk_dir) / '.mobsf-proxy-state'
        gadget_marker = Path(apk_dir) / '.mobsf-gadget-mode'
        proxy_state = {}
        # codeql[py/path-injection]: md5 hash and state paths validated above
        if state_file.is_file() and not state_file.is_symlink():
            try:
                # codeql[py/path-injection]: regular non-symlink state file
                with state_file.open(encoding='utf-8') as source:
                    proxy_state = json.load(source)
            except (OSError, ValueError, TypeError):
                logger.warning(
                    'Unable to read saved Android proxy state')
            if not isinstance(proxy_state, dict):
                proxy_state = {}
        identifier = proxy_state.get('identifier')
        # codeql[py/path-injection]: marker path derives from validated hash
        if (not valid_android_device_identifier(identifier)
                and gadget_marker.is_file()
                and not gadget_marker.is_symlink()):
            # codeql[py/path-injection]: regular non-symlink marker above
            marker_identifier = gadget_marker.read_text(
                encoding='utf-8',
                errors='ignore',
            ).strip()
            if valid_android_device_identifier(marker_identifier):
                identifier = marker_identifier
        if not valid_android_device_identifier(identifier):
            identifier = get_device(request)
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
            # codeql[py/path-injection]: output derives from validated hash
            with open(lout, 'wb') as flip:
                flip.write(logcat or b'')
            logger.info('Downloading dumpsys logs')
            dumpsys = env.adb_command(['dumpsys'], True)
            # codeql[py/path-injection]: output derives from validated hash
            with open(dout, 'wb') as flip:
                flip.write(dumpsys or b'')
            if env.get_android_version() < 5:
                download_xposed_log(apk_dir, env.identifier)
        finally:
            env.adb_command(['am', 'force-stop', package], True)
            logger.info('Stopping app')
            proxy_restored = True
            # codeql[py/path-injection]: state path derives from validated hash
            if state_file.exists() and not state_file.is_symlink():
                previous_proxy = ''
                value = proxy_state.get('proxy')
                if isinstance(value, str):
                    previous_proxy = value
                proxy_restored = env.restore_global_proxy(previous_proxy)
                if proxy_state.get('remove_reverse') is True:
                    env.disable_adb_reverse_tcp()
            else:
                logger.info(
                    'No MobSF proxy ownership state found; '
                    'checking for stale MobSF proxy state')
                current_proxy = env.get_global_proxy()
                mobsf_proxy = env.get_mobsf_proxy(
                    env.get_android_version())
                if current_proxy and current_proxy == mobsf_proxy:
                    proxy_restored = env.restore_global_proxy('')
                    env.disable_adb_reverse_tcp()
            env.remove_frida_forward()
            if proxy_restored:
                # codeql[py/path-injection]: validated state path
                state_file.unlink(missing_ok=True)
            # codeql[py/path-injection]: validated marker path
            gadget_marker.unlink(missing_ok=True)
            if not proxy_restored:
                raise RuntimeError(
                    'Failed to restore the Android proxy setting')
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
        gadget_marker = (
            Path(settings.UPLD_DIR)
            / md5_hash
            / '.mobsf-gadget-mode'
        )
        # codeql[py/path-injection]: marker derives from validated hash
        if ((gadget_marker.is_file() and not gadget_marker.is_symlink())
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
