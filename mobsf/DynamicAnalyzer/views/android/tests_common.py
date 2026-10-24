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
    android_analysis_is_active,
    android_analysis_lifecycle,
    android_analysis_operation,
    android_analysis_state_file,
    android_gadget_marker_file,
    get_android_analysis_claim,
    get_android_frida_target,
    get_package_name,
    get_requested_android_analysis,
    release_android_analysis,
    write_android_analysis_state,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.frida_core import Frida
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
    is_md5,
    python_list,
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
    identifier, _ = get_requested_android_analysis(
        request, md5_hash)
    return identifier


def _active_analysis_environment(request, checksum):
    """Return the environment for the exact active client generation."""
    identifier, analysis_id = get_requested_android_analysis(
        request, checksum)
    if not android_analysis_is_active(
            identifier, checksum, analysis_id):
        return None
    return Environment(identifier)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
@android_analysis_operation
def start_activity(request, api=False):
    """Launch a specific activity."""
    try:
        activity = request.POST['activity']
        md5_hash = request.POST['hash']

        valid_md5 = is_md5(md5_hash)
        valid_act = re.match(r'^[\w]+(\.[\w]+)*$', activity)
        if not valid_act or not valid_md5:
            return invalid_params(api)
        env = _active_analysis_environment(request, md5_hash)
        if env is None:
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
@android_analysis_operation
def start_deeplink(request, api=False):
    """Launch a specific deeplink."""
    try:
        url = request.POST['url']
        md5_hash = request.POST['hash']

        valid_md5 = is_md5(md5_hash)
        if cmd_injection_check(url) or not valid_md5:
            return invalid_params(api)
        env = _active_analysis_environment(request, md5_hash)
        if env is None:
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
@android_analysis_operation
def activity_tester(request, api=False):
    """Exported & non exported activity Tester."""
    data = {}
    try:
        test = request.POST['test']
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        env = _active_analysis_environment(request, md5_hash)
        if env is None:
            return invalid_params(api)
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
    """Serialize final data collection with Android lifecycle changes."""
    try:
        with android_analysis_lifecycle():
            return _download_data(request, api, identifier)
    except TimeoutError as exp:
        return send_response({
            'status': 'failed',
            'message': str(exp),
        }, api)


def _download_data(request, api=False, identifier=None):
    """Download Application Data from Device."""
    logger.info('Downloading app data')
    data = {}
    state_file = None
    gadget_marker = None
    owns_analysis = False
    try:
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        bound_identifier, analysis_id = get_requested_android_analysis(
            request, md5_hash)
        if identifier is not None and identifier != bound_identifier:
            return invalid_params(api)
        identifier = bound_identifier
        if not valid_android_device_identifier(identifier):
            return invalid_params(api)
        state_file = android_analysis_state_file(md5_hash)
        gadget_marker = android_gadget_marker_file(md5_hash)
        if state_file is None or gadget_marker is None:
            return invalid_params(api)
        claim_checksum = get_android_analysis_claim(identifier)
        if claim_checksum != md5_hash:
            return send_response({
                'status': 'ok',
                'analysis_inactive': True,
                'data_collected': False,
                'message': 'Analysis was already cleaned up',
            }, api)
        state = {}
        if state_file.is_file() and not state_file.is_symlink():
            try:
                with state_file.open(encoding='utf-8') as source:
                    state = json.load(source)
            except (OSError, ValueError, TypeError):
                state = {}
        if (not isinstance(state, dict)
                or state.get('identifier') != identifier
                or state.get('analysis_id') != analysis_id
                or state.get('cleanup_complete') is not True):
            return send_response({
                'status': 'failed',
                'message': 'Collect logs before downloading app data',
            }, api)
        owns_analysis = True
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
        archive_status = env.archive_app_data(
            package, output_file.as_posix())
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
    finally:
        if owns_analysis:
            gadget_marker.unlink(missing_ok=True)
            release_android_analysis(identifier, md5_hash)
            state.update({
                'analysis_ready': False,
                'analysis_released': True,
                'cleanup_complete': True,
                'finalizing': False,
            })
            write_android_analysis_state(md5_hash, state)
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def collect_logs(request, api=False, identifier=None):
    """Serialize Android cleanup across threads and workers."""
    try:
        with android_analysis_lifecycle():
            return _collect_logs(request, api, identifier)
    except TimeoutError as exp:
        return send_response({
            'status': 'failed',
            'message': str(exp),
        }, api)


def _collect_logs(request, api=False, identifier=None):
    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    data = {}
    try:
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        bound_identifier, analysis_id = get_requested_android_analysis(
            request, md5_hash)
        if identifier is not None and identifier != bound_identifier:
            return invalid_params(api)
        identifier = bound_identifier
        if not valid_android_device_identifier(identifier):
            return invalid_params(api)
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        state_file = android_analysis_state_file(md5_hash)
        gadget_marker = android_gadget_marker_file(md5_hash)
        if state_file is None or gadget_marker is None:
            return invalid_params(api)
        proxy_state = {}
        if state_file.is_file() and not state_file.is_symlink():
            try:
                with state_file.open(encoding='utf-8') as source:
                    proxy_state = json.load(source)
            except (OSError, ValueError, TypeError):
                logger.warning(
                    'Unable to read saved Android proxy state')
            if not isinstance(proxy_state, dict):
                proxy_state = {}
        if (proxy_state.get('identifier') != identifier
                or proxy_state.get('analysis_id') != analysis_id):
            return invalid_params(api)
        claim_checksum = get_android_analysis_claim(identifier)
        if (claim_checksum != md5_hash
                and proxy_state.get('analysis_released') is True
                and proxy_state.get('cleanup_complete') is True):
            return send_response({
                'status': 'ok',
                'analysis_inactive': True,
                'message': 'Analysis was already cleaned up',
            }, api)
        if claim_checksum != md5_hash:
            return invalid_params(api)
        if (claim_checksum == md5_hash
                and proxy_state.get('cleanup_complete') is True):
            return send_response({
                'status': 'ok',
                'message': 'Logs were already collected',
            }, api)
        proxy_state['finalizing'] = True
        write_android_analysis_state(md5_hash, proxy_state)
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
            frida_target = (
                get_android_frida_target(env.identifier, md5_hash)
                or package
            )
            if frida_target != package:
                env.adb_command(
                    ['am', 'force-stop', frida_target], True)
            proxy_restored = True
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
            frida_closed = Frida.close_active(
                md5_hash,
                env.identifier,
                frida_target,
            )
            if frida_closed:
                frida_closed = env.remove_frida_forward()
            if proxy_restored and frida_closed:
                proxy_state.update({
                    'identifier': env.identifier,
                    'checksum': md5_hash,
                    'cleanup_complete': True,
                })
                write_android_analysis_state(md5_hash, proxy_state)
            if not proxy_restored:
                raise RuntimeError(
                    'Failed to restore the Android proxy setting')
            if not frida_closed:
                raise RuntimeError(
                    'Failed to close the active Frida session')
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
    """Serialize TLS proxy transitions with Android lifecycle changes."""
    try:
        with android_analysis_lifecycle():
            return _tls_tests(request, api)
    except TimeoutError as exp:
        return send_response({
            'status': 'failed',
            'message': str(exp),
        }, api)


def _tls_tests(request, api=False):
    """Perform TLS tests."""
    logger.info('Running TLS/SSL Security tests')
    data = {}
    env = None
    package = None
    resume_proxy = False
    try:
        test_duration = 25
        test_package = 'tls_tests'
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params(api)
        identifier, analysis_id = get_requested_android_analysis(
            request, md5_hash)
        if not android_analysis_is_active(
                identifier, md5_hash, analysis_id):
            return send_response({
                'status': 'failed',
                'message': 'Android analysis is no longer active',
            }, api)
        env = Environment(identifier)
        gadget_marker = (
            android_gadget_marker_file(md5_hash)
        )
        if (gadget_marker is None
                or (gadget_marker.is_file()
                    and not gadget_marker.is_symlink())
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
