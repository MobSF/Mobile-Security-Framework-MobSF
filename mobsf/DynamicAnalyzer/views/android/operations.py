# -*- coding: utf_8 -*-
"""Dynamic Analyzer Operations."""
import json
import hashlib
import logging
import os
import random
import shlex
import subprocess
import threading
from pathlib import Path

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.MobSF.security import is_attack_pattern
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.frida_core import (
    Frida,
    GADGET_SESSION_REQUIRED,
)
from mobsf.DynamicAnalyzer.views.android.progress import (
    progress_response,
)
from mobsf.MobSF.security import cmd_injection_check
from mobsf.MobSF.utils import (
    clear_analysis_state,
    docker_translate_localhost,
    get_adb,
    get_device,
    is_md5,
    is_number,
    read_analysis_state,
    scan_state_root,
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


# Helpers

def _device_packages_file(identifier):
    """Return a device-scoped package inventory path."""
    if not identifier:
        return None
    digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    return Path(settings.DWD_DIR) / f'packages-{digest}.json'


def supersede_android_analyses():
    """Best-effort cleanup of previous analyses before starting a new one."""
    try:
        Frida.close_all()
    except Exception:
        logger.exception('Unable to close previous Frida sessions')
    cleaned = set()
    for state_file in scan_state_root().glob('*/proxy-state'):
        checksum = state_file.parent.name
        if not is_md5(checksum):
            continue
        identifier = read_analysis_state(checksum).get('identifier')
        if valid_android_device_identifier(identifier):
            try:
                env = Environment(identifier)
                if env.get_device_state() == 'device':
                    # A running Gadget app keeps port 27042 bound.
                    package = get_package_name(checksum, identifier)
                    if package:
                        env.adb_command(
                            ['am', 'force-stop', package],
                            True,
                            timeout=10)
                    if identifier not in cleaned:
                        cleaned.add(identifier)
                        env.clear_proxy()
                        env.stop_physical_frida_server()
                        env.remove_frida_forward()
            except Exception:
                logger.exception(
                    'Unable to clean up previous Android analysis')
        clear_analysis_state(checksum)


def save_device_packages(identifier, packages):
    """Persist one device package inventory."""
    package_file = _device_packages_file(identifier)
    if package_file:
        package_file.write_text(
            json.dumps(packages),
            encoding='utf-8',
        )


def get_package_name(checksum, identifier=None):
    """Get Package Name from DB or Device."""
    try:
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=checksum)
        package = static_android_db.PACKAGE_NAME
        return (
            package
            if isinstance(package, str) and strict_package_check(package)
            else None
        )
    except Exception:
        if identifier:
            package_files = (_device_packages_file(identifier),)
        else:
            package_files = Path(settings.DWD_DIR).glob(
                'packages-*.json')
        for package_file in package_files:
            if (package_file is None
                    or not package_file.is_file()
                    or package_file.is_symlink()):
                continue
            try:
                with package_file.open(encoding='utf-8') as src:
                    packages = json.load(src)
            except (OSError, ValueError, TypeError):
                continue
            if not isinstance(packages, dict):
                continue
            details = packages.get(checksum)
            if (isinstance(details, (list, tuple))
                    and details):
                package = details[0]
                return (
                    package
                    if (isinstance(package, str)
                        and strict_package_check(package))
                    else None
                )
        return None
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def mobsfy(request, api=False):
    """Configure Instance for Dynamic Analysis."""
    if not api and request.headers.get('X-MobSF-Progress') == '1':
        return progress_response(lambda: _mobsfy_result(request))
    return send_response(_mobsfy_result(request), api)


def _mobsfy_result(request):
    """Prepare one Android runtime and return the status payload."""
    logger.info('MobSFying Android instance')
    data = {}
    msg = 'Connection failed'
    try:
        identifier = request.POST['identifier']
        if cmd_injection_check(identifier):
            # Additional Check, not required
            data = {
                'status': 'failed',
                'message': 'Command Injection Detected',
            }
            return data
        identifier = docker_translate_localhost(identifier)
        create_env = Environment(identifier)
        if not create_env.connect_n_mount():
            data = {'status': 'failed', 'message': msg}
            return data
        version = create_env.mobsfy_init()
        if not version:
            data = {'status': 'failed', 'message': msg}
            return data
        data = {'status': 'ok', 'android_version': version}
    except Exception as exp:
        logger.exception('MobSFying Android instance failed')
        data = {'status': 'failed', 'message': str(exp)}
    return data

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def execute_adb(request, api=False):
    """Execute ADB Commands."""
    data = {'status': 'ok', 'message': ''}
    cmd = request.POST['cmd']
    if cmd:
        identifier = get_device(request)
        if not identifier:
            return send_response({
                'status': 'failed',
                'message': 'No Android device selected',
            }, api)
        args = [get_adb(),
                '-s',
                identifier]
        stdout = b''
        stderr = b''
        try:
            proc = subprocess.Popen(
                args + cmd.split(' '),  # lgtm [py/command-line-injection]
                stdout=subprocess.PIPE,  # Expected, cmd execute inside VM/AVD
                stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
        except Exception:
            logger.exception('Executing ADB Commands')
        if stdout or stderr:
            out = stdout or stderr
            out = out.decode('utf8', 'ignore')
        else:
            out = ''
        data = {'status': 'ok', 'message': out}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def get_component(request):
    """Get Android Component."""
    data = {}
    try:
        env = Environment(get_device(request))
        comp = request.POST['component']
        bin_hash = request.POST['hash']
        if is_attack_pattern(comp) or not is_md5(bin_hash):
            return invalid_params()
        comp = env.android_component(bin_hash, comp)
        data = {'status': 'ok', 'message': comp}
    except Exception as exp:
        logger.exception('Getting Android Component')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def run_apk(request):
    """Run Android APK."""
    data = {}
    try:
        env = Environment(get_device(request))
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params()
        if Frida.gadget_needs_session(md5_hash):
            return send_response({
                'status': 'failed',
                'message': GADGET_SESSION_REQUIRED,
            })
        pkg = get_package_name(md5_hash, env.identifier)
        if not pkg:
            return invalid_params()
        env.run_app(pkg)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Running the App')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def take_screenshot(request, api=False):
    """Take Screenshot."""
    logger.info('Taking screenshot')
    data = {}
    try:
        env = Environment(get_device(request))
        bin_hash = request.POST['hash']
        if not is_md5(bin_hash):
            return invalid_params(api)
        data = {}
        rand_int = random.randint(1, 1000000)
        screen_dir = os.path.join(settings.UPLD_DIR,
                                  bin_hash + '/screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        outile = '{}screenshot-{}.png'.format(
            screen_dir,
            str(rand_int))
        if not env.screen_shot(outile):
            return send_response({
                'status': 'failed',
                'message': 'Failed to capture screenshot',
            }, api)
        logger.info('Screenshot captured')
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Taking screenshot')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def screen_cast(request):
    """ScreenCast."""
    data = {
        'status': 'failed',
        'message': 'Failed to stream screen'}
    try:
        env = Environment(get_device(request))
        b64dat = env.screen_stream()
        if not b64dat:
            return send_response(data)
        data = {
            'status': 'ok',
            'message': f'data:image/png;base64,{b64dat}'}
    except Exception as exp:
        logger.exception('Screen streaming')
        data['message'] = str(exp)
    return send_response(data)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def touch(request):
    """Sending Touch/Swipe/Text Events."""
    data = {
        'status': 'failed',
        'message': '',
    }
    try:
        env = Environment(get_device(request))
        x = request.POST['x']
        y = request.POST['y']
        event = request.POST['event']
        end_x = request.POST.get('end_x', 0)
        end_y = request.POST.get('end_y', 0)
        max_x = request.POST.get('max_x', 0)
        max_y = request.POST.get('max_y', 0)

        if event == 'text':
            args = ['text', shlex.quote(x)]
        else:
            if (not is_number(x)
                    or not is_number(y)
                    or not is_number(end_x)
                    or not is_number(end_y)
                    or not is_number(max_x)
                    or not is_number(max_y)):
                return data
            width = max(1, int(float(max_x)))
            height = max(1, int(float(max_y)))
            max_screen_x = width - 1
            max_screen_y = height - 1
            touch_x = max(0, min(int(float(x)), max_screen_x))
            touch_y = max(0, min(int(float(y)), max_screen_y))
            distance_x = max(50, width // 4)
            distance_y = max(50, height // 4)
            left_x = max(0, touch_x - distance_x)
            right_x = min(max_screen_x, touch_x + distance_x)
            up_y = max(0, touch_y - distance_y)
            down_y = min(max_screen_y, touch_y + distance_y)
            touch_x = str(touch_x)
            touch_y = str(touch_y)
            end_x = str(max(
                0, min(int(float(end_x)), max_screen_x)))
            end_y = str(max(
                0, min(int(float(end_y)), max_screen_y)))

            if event == 'enter':
                args = ['keyevent', '66']
            elif event == 'backspace':
                args = ['keyevent', '67']
            elif event == 'left':
                args = ['keyevent', '21']
            elif event == 'right':
                args = ['keyevent', '22']
            elif event == 'back':
                args = ['keyevent', '4']
            elif event == 'home':
                args = ['keyevent', '3']
            elif event == 'recents':
                args = ['keyevent', '187']
            elif event == 'swipe':
                args = [
                    'swipe', touch_x, touch_y,
                    end_x, end_y, '300',
                ]
            elif event == 'swipe_up':
                args = [
                    'swipe', touch_x, str(down_y),
                    touch_x, str(up_y), '300',
                ]
            elif event == 'swipe_down':
                args = [
                    'swipe', touch_x, str(up_y),
                    touch_x, str(down_y), '300',
                ]
            elif event == 'swipe_left':
                args = [
                    'swipe', str(right_x), touch_y,
                    str(left_x), touch_y, '300',
                ]
            elif event == 'swipe_right':
                args = [
                    'swipe', str(left_x), touch_y,
                    str(right_x), touch_y, '300',
                ]
            elif event == 'touch':
                args = ['tap', touch_x, touch_y]
            else:
                data['message'] = 'Unsupported input event'
                return send_response(data)
        threading.Thread(target=env.adb_command,
                         args=(['input'] + args, True),
                         daemon=True).start()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Sending Touchscreen Events')
        data['message'] = str(exp)
    return send_response(data)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def mobsf_ca(request, api=False):
    """Install and Remove MobSF Proxy RootCA."""
    data = {}
    try:
        env = Environment(get_device(request))
        action = request.POST['action']
        if action == 'install':
            env.install_mobsf_ca(action)
            data = {'status': 'ok', 'message': 'installed'}
        elif action == 'remove':
            env.install_mobsf_ca(action)
            data = {'status': 'ok', 'message': 'removed'}
        else:
            data = {'status': 'failed',
                    'message': 'Action not supported'}
    except Exception as exp:
        logger.exception('MobSF RootCA Handler')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def global_proxy(request, api=False):
    """Set/unset global proxy."""
    data = {}
    try:
        env = Environment(get_device(request))
        version = env.get_android_version()
        action = request.POST['action']
        if action == 'set':
            env.set_global_proxy(version)
            data = {'status': 'ok', 'message': 'set'}
        elif action == 'unset':
            env.unset_global_proxy()
            data = {'status': 'ok', 'message': 'unset'}
        else:
            data = {'status': 'failed',
                    'message': 'Action not supported'}
    except Exception as exp:
        logger.exception('MobSF Global Proxy')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)
