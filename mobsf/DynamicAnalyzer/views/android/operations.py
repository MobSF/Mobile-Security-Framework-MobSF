# -*- coding: utf_8 -*-
"""Dynamic Analyzer Operations."""
import json
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
    is_attack_pattern,
    send_response,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.MobSF.utils import (
    cmd_injection_check,
    docker_translate_localhost,
    get_adb,
    get_device,
    is_md5,
    is_number,
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

def get_package_name(checksum):
    """Get Package Name from DB or Device."""
    try:
        static_android_db = StaticAnalyzerAndroid.objects.get(
            MD5=checksum)
        return static_android_db.PACKAGE_NAME
    except Exception:
        pkg_file = Path(settings.DWD_DIR) / 'packages.json'
        if not pkg_file.exists():
            return None
        with pkg_file.open(encoding='utf-8') as src:
            packages = json.load(src)
        if packages.get(checksum):
            return packages[checksum][0]
        return None
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def mobsfy(request, api=False):
    """Configure Instance for Dynamic Analysis."""
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
            return send_response(data, api)
        identifier = docker_translate_localhost(identifier)
        create_env = Environment(identifier)
        if not create_env.connect_n_mount():
            data = {'status': 'failed', 'message': msg}
            return send_response(data, api)
        version = create_env.mobsfy_init()
        if not version:
            data = {'status': 'failed', 'message': msg}
            return send_response(data, api)
        else:
            data = {'status': 'ok', 'android_version': version}
    except Exception as exp:
        logger.exception('MobSFying Android instance failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def execute_adb(request, api=False):
    """Execute ADB Commands."""
    data = {'status': 'ok', 'message': ''}
    cmd = request.POST['cmd']
    if cmd:
        args = [get_adb(),
                '-s',
                get_device()]
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
        env = Environment()
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
        env = Environment()
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params()
        pkg = get_package_name(md5_hash)
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
        env = Environment()
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
        env.screen_shot(outile)
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
        env = Environment()
        b64dat = env.screen_stream()
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
        env = Environment()
        x = request.POST['x']
        y = request.POST['y']
        event = request.POST['event']
        max_x = request.POST.get('max_x', 0)
        max_y = request.POST.get('max_y', 0)

        if event == 'text':
            args = ['text', shlex.quote(x)]
        else:
            if (not is_number(x)
                    or not is_number(y)
                    or not is_number(max_x)
                    or not is_number(max_y)):
                return data
            # Should not be greater than max screen size
            swipe_x = str(min(int(float(x)) + 500, int(float(max_x))))
            swipe_y = str(min(int(float(y)) + 500, int(float(max_y))))

            if event == 'enter':
                args = ['keyevent', '66']
            elif event == 'backspace':
                args = ['keyevent', '67']
            elif event == 'left':
                args = ['keyevent', '21']
            elif event == 'right':
                args = ['keyevent', '22']
            elif event == 'swipe_up':
                args = ['swipe', x, y, x, swipe_y]
            elif event == 'swipe_down':
                args = ['swipe', x, swipe_y, x, y]
            elif event == 'swipe_left':
                args = ['swipe', x, y, swipe_x, y]
            elif event == 'swipe_right':
                args = ['swipe', swipe_x, y, x, y]
            else:
                args = ['tap', x, y]
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
        env = Environment()
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
        env = Environment()
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
