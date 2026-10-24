# -*- coding: utf_8 -*-
"""Dynamic Analyzer Operations."""
from contextlib import contextmanager
from functools import wraps
import json
import hashlib
import logging
import os
import random
import re
import shlex
import tempfile
import threading
import time
from pathlib import Path

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.MobSF.security import (
    cmd_injection_check,
    is_attack_pattern,
    is_path_traversal,
)
from mobsf.MobSF.utils import (
    docker_translate_localhost,
    is_md5,
    is_number,
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
_ANDROID_ANALYSIS_LIFECYCLE_LOCK = threading.Lock()


# Helpers

def _device_packages_file(identifier):
    """Return a device-scoped package inventory path."""
    if not identifier:
        return None
    digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    return Path(settings.DWD_DIR) / f'packages-{digest}.json'


def android_analysis_state_file(checksum):
    """Return trusted state for one Android analysis."""
    if not is_md5(checksum):
        return None
    return (
        Path(settings.DWD_DIR)
        / f'android-analysis-state-{checksum}.json'
    )


def write_android_analysis_state(checksum, state):
    """Atomically publish trusted Android analysis state."""
    state_file = android_analysis_state_file(checksum)
    if state_file is None or not isinstance(state, dict):
        raise ValueError('Invalid Android analysis state')
    state_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                dir=state_file.parent,
                prefix=f'.{state_file.name}.',
                delete=False) as target:
            temporary = Path(target.name)
            json.dump(state, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, state_file)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def android_gadget_marker_file(checksum):
    """Return the trusted Gadget-mode marker for one analysis."""
    if not is_md5(checksum):
        return None
    return Path(settings.DWD_DIR) / f'android-gadget-{checksum}.state'


def android_frida_owner_file(checksum):
    """Return the trusted Frida worker owner file for one analysis."""
    if not is_md5(checksum):
        return None
    return (
        Path(settings.DWD_DIR)
        / f'android-frida-owner-{checksum}.state'
    )


def _analysis_claim_file(identifier):
    """Return the ownership record for one Android device."""
    if not valid_android_device_identifier(identifier):
        return None
    digest = hashlib.sha256(identifier.encode('utf-8')).hexdigest()
    return (
        Path(settings.DWD_DIR)
        / f'android-device-claim-{digest}.json'
    )


def _capture_claim_file():
    """Return the singleton HTTP capture ownership record."""
    return Path(settings.DWD_DIR) / 'android-capture-owner.json'


@contextmanager
def android_analysis_lifecycle(timeout=300):
    """Serialize Android setup and teardown across MobSF workers."""
    lock_file = Path(settings.DWD_DIR) / 'android-analysis-lifecycle.lock'
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    if not _ANDROID_ANALYSIS_LIFECYCLE_LOCK.acquire(timeout=timeout):
        raise TimeoutError(
            'Another Android analysis operation is still running',
        )
    descriptor = None
    locked = False
    try:
        descriptor = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b'\0')
        while not locked:
            try:
                if os.name == 'nt':
                    import msvcrt
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(
                        descriptor,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                locked = True
            except OSError as exp:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        'Another Android analysis operation is still running',
                    ) from exp
                time.sleep(0.1)
        yield
    finally:
        try:
            if locked:
                if os.name == 'nt':
                    import msvcrt
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            _ANDROID_ANALYSIS_LIFECYCLE_LOCK.release()


def android_analysis_operation(view):
    """Serialize one authenticated Android analysis endpoint."""
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        api = kwargs.get(
            'api',
            args[0] if args and isinstance(args[0], bool) else False,
        )
        try:
            with android_analysis_lifecycle():
                return view(request, *args, **kwargs)
        except TimeoutError as exp:
            return send_response({
                'status': 'failed',
                'message': str(exp),
            }, api)
    return wrapped


def _read_analysis_claim(claim_file):
    """Read one validated local analysis claim."""
    if not claim_file.is_file() or claim_file.is_symlink():
        return None
    try:
        claim = json.loads(claim_file.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(claim, dict):
        return None
    identifier = claim.get('identifier')
    checksum = claim.get('checksum')
    if (not valid_android_device_identifier(identifier)
            or not is_md5(checksum)):
        return None
    return claim


def _read_android_analysis_state(checksum):
    """Read validated trusted state for one Android analysis."""
    state_file = android_analysis_state_file(checksum)
    if (state_file is None
            or not state_file.is_file()
            or state_file.is_symlink()):
        return None
    try:
        state = json.loads(state_file.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError):
        return None
    if (not isinstance(state, dict)
            or state.get('checksum') != checksum
            or not valid_android_device_identifier(
                state.get('identifier'))):
        return None
    return state


def valid_android_analysis_id(analysis_id):
    """Validate an opaque Android analysis generation identifier."""
    return bool(
        isinstance(analysis_id, str)
        and re.fullmatch(r'[0-9a-f]{32}', analysis_id),
    )


def get_requested_android_analysis(request, checksum):
    """Resolve an exact analysis generation submitted by the client."""
    if not is_md5(checksum):
        return None, None
    state = _read_android_analysis_state(checksum)
    if not state:
        return None, None
    identifier = request.POST.get('identifier')
    analysis_id = request.POST.get('analysis_id')
    if (not valid_android_device_identifier(identifier)
            or not valid_android_analysis_id(analysis_id)
            or state.get('identifier') != identifier
            or state.get('analysis_id') != analysis_id):
        return None, None
    return identifier, analysis_id


def get_android_analysis_claim(identifier):
    """Return the checksum currently owning a device."""
    claim_file = _analysis_claim_file(identifier)
    if claim_file is None:
        return None
    claim = _read_analysis_claim(claim_file)
    return claim.get('checksum') if claim else None


def get_android_capture_claim():
    """Return the active Android HTTP capture owner."""
    claim = _read_analysis_claim(_capture_claim_file())
    if not claim:
        return None
    return claim.get('identifier'), claim.get('checksum')


def android_analysis_is_active(identifier, checksum, analysis_id):
    """Check exact device, capture, and initialized analysis ownership."""
    if (not valid_android_device_identifier(identifier)
            or not is_md5(checksum)
            or not valid_android_analysis_id(analysis_id)
            or get_android_analysis_claim(identifier) != checksum
            or get_android_capture_claim() != (identifier, checksum)):
        return False
    state = _read_android_analysis_state(checksum)
    return bool(
        state
        and state.get('identifier') == identifier
        and state.get('checksum') == checksum
        and state.get('analysis_id') == analysis_id
        and state.get('analysis_ready') is True
        and state.get('finalizing') is not True
        and state.get('cleanup_complete') is not True,
    )


def get_android_frida_target(identifier, checksum):
    """Return the validated package currently targeted by Frida."""
    state = _read_android_analysis_state(checksum)
    if not state or state.get('identifier') != identifier:
        return None
    package = state.get('frida_target_package')
    if (isinstance(package, str)
            and strict_package_check(package)
            and not is_path_traversal(package)):
        return package
    return None


def set_android_frida_target(identifier, checksum, package):
    """Persist the package needed for cross-worker Frida teardown."""
    if (not isinstance(package, str)
            or not strict_package_check(package)
            or is_path_traversal(package)):
        return False
    state = _read_android_analysis_state(checksum)
    if (not state
            or state.get('identifier') != identifier
            or state.get('analysis_ready') is not True
            or state.get('finalizing') is True
            or state.get('cleanup_complete') is True):
        return False
    state['frida_target_package'] = package
    write_android_analysis_state(checksum, state)
    return True


def _active_analysis_environment(request):
    """Return the environment for the exact active client generation."""
    checksum = request.POST.get('hash')
    identifier, analysis_id = get_requested_android_analysis(
        request, checksum)
    if not android_analysis_is_active(
            identifier, checksum, analysis_id):
        return None
    return Environment(identifier)


def claim_android_analysis(identifier, checksum):
    """Atomically claim shared capture and one Android device."""
    claim_file = _analysis_claim_file(identifier)
    if claim_file is None or not is_md5(checksum):
        return False
    claim_file.parent.mkdir(parents=True, exist_ok=True)
    capture_file = _capture_claim_file()
    capture = _read_analysis_claim(capture_file)
    if (capture_file.exists() or capture_file.is_symlink()) and not capture:
        capture_file.unlink(missing_ok=True)
    elif capture:
        capture_claim_file = _analysis_claim_file(
            capture.get('identifier'))
        paired_claim = (
            _read_analysis_claim(capture_claim_file)
            if capture_claim_file else None
        )
        if (not paired_claim
                or paired_claim.get('checksum')
                != capture.get('checksum')):
            capture_file.unlink(missing_ok=True)
            capture = None
        else:
            paired_state = _read_android_analysis_state(
                capture.get('checksum'))
            if (not paired_state
                    or paired_state.get('identifier')
                    != capture.get('identifier')):
                capture_claim_file.unlink(missing_ok=True)
                capture_file.unlink(missing_ok=True)
                capture = None
    device_claim = _read_analysis_claim(claim_file)
    if (claim_file.exists() or claim_file.is_symlink()) and not device_claim:
        claim_file.unlink(missing_ok=True)
    capture_created = False
    try:
        descriptor = os.open(
            capture_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        capture = _read_analysis_claim(capture_file)
        if (not capture
                or capture.get('identifier') != identifier
                or capture.get('checksum') != checksum):
            return False
    else:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
            json.dump({
                'identifier': identifier,
                'checksum': checksum,
            }, target)
        capture_created = True
    try:
        descriptor = os.open(
            claim_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        claim = _read_analysis_claim(claim_file)
        claimed = bool(
            claim
            and claim.get('identifier') == identifier
            and claim.get('checksum') == checksum,
        )
        if capture_created and not claimed:
            capture_file.unlink(missing_ok=True)
        return claimed
    with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
        json.dump({
            'identifier': identifier,
            'checksum': checksum,
        }, target)
    return True


def release_android_analysis(identifier, checksum=None):
    """Release MobSF-owned device and shared capture claims."""
    claim_file = _analysis_claim_file(identifier)
    if claim_file is None:
        return
    claim = _read_analysis_claim(claim_file)
    if not claim:
        claim_file.unlink(missing_ok=True)
        capture_file = _capture_claim_file()
        capture = _read_analysis_claim(capture_file)
        if (not capture
                or (capture.get('identifier') == identifier
                    and (checksum is None
                         or capture.get('checksum') == checksum))):
            capture_file.unlink(missing_ok=True)
        return
    owner_checksum = claim.get('checksum')
    if checksum is not None and owner_checksum != checksum:
        return
    claim_file.unlink(missing_ok=True)
    for other_file in Path(settings.DWD_DIR).glob(
            'android-device-claim-*.json'):
        other = _read_analysis_claim(other_file)
        if other and other.get('checksum') == owner_checksum:
            return
    capture_file = _capture_claim_file()
    capture = _read_analysis_claim(capture_file)
    if (not capture
            or capture.get('checksum') == owner_checksum):
        capture_file.unlink(missing_ok=True)


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
@android_analysis_operation
def execute_adb(request, api=False):
    """Execute ADB Commands."""
    data = {'status': 'ok', 'message': ''}
    cmd = request.POST['cmd']
    if cmd:
        env = _active_analysis_environment(request)
        if env is None:
            return send_response({
                'status': 'failed',
                'message': 'Android analysis is no longer active',
            }, api)
        output = env.adb_command(
            cmd.split(' '),  # lgtm [py/command-line-injection]
            silent=True,
            timeout=120,
        )
        if output is None:
            return send_response({
                'status': 'failed',
                'message': 'ADB command failed or timed out',
            }, api)
        out = output.decode('utf8', 'ignore')
        data = {'status': 'ok', 'message': out}
    return send_response(data, api)

# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
@android_analysis_operation
def get_component(request):
    """Get Android Component."""
    data = {}
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return invalid_params()
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
@android_analysis_operation
def run_apk(request):
    """Run Android APK."""
    data = {}
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return invalid_params()
        md5_hash = request.POST['hash']
        if not is_md5(md5_hash):
            return invalid_params()
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
@android_analysis_operation
def take_screenshot(request, api=False):
    """Take Screenshot."""
    logger.info('Taking screenshot')
    data = {}
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return invalid_params(api)
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
@android_analysis_operation
def screen_cast(request):
    """ScreenCast."""
    data = {
        'status': 'failed',
        'message': 'Failed to stream screen'}
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return send_response(data)
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
@android_analysis_operation
def touch(request):
    """Sending Touch/Swipe/Text Events."""
    data = {
        'status': 'failed',
        'message': '',
    }
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return send_response(data)
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
                return data
        if env.adb_command(['input'] + args, True) is None:
            data['message'] = 'Failed to send input event'
            return send_response(data)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Sending Touchscreen Events')
        data['message'] = str(exp)
    return send_response(data)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
@android_analysis_operation
def mobsf_ca(request, api=False):
    """Install and Remove MobSF Proxy RootCA."""
    data = {}
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return invalid_params(api)
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
@android_analysis_operation
def global_proxy(request, api=False):
    """Set/unset global proxy."""
    data = {}
    try:
        env = _active_analysis_environment(request)
        if env is None:
            return invalid_params(api)
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
