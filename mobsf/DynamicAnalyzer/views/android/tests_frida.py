# -*- coding: utf_8 -*-
"""Frida tests."""
from pathlib import Path
import logging

from django.shortcuts import render
from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.android.api_monitor import (
    capture_id,
    group_api_calls,
    read_api_monitor,
)
from mobsf.DynamicAnalyzer.views.android.frida_core import Frida
from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    send_response,
)
from mobsf.MobSF.security import is_attack_pattern
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.MobSF.utils import (
    get_device,
    is_gadget_analysis,
    is_md5,
    print_n_send_error_response,
    read_analysis_state,
    strict_package_check,
    valid_android_device_identifier,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)
API_MONITOR_FILE = 'mobsf_api_monitor.txt'


def _analysis_identifier(request, checksum):
    """Return the device bound to this dynamic-analysis session."""
    identifier = read_analysis_state(checksum).get('identifier')
    if valid_android_device_identifier(identifier):
        return identifier
    return get_device(request)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def get_runtime_dependencies(request, api=False):
    """Get App runtime dependencies."""
    data = {
        'status': 'failed',
        'message': 'Failed to get runtime dependencies'}
    try:
        checksum = request.POST['hash']
        if not is_md5(checksum):
            return invalid_params(api)
        identifier = _analysis_identifier(request, checksum)
        package = get_package_name(checksum, identifier)
        if not package:
            return invalid_params(api)
        success, error = get_dependencies(package, checksum, identifier)
        if not success:
            return send_response({
                'status': 'failed',
                'message': error or 'Unable to connect to Frida',
            }, api)
        return send_response(
            {'status': 'ok'},
            api)
    except Exception:
        pass
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def instrument(request, api=False):
    """Instrument app with frida."""
    data = {
        'status': 'failed',
        'message': ''}
    try:
        action = request.POST.get('frida_action', 'spawn')
        pid = request.POST.get('pid')
        new_pkg = request.POST.get('new_package')
        md5_hash = request.POST['hash']
        default_hooks = request.POST['default_hooks']
        auxiliary_hooks = request.POST['auxiliary_hooks']
        code = request.POST['frida_code']
        # Fill extras
        extras = {}
        class_name = request.POST.get('class_name')
        if class_name:
            extras['class_name'] = class_name.strip()
        class_search = request.POST.get('class_search')
        if class_search:
            extras['class_search'] = class_search.strip()
        cls_trace = request.POST.get('class_trace')
        if cls_trace:
            extras['class_trace'] = cls_trace.strip()

        if (is_attack_pattern(default_hooks)
                or is_attack_pattern(auxiliary_hooks)
                or not is_md5(md5_hash)
                or action not in ('spawn', 'session', 'ps', 'get')
                or (pid and action != 'session')
                or (pid and (not pid.isdigit() or not new_pkg))
                or (new_pkg and not strict_package_check(new_pkg))):
            return invalid_params(api)
        identifier = _analysis_identifier(request, md5_hash)
        package = get_package_name(md5_hash, identifier)
        if not package and not new_pkg:
            return invalid_params(api)
        frida_obj = Frida(md5_hash,
                          package,
                          default_hooks.split(','),
                          auxiliary_hooks.split(','),
                          extras,
                          code,
                          identifier)
        gadget_mode = is_gadget_analysis(md5_hash)
        if gadget_mode and (action == 'ps' or pid):
            return send_response({
                'status': 'failed',
                'message': (
                    'Process enumeration and PID attachment are unavailable '
                    'in Frida Gadget mode'
                ),
            }, api)
        if action == 'spawn':
            logger.info('Starting Instrumentation')
            if not frida_obj.instrument():
                return send_response({
                    'status': 'failed',
                    'message': (
                        frida_obj.last_error
                        or 'Unable to launch and instrument the app'
                    ),
                }, api)
        elif action == 'ps':
            logger.info('Enumerating running applications')
            data['message'] = frida_obj.ps()
        elif action == 'get':
            # Get injected Frida script.
            data['message'] = frida_obj.get_script(nolog=True)
        if action in ('spawn', 'session'):
            if pid and pid.isdigit():
                # Attach to a different pid/bundle id
                logger.info('Attaching to %s [PID: %s]', new_pkg, pid)
                if not frida_obj.instrument(int(pid), new_pkg):
                    return send_response({
                        'status': 'failed',
                        'message': (
                            frida_obj.last_error
                            or 'Unable to attach and inject Frida'
                        ),
                    }, api)
            else:
                if action == 'session':
                    logger.info('Injecting to existing frida session')
                    if not frida_obj.reuse_session():
                        return send_response({
                            'status': 'failed',
                            'message': (
                                frida_obj.last_error
                                or 'No reusable Frida session is active'
                            ),
                        }, api)
                    data['status'] = 'ok'
                    return send_response(data, api)
        data['status'] = 'ok'
    except Exception as exp:
        logger.exception('Instrumentation failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)


def _parse_offset(value):
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['GET', 'POST'])
def live_api(request, api=False):
    """Render the live API monitor or return captured API calls."""
    try:
        if request.method == 'GET':
            apphash = request.GET.get('hash', '')
            package = request.GET.get('package', '')
            if not is_md5(apphash) or not strict_package_check(package):
                return invalid_params(api)
            logger.info('Starting API monitor streaming')
            template = 'dynamic_analysis/android/live_api.html'
            return render(request,
                          template,
                          {'hash': apphash,
                           'package': package,
                           'version': settings.MOBSF_VER,
                           'title': 'Live API Monitor'})
        apphash = request.POST.get('hash', '')
        if not is_md5(apphash):
            return invalid_params(api)
        apimon_file = Path(settings.UPLD_DIR) / apphash / API_MONITOR_FILE
        if not apimon_file.is_file():
            return send_response({
                'status': 'failed',
                'message': 'Data does not exist.'}, api)
        capture = capture_id(apimon_file)
        entries = read_api_monitor(apimon_file)
        if api:
            return send_response({'data': entries}, api)
        offset = _parse_offset(request.POST.get('offset'))
        # Restarted instrumentation starts a new log; resend from start.
        reset = (offset > len(entries)
                 or (offset > 0
                     and request.POST.get('capture', '') != capture))
        if reset:
            offset = 0
        return send_response({
            'data': entries[offset:],
            'offset': offset,
            'total': len(entries),
            'capture': capture,
            'reset': reset}, api)
    except Exception:
        logger.exception('API monitor streaming')
        err = 'Error in API monitor streaming'
        return print_n_send_error_response(request, err, api)


def apimon_analysis(app_dir):
    """API Analysis."""
    api_details, strings = {}, []
    try:
        location = Path(app_dir) / API_MONITOR_FILE
        if not location.is_file():
            return api_details, strings
        logger.info('Frida API Monitor Analysis')
        api_details, strings = group_api_calls(read_api_monitor(location))
    except Exception:
        logger.exception('API Monitor Analysis')
    return api_details, strings


def get_dependencies(package, checksum, identifier=None):
    """Get 3rd party dependencies at runtime."""
    frd = Frida(
        checksum,
        package,
        ['ssl_pinning_bypass', 'debugger_check_bypass', 'root_bypass'],
        ['get_dependencies'],
        None,
        None,
        identifier,
    )
    location = Path(frd.deps)
    if location.exists():
        location.write_text('')
    if frd.reuse_session(replace=False):
        return True, ''
    if frd.last_error:
        return False, frd.last_error
    if frd.instrument(completion_timeout=30):
        return True, ''
    return False, frd.last_error


def dependency_analysis(package, app_dir):
    deps = set()
    msg = 'Collecting Runtime Dependency Analysis data'
    try:
        ignore = (
            package,
            'android.', 'androidx.', 'kotlin.', 'kotlinx.', 'java.', 'javax.',
            'sun.', 'com.android.', 'j$', 'dalvik.system.', 'libcore.',
            'com.google.', 'org.kxml2.', 'org.apache.', 'org.json.')
        location = Path(app_dir) / 'mobsf_app_deps.txt'
        if not location.exists():
            return deps
        logger.info(msg)
        data = location.read_text('utf-8', 'ignore').splitlines()
        for dep in data:
            if not dep.startswith(ignore):
                deps.add(dep.rsplit('.', 1)[0])
    except Exception:
        logger.exception(msg)
    return deps
