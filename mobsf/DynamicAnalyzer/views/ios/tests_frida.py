# -*- coding: utf_8 -*-
"""Frida tests for iOS."""
import glob
import os
from pathlib import Path
from threading import Thread
import logging

from django.conf import settings
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.views.ios.frida_core import (
    Frida,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_apis import (
    CorelliumInstanceAPI,
    OK,
)
from mobsf.MobSF.utils import (
    common_check,
    is_file_exists,
    is_md5,
    is_safe_path,
    strict_package_check,
)

logger = logging.getLogger(__name__)
# AJAX


@require_http_methods(['GET'])
def list_ios_frida_scripts(request, api=False):
    """List frida scripts from others."""
    scripts = []
    others = os.path.join(settings.TOOLS_DIR,
                          'frida_scripts'
                          'ios',
                          'others')
    files = glob.glob(others + '**/*.js', recursive=True)
    for item in files:
        scripts.append(Path(item).stem)
    scripts.sort()
    return send_response(
        {'status': OK,
         'files': scripts},
        api)
# AJAX


@require_http_methods(['POST'])
def ios_get_script(request, api=False):
    """Get frida scripts from others."""
    data = {'status': OK, 'content': ''}
    try:
        scripts = request.POST.getlist('scripts[]')
        others = os.path.join(settings.TOOLS_DIR,
                              'frida_scripts'
                              'ios',
                              'others')
        script_ct = []
        for script in scripts:
            script_file = os.path.join(others, script + '.js')
            if not is_safe_path(others, script_file):
                data = {
                    'status': 'failed',
                    'message': 'Path traversal detected.'}
                return send_response(data, api)
            if is_file_exists(script_file):
                script_ct.append(Path(script_file).read_text())
        data['content'] = '\n'.join(script_ct)
    except Exception:
        pass
    return send_response(data, api)
# AJAX


@require_http_methods(['POST'])
def ios_instrument(request, api=False):
    """Instrument app with frida."""
    data = {
        'status': 'failed',
        'message': 'Failed to instrument app'}
    try:
        action = request.POST.get('frida_action', 'spawn')
        pid = request.POST.get('pid')
        new_bundle_id = request.POST.get('new_bundle_id')
        instance_id = request.POST['instance_id']
        bundle_id = request.POST['bundle_id']
        md5_hash = request.POST['hash']
        default_hooks = request.POST['default_hooks']
        dump_hooks = request.POST['dump_hooks']
        auxiliary_hooks = request.POST['auxiliary_hooks']
        code = request.POST['frida_code']

        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        if new_bundle_id and not strict_package_check(new_bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        ci = CorelliumInstanceAPI(instance_id)

        # Fill extras
        extras = {}
        class_name = request.POST.get('class_name')
        if class_name:
            extras['class_name'] = class_name.strip()
        class_search = request.POST.get('class_search')
        if class_search:
            extras['class_search'] = class_search.strip()
        method_search = request.POST.get('method_search')
        if method_search:
            extras['method_search'] = method_search.strip()
        cls_trace = request.POST.get('class_trace')
        if cls_trace:
            extras['class_trace'] = cls_trace.strip()
        if (is_attack_pattern(default_hooks)
                or is_attack_pattern(dump_hooks)
                or is_attack_pattern(auxiliary_hooks)
                or not is_md5(md5_hash)):
            return invalid_params(api)

        frida_obj = Frida(
            ci.get_ssh_connection_string(),
            md5_hash,
            bundle_id,
            default_hooks.split(','),
            dump_hooks.split(','),
            auxiliary_hooks.split(','),
            extras,
            code,
            action)
        if action == 'spawn':
            logger.info('Starting Instrumentation')
            frida_obj.spawn()
        elif action == 'ps':
            logger.info('Enumerating running applications')
            data['message'] = frida_obj.ps()
        if action in ('spawn', 'session'):
            if pid and pid.isdigit():
                # Attach to a different pid/bundle id
                args = (int(pid), new_bundle_id)
                logger.info('Attaching to %s [PID: %s]', new_bundle_id, pid)
            else:
                # Injecting to existing session/spawn
                if action == 'session':
                    logger.info('Injecting to existing frida session')
                args = (None, None)
            Thread(target=frida_obj.session, args=args, daemon=True).start()
        data['status'] = OK
    except Exception as exp:
        logger.exception('Frida Instrumentation failed')
        data = {'status': 'failed', 'message': str(exp)}
    return send_response(data, api)
