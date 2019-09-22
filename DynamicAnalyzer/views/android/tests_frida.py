# -*- coding: utf_8 -*-
"""Frida tests."""
import base64
import glob
import os
import re
import json
from pathlib import Path
import threading
import logging

from django.shortcuts import render
from django.conf import settings
from django.views.decorators.http import require_http_methods

from DynamicAnalyzer.views.android.frida_core import Frida
from DynamicAnalyzer.views.android.operations import (
    invalid_params,
    is_attack_pattern,
    is_md5,
    json_response,
    strict_package_check)

from MobSF.utils import (
    is_file_exists,
    is_safe_path,
    print_n_send_error_response)

logger = logging.getLogger(__name__)

# AJAX


@require_http_methods(['GET'])
def list_frida_scripts(request):
    """Get frida scripts from others."""
    scripts = []
    others = os.path.join(settings.TOOLS_DIR,
                          'frida_scripts',
                          'others')
    files = [f for f in glob.glob(
        others + '**/*.js', recursive=True)]
    for item in files:
        scripts.append(Path(item).stem)
    return json_response({'status': 'ok',
                          'files': scripts})
# AJAX


@require_http_methods(['POST'])
def get_script(request):
    """Get frida scripts from others."""
    data = {'status': 'ok', 'content': ''}
    try:
        scripts = request.POST.getlist('scripts[]')
        others = os.path.join(settings.TOOLS_DIR,
                              'frida_scripts',
                              'others')
        script_ct = []
        for script in scripts:
            script_file = os.path.join(others, script + '.js')
            if not is_safe_path(others, script_file):
                return json_response(data)
            if is_file_exists(script_file):
                script_ct.append(Path(script_file).read_text())
        data['content'] = '\n'.join(script_ct)
    except Exception:
        pass
    return json_response(data)
# AJAX


@require_http_methods(['POST'])
def instrument(request):
    """Instrument app with frida."""
    data = {}
    try:
        logger.info('Starting Instrumentation')
        package = request.POST['package']
        md5_hash = request.POST['hash']
        default_hooks = request.POST['default_hooks']
        auxiliary_hooks = request.POST['auxiliary_hooks']
        code = request.POST['frida_code']
        # Fill extras
        extras = {}
        class_name = request.POST.get('cls_name')
        if class_name:
            extras['cls_name'] = class_name.strip()
        class_search = request.POST.get('cls_search')
        if class_search:
            extras['cls_search'] = class_search.strip()
        cls_trace = request.POST.get('cls_trace')
        if cls_trace:
            extras['cls_trace'] = cls_trace.strip()
        if (is_attack_pattern(default_hooks)
                or not strict_package_check(package)
                or not is_md5(md5_hash)):
            return invalid_params()
        frida_obj = Frida(md5_hash,
                          package,
                          default_hooks.split(','),
                          auxiliary_hooks.split(','),
                          extras,
                          code)
        trd = threading.Thread(target=frida_obj.connect)
        trd.daemon = True
        trd.start()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Instrumentation failed')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)


def live_api(request):
    try:
        apphash = request.GET.get('hash', '')
        stream = request.GET.get('stream', '')
        if not is_md5(apphash):
            return invalid_params()
        if stream:
            apk_dir = os.path.join(settings.UPLD_DIR, apphash + '/')
            apimon_file = os.path.join(apk_dir, 'mobsf_api_monitor.txt')
            data = {}
            if is_file_exists(apimon_file):
                with open(apimon_file, 'r') as flip:
                    api_list = json.loads('[{}]'.format(
                        flip.read()[:-1]))
                data = {'data': api_list}
                return json_response(data)
        logger.info('Starting API monitor streaming')
        template = 'dynamic_analysis/android/live_api.html'
        return render(request,
                      template,
                      {'hash': apphash,
                       'package': request.GET.get('package', ''),
                       'title': 'Live API Monitor'})
    except Exception:
        logger.exception('API monitor streaming')
        err = 'Error in API monitor streaming'
        return print_n_send_error_response(request, err)


def frida_logs(request):
    try:
        apphash = request.GET.get('hash', '')
        stream = request.GET.get('stream', '')
        if not is_md5(apphash):
            return invalid_params()
        if stream:
            apk_dir = os.path.join(settings.UPLD_DIR, apphash + '/')
            frida_logs = os.path.join(apk_dir, 'mobsf_frida_out.txt')
            data = {}
            if is_file_exists(frida_logs):
                with open(frida_logs, 'r') as flip:
                    data = {'data': flip.read()}
                return json_response(data)
        logger.info('Frida Logs live streaming')
        template = 'dynamic_analysis/android/frida_logs.html'
        return render(request,
                      template,
                      {'hash': apphash,
                       'package': request.GET.get('package', ''),
                       'title': 'Live Frida logs'})
    except Exception:
        logger.exception('Frida log streaming')
        err = 'Error in Frida log streaming'
        return print_n_send_error_response(request, err)


def decode_base64(data, altchars=b'+/'):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.

    """
    data = re.sub(rb'[^a-zA-Z0-9%s]+' % altchars,
                  b'', data.encode())
    missing_padding = len(data) % 4
    if missing_padding:
        data += b'=' * (4 - missing_padding)
    return base64.b64decode(data, altchars)


def apimon_analysis(app_dir):
    """API Analysis."""
    api_details = {}
    try:
        location = os.path.join(app_dir, 'mobsf_api_monitor.txt')
        if not is_file_exists(location):
            return {}
        logger.info('Frida API Monitor Analysis')
        with open(location, 'r') as flip:
            apis = json.loads('[{}]'.format(
                flip.read()[:-1]))
        for api in apis:
            to_decode = None
            if (api['class'] == 'android.util.Base64'
                    and (api['method'] == 'encodeToString')):
                to_decode = api['returnValue'].replace('"', '')
            elif (api['class'] == 'android.util.Base64'
                  and api['method'] == 'decode'):
                to_decode = api['arguments'][0]
            try:
                if to_decode:
                    api['decoded'] = decode_base64(to_decode)
            except Exception:
                pass
            if api['name'] in api_details:
                api_details[api['name']].append(api)
            else:
                api_details[api['name']] = [api]
    except Exception:
        logger.exception('API Monitor Analysis')
    return api_details
