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

from mobsf.DynamicAnalyzer.views.android.frida_core import Frida
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    is_md5,
    is_safe_path,
    print_n_send_error_response,
)

logger = logging.getLogger(__name__)

# AJAX


@require_http_methods(['GET'])
def list_frida_scripts(request, api=False):
    """Get frida scripts from others."""
    scripts = []
    others = os.path.join(settings.TOOLS_DIR,
                          'frida_scripts',
                          'others')
    files = glob.glob(others + '**/*.js', recursive=True)
    for item in files:
        scripts.append(Path(item).stem)
    return send_response({'status': 'ok',
                          'files': scripts},
                         api)
# AJAX


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
        package = get_package_name(checksum)
        if not package:
            return invalid_params(api)
        get_dependencies(package, checksum)
        return send_response(
            {'status': 'ok'},
            api)
    except Exception:
        pass
    return send_response(data, api)
# AJAX


@require_http_methods(['POST'])
def get_script(request, api=False):
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
def instrument(request, api=False):
    """Instrument app with frida."""
    data = {}
    try:
        logger.info('Starting Instrumentation')
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
                or not is_md5(md5_hash)):
            return invalid_params(api)
        package = get_package_name(md5_hash)
        if not package:
            return invalid_params(api)
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
    return send_response(data, api)


def live_api(request, api=False):
    try:
        if api:
            apphash = request.POST['hash']
            stream = True
        else:
            apphash = request.GET.get('hash', '')
            stream = request.GET.get('stream', '')
        if not is_md5(apphash):
            return invalid_params(api)
        if stream:
            apk_dir = os.path.join(settings.UPLD_DIR, apphash + '/')
            apimon_file = os.path.join(apk_dir, 'mobsf_api_monitor.txt')
            data = {}
            if not is_file_exists(apimon_file):
                data = {
                    'status': 'failed',
                    'message': 'Data does not exist.'}
                return send_response(data, api)
            with open(apimon_file, 'r',
                      encoding='utf8',
                      errors='ignore') as flip:
                api_list = json.loads('[{}]'.format(
                    flip.read()[:-1]))
            data = {'data': api_list}
            return send_response(data, api)
        logger.info('Starting API monitor streaming')
        template = 'dynamic_analysis/android/live_api.html'
        return render(request,
                      template,
                      {'hash': apphash,
                       'package': request.GET.get('package', ''),
                       'version': settings.MOBSF_VER,
                       'title': 'Live API Monitor'})
    except Exception:
        logger.exception('API monitor streaming')
        err = 'Error in API monitor streaming'
        return print_n_send_error_response(request, err, api)


def frida_logs(request, api=False):
    try:
        if api:
            apphash = request.POST['hash']
            stream = True
        else:
            apphash = request.GET.get('hash', '')
            stream = request.GET.get('stream', '')
        if not is_md5(apphash):
            return invalid_params(api)
        if stream:
            apk_dir = os.path.join(settings.UPLD_DIR, apphash + '/')
            frida_logs = os.path.join(apk_dir, 'mobsf_frida_out.txt')
            data = {}
            if not is_file_exists(frida_logs):
                data = {
                    'status': 'failed',
                    'message': 'Data does not exist.'}
                return send_response(data, api)
            with open(frida_logs, 'r',
                      encoding='utf8',
                      errors='ignore') as flip:
                data = {'data': flip.read()}
            return send_response(data, api)
        logger.info('Frida Logs live streaming')
        template = 'dynamic_analysis/android/frida_logs.html'
        return render(request,
                      template,
                      {'hash': apphash,
                       'package': request.GET.get('package', ''),
                       'version': settings.MOBSF_VER,
                       'title': 'Live Frida logs'})
    except Exception:
        logger.exception('Frida log streaming')
        err = 'Error in Frida log streaming'
        return print_n_send_error_response(request, err, api)


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


def get_icon_map(name):
    """Get icon mapping."""
    mapping = {
        'Process': 'fas fa-chart-bar',
        'Command': 'fas fa-terminal',
        'Java Native Interface': 'fab fa-cuttlefish',
        'WebView': 'far fa-window-maximize',
        'File IO': 'fas fa-file-signature',
        'Database': 'fas fa-database',
        'IPC': 'fas fa-broadcast-tower',
        'Binder': 'fas fa-cubes',
        'Crypto': 'fas fa-lock',
        'Crypto - Hash': 'fas fa-hashtag',
        'Device Info': 'fas fa-info',
        'Network': 'fas fa-wifi',
        'Dex Class Loader': 'fas fa-asterisk',
        'Base64': 'fas fa-puzzle-piece',
        'System Manager': 'fas fa-cogs',
        'SMS': 'fas fa-comment-alt',
        'Device Data': 'fas fa-phone',
    }
    if name in mapping:
        return mapping[name]
    return 'far fa-dot-circle'


def apimon_analysis(app_dir):
    """API Analysis."""
    api_details = {}
    try:
        strings = []
        location = os.path.join(app_dir, 'mobsf_api_monitor.txt')
        if not is_file_exists(location):
            return api_details, strings
        logger.info('Frida API Monitor Analysis')
        with open(location, 'r',
                  encoding='utf8',
                  errors='ignore') as flip:
            apis = json.loads('[{}]'.format(
                flip.read()[:-1]))
        for api in apis:
            to_decode = None
            if (api['class'] == 'android.util.Base64'
                    and (api['method'] == 'encodeToString')):
                if api.get('returnValue'):
                    to_decode = api['returnValue'].replace('"', '')
            elif (api['class'] == 'android.util.Base64'
                  and api['method'] == 'decode'):
                to_decode = api['arguments'][0]
            try:
                if to_decode:
                    api['decoded'] = decode_base64(
                        to_decode).decode('utf-8', 'ignore')
                    strings.append((api['calledFrom'], api['decoded']))
            except Exception:
                pass
            api['icon'] = get_icon_map(api['name'])
            if api['name'] in api_details:
                api_details[api['name']].append(api)
            else:
                api_details[api['name']] = [api]
    except Exception:
        logger.exception('API Monitor Analysis')
    return api_details, strings


def get_dependencies(package, checksum):
    """Get 3rd party dependencies at runtime."""
    frd = Frida(
        checksum,
        package,
        ['ssl_pinning_bypass', 'debugger_check_bypass', 'root_bypass'],
        ['get_dependencies'],
        None,
        None,
    )
    location = Path(frd.deps)
    if location.exists():
        location.write_text('')
    trd = threading.Thread(target=frd.connect)
    trd.daemon = True
    trd.start()


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
