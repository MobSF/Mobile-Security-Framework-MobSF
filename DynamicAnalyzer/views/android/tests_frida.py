# -*- coding: utf_8 -*-
"""Frida tests."""
import base64
import os
import re
import glob
import json
import sys
import time
from pathlib import Path
import logging

import frida

from django.shortcuts import render
from django.conf import settings
from django.views.decorators.http import require_http_methods

from DynamicAnalyzer.views.android.environment import Environment
from DynamicAnalyzer.views.android.operations import (
    invalid_params,
    is_attack_pattern,
    is_md5,
    json_response)

from MobSF.utils import (get_device,
                         is_file_exists,
                         print_n_send_error_response)

logger = logging.getLogger(__name__)


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
        if (is_attack_pattern(default_hooks)
                or is_attack_pattern(package) or not is_md5(md5_hash)):
            return invalid_params()
        frida = Frida(md5_hash, package, default_hooks.split(','))
        frida.connect()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Instrumentation failed')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)


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


def apimon_analysis(app_dir, package):
    """API Analysis."""
    logger.info('API Monitor Analysis')
    api_details = {}
    try:
        location = os.path.join(app_dir, 'mobsf_api_monitor.txt')
        if not is_file_exists(location):
            return {}
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


class Frida:

    def __init__(self, app_hash, package, defaults):
        self.hash = app_hash
        self.package = package
        self.defaults = defaults
        self.frida_dir = os.path.join(settings.TOOLS_DIR,
                                      'frida_scripts')
        self.apk_dir = os.path.join(settings.UPLD_DIR, self.hash + '/')

    def get_default_scripts(self):
        """Get default Frida Scripts."""
        combined_script = []
        header = []
        def_scripts = os.path.join(self.frida_dir, 'default')
        files = [f for f in glob.glob(
            def_scripts + '**/*.js', recursive=True)]
        for item in files:
            script = Path(item)
            if script.stem in self.defaults:
                header.append('send("Loaded Frida Script - {}");'.format(
                    script.stem))
                combined_script.append(script.read_text())
        return '\n'.join(header) + '\n'.join(combined_script)

    def get_script(self):
        """Get final script."""
        return self.get_default_scripts()

    def frida_response(self, message, data):
        """Function to handle frida responses."""
        if 'payload' in message:
            msg = message['payload']
            api_mon = 'MobSF-API-Monitor: '
            api_mon_log = os.path.join(self.apk_dir, 'mobsf_api_monitor.txt')
            if msg.startswith(api_mon):
                with open(api_mon_log, 'a') as flip:
                    flip.write(msg.replace(api_mon, ''))
            else:
                logger.debug('[Frida] %s', message['payload'])
        else:
            logger.error('[Frida] %s', message)

    def connect(self):
        """Connect to Frida Server."""
        session = None
        try:
            env = Environment()
            self.clean_up()
            env.run_frida_server()
            device = frida.get_device(get_device(), settings.FRIDA_TIMEOUT)
            logger.info('Spawning %s', self.package)
            pid = device.spawn([self.package])
            device.resume(pid)
            time.sleep(1)
            session = device.attach(pid)
        except frida.ServerNotRunningError:
            logger.warning('Frida server is not running')
            self.connect()
        except frida.TimedOutError:
            logger.error('Timed out while waiting for device to appear')
        except Exception:
            logger.exception('Error Connecting to Frida')
        try:
            if session:
                script = session.create_script(self.get_script())
                script.on('message', self.frida_response)
                script.load()
                sys.stdin.read()
                script.unload()
                session.detach()
        except Exception:
            logger.exception('Error Connecting to Frida')

    def clean_up(self):
        apimon_file = os.path.join(self.apk_dir, 'mobsf_api_monitor.txt')
        if is_file_exists(apimon_file):
            os.remove(apimon_file)
