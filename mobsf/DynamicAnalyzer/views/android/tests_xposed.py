# -*- coding: utf_8 -*-
"""Xposed tests."""
import logging
import base64
import json
import os
import re

from mobsf.DynamicAnalyzer.views.android.environment import (
    Environment,
)
from mobsf.MobSF.utils import (
    is_base64,
    is_file_exists,
    python_list,
)

logger = logging.getLogger(__name__)


def get_hooked_apis():
    """Hooked APIs Regex."""
    apis = {
        'api_fileio': {
            'name': 'File IO',
            'regex': r'libcore.io|android.app.Shared'
                    r'PreferencesImpl\\$EditorImpl',
            'icon': 'fas fa-file-signature',
        },
        'api_reflect': {
            'name': 'Reflection',
            'regex': r'java.lang.reflect',
            'icon': 'fas fa-object-ungroup',
        },
        'api_sysprop': {
            'name': 'Device Data',
            'regex': r'android.content.ContentResolver|'
                     r'android.location.Location|'
                     r'android.media.AudioRecord|'
                     r'android.media.MediaRecorder|'
                     r'android.os.SystemProperties',
            'icon': 'fas fa-phone',
        },
        'api_binder': {
            'name': 'Binder',
            'regex': r'android.app.Activity|'
                     r'android.app.ContextImpl|'
                     r'android.app.ActivityThread',
            'icon': 'fas fa-cubes',
        },
        'api_crypto': {
            'name': 'Crypto',
            'regex': r'javax.crypto.spec.SecretKeySpec|'
                     r'javax.crypto.Cipher|'
                     r'javax.crypto.Mac',
            'icon': 'fas fa-lock',
        },
        'api_acntmnger': {
            'name': 'System Managers',
            'regex': r'android.accounts.AccountManager|'
                     r'android.app.ApplicationPackageManager|'
                     r'android.app.NotificationManager|'
                     r'android.net.ConnectivityManager|'
                     r'android.content.BroadcastReceiver',
            'icon': 'fas fa-cogs',
        },
        'api_deviceinfo': {
            'name': 'Device Info',
            'regex': r'android.telephony.TelephonyManager|'
                     r'android.net.wifi.WifiInfo|'
                     r'android.os.Debug',
            'icon': 'fas fa-info',
        },
        'api_dexloader': {
            'name': 'Dex Class Loader',
            'regex': r'dalvik.system.BaseDexClassLoader|'
                     r'dalvik.system.DexFile|'
                     r'dalvik.system.DexClassLoader|'
                     r'dalvik.system.PathClassLoader',
            'icon': 'fas fa-asterisk',
        },
        'api_cmd': {
            'name': 'Process',
            'regex': r'java.lang.Runtime|java.lang.ProcessBuilder|'
                     r'java.io.FileOutputStream|'
                     r'java.io.FileInputStream|'
                     r'android.os.Process',
            'icon': 'fas fa-chart-bar',
        },
        'api_cntvl': {
            'name': 'Content Values',
            'regex': r'android.content.ContentValues',
            'icon': 'fas fa-bars',
        },
        'api_sms': {
            'name': 'SMS Manager',
            'regex': r'android.telephony.SmsManager',
            'icon': 'fas fa-comment-alt',
        },
        'api_net': {
            'name': 'Network',
            'regex': r'java.net.URL|org.apache.http.'
                     r'impl.client.AbstractHttpClient',
            'icon': 'fas fa-wifi',
        },
        'api_base64': {
            'name': 'Base64',
            'regex': r'android.util.Base64',
            'icon': 'fas fa-puzzle-piece',
        },
    }
    return apis


def droidmon_api_analysis(app_dir, package):
    """API Analysis."""
    try:
        dat = ''
        hooked_apis = get_hooked_apis()
        api_details = {}
        hooks = []
        location = os.path.join(app_dir, 'x_logcat.txt')
        if not is_file_exists(location):
            return {}
        logger.info('Xposed Droidmon API Analysis')
        with open(location, 'r',
                  encoding='utf8',
                  errors='ignore') as flip:
            dat = flip.readlines()
        res_id = 'Droidmon-apimonitor-' + package + ':'
        for line in dat:
            if res_id not in line:
                continue
            _, value = line.split(res_id, 1)
            try:
                apis = json.loads(value, strict=False)
                call_data = {}
                call_data['class'] = apis['class']
                call_data['method'] = apis['method']
                if apis.get('return'):
                    call_data['return'] = apis['return']
                if apis.get('args'):
                    call_data['args'] = apis['args']
                for api, details in hooked_apis.items():
                    if re.findall(details['regex'], apis['class']):
                        call_data['api'] = api
                        # Decode Base64
                        if ('decode' in apis['method']
                                and api == 'api_base64'):
                            call_data['decoded'] = base64_decode(
                                call_data['args']).decode('utf-8', 'ignore')
                        hooks.append(call_data)
            except Exception:
                pass
        for hook in hooks:
            iden = hook['api']
            api_details[iden] = {
                'name': hooked_apis[iden]['name'],
                'icon': hooked_apis[iden]['icon'],
                'calls': [],
            }
        for hook in hooks:
            iden = hook['api']
            if hook not in api_details[iden]['calls']:
                api_details[iden]['calls'].append(hook)
    except Exception:
        logger.exception('Droidmon API Analysis')
    return api_details


def base64_decode(args):
    """Decode Base64 Automatically."""
    decoded = ''
    args_list = python_list(args)
    if not is_base64(args_list[0]):
        return decoded
    try:
        decoded = base64.b64decode(
            args_list[0]).decode('ISO-8859-1')
    except Exception:
        pass
    return decoded


def download_xposed_log(apk_dir):
    """Download Xposed Output."""
    env = Environment()
    xposed_out = ('/data/data/'
                  'de.robv.android.xposed.installer'
                  '/log/error.log')
    env.adb_command(['pull',
                     xposed_out,
                     apk_dir + 'x_logcat.txt'])
    logger.info('Downloading droidmon API monitor logs')
