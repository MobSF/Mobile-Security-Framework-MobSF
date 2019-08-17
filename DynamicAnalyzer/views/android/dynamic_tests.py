# -*- coding: utf_8 -*-
"""Android Dynamic Tests."""
import threading
import json
import logging
import os
import random
import re
import subprocess

from django.conf import settings
from django.http import HttpResponse

from DynamicAnalyzer.tools.webproxy import (get_ca_dir, stop_capfuzz)
from DynamicAnalyzer.views.android.environment import Environment

from MobSF.utils import (get_adb, is_number,
                         print_n_send_error_response,
                         python_list)

from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)

env = Environment(settings.ANALYZER_IDENTIFIER)

# AJAX


def get_component(request):
    """Get Android Component."""
    data = {}
    try:
        if request.method == 'POST':
            comp = request.POST['component']
            bin_hash = request.POST['hash']
            if re.match('^[0-9a-f]{32}$', bin_hash):
                comp = env.android_component(bin_hash, comp)
                data = {'status': 'ok',
                        'resp': comp}
                return HttpResponse(json.dumps(data),
                                    content_type='application/json')
            else:
                return print_n_send_error_response(request,
                                                   'Invalid Scan Hash',
                                                   True)
        else:
            return print_n_send_error_response(request,
                                               'Only POST allowed',
                                               True)
    except Exception:
        logger.exception('Getting Android Component')
        return print_n_send_error_response(request,
                                           'Error Taking Screenshot',
                                           True)

# AJAX


def take_screenshot(request):
    """Take Screenshot."""
    logger.info('Taking Screenshot')
    try:
        if request.method == 'POST':
            md5_hash = request.POST['md5']
            if re.match('^[0-9a-f]{32}$', md5_hash):
                data = {}
                rand_int = random.randint(1, 1000000)
                # make sure that list only png from this directory
                screen_dir = os.path.join(
                    settings.UPLD_DIR, md5_hash + '/screenshots-apk/')
                if not os.path.exists(screen_dir):
                    os.makedirs(screen_dir)
                env.adb_command(['screencap',
                                 '-p',
                                 '/data/local/screen.png'], True)
                env.adb_command(['pull',
                                 '/data/local/screen.png',
                                 '{}screenshot-{}.png'.format(
                                     screen_dir,
                                     str(rand_int))])
                logger.info('Screenshot Taken')
                data = {'screenshot': 'yes'}
                return HttpResponse(json.dumps(data),
                                    content_type='application/json')
            else:
                return print_n_send_error_response(request,
                                                   'Invalid Scan Hash',
                                                   True)
        else:
            return print_n_send_error_response(request,
                                               'Only POST allowed',
                                               True)
    except Exception:
        logger.exception('Taking Screenshot')
        return print_n_send_error_response(request,
                                           'Error Taking Screenshot',
                                           True)
# AJAX


def screen_cast(request):
    """Start or Stop ScreenCast Feature."""
    try:
        trd = threading.Thread(target=env.screen_stream)
        trd.daemon = True
        trd.start()
        data = {'status': 'ok'}
        return HttpResponse(json.dumps(data),
                            content_type='application/json')
    except Exception:
        logger.exception('Screen streaming')
        return print_n_send_error_response(request,
                                           'Error Streaming screen',
                                           True)

# AJAX


def touch(request):
    """Sending Touch Events."""
    try:
        data = {}
        if (request.method == 'POST'
            and is_number(request.POST['x'])
                and is_number(request.POST['y'])):
            x_axis = request.POST['x']
            y_axis = request.POST['y']
            args = ['input',
                    'tap',
                    x_axis,
                    y_axis]
            data = {'status': 'success'}
            try:
                trd = threading.Thread(target=env.adb_command,
                                       args=(args, True))
                trd.daemon = True
                trd.start()
            except Exception:
                data = {'status': 'error'}
                logger.exception('Performing Touch Action')
        else:
            data = {'status': 'failed'}
        return HttpResponse(json.dumps(data),
                            content_type='application/json')
    except Exception:
        logger.exception('Sending Touch Events')
        return print_n_send_error_response(request,
                                           'Error Sending Touch Events',
                                           True)
# AJAX


def execute_adb(request):
    """Execute ADB Commands."""
    logger.info('Executing ADB Commands')
    try:
        if request.method == 'POST':
            data = {}
            cmd = request.POST['cmd']
            if cmd:
                args = [get_adb(),
                        '-s',
                        settings.ANALYZER_IDENTIFIER]
                try:
                    proc = subprocess.Popen(args + cmd.split(' '),
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                    stdout, stderr = proc.communicate()
                except Exception:
                    logger.exception('Executing ADB Commands')
                if stdout or stderr:
                    out = stdout or stderr
                    out = out.decode('utf8', 'ignore')
                else:
                    out = ''
                data = {'cmd': 'yes', 'resp': out}
            return HttpResponse(json.dumps(data),
                                content_type='application/json')
        else:
            return print_n_send_error_response(request,
                                               'Only POST allowed',
                                               True)
    except Exception:
        logger.exception('Executing ADB Commands')
        return print_n_send_error_response(request,
                                           'Error running ADB commands',
                                           True)

# AJAX


def mobsf_ca(request):
    adb_command = env.adb_command
    """Install and Remove MobSF Proxy RootCA."""
    try:
        if request.method == 'POST':
            data = {}
            act = request.POST['action']
            rootca = get_ca_dir()
            ca_file = '/system/etc/security/cacerts/' + settings.ROOT_CA
            if act == 'install':
                logger.info('Installing MobSF RootCA')
                adb_command(
                    ['push', rootca, ca_file])
                adb_command(['chmod',
                             '644',
                             ca_file], True)
                data = {'ca': 'installed'}
            elif act == 'remove':
                logger.info('Removing MobSF RootCA')
                adb_command(
                    ['rm', ca_file], True)
                data = {'ca': 'removed'}
            return HttpResponse(json.dumps(data),
                                content_type='application/json')
        else:
            return print_n_send_error_response(request,
                                               'Only POST allowed',
                                               True)
    except Exception:
        logger.exception('MobSF RootCA Handler')
        return print_n_send_error_response(request,
                                           'Error in RootCA Handler',
                                           True)

# AJAX


def final_test(request):
    adb_command = env.adb_command

    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    try:
        if request.method == 'POST':
            data = {}
            md5_hash = request.POST['md5']
            package = request.POST['pkg']
            if re.findall(r';|\$\(|\|\||&&', package):
                return print_n_send_error_response(request,
                                                   'Possible RCE Attack',
                                                   True)
            if re.match('^[0-9a-f]{32}$', md5_hash):
                apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                adb = get_adb()
                # Change to check output of subprocess when analysis is done
                # Can't RCE
                cmd = ('{} -s {} logcat -d dalvikvm:'
                       'W ActivityManager:I > "{}logcat.txt"').format(
                           adb,
                           settings.ANALYZER_IDENTIFIER,
                           apk_dir)
                os.system(cmd)
                logger.info('Downloading Logcat logs')
                android_version = env.get_android_version()
                if android_version < 5:
                    xposed_out = ('/data/data/'
                                  'de.robv.android.xposed.installer'
                                  '/log/error.log')
                    adb_command(['pull',
                                xposed_out,
                                apk_dir + 'x_logcat.txt'])
                    logger.info('Downloading Droidmon API Monitor Logcat logs')
                # Can't RCE
                cmd = '{} -s {} shell dumpsys > "{}dump.txt"'.format(
                    adb,
                    settings.ANALYZER_IDENTIFIER,
                    apk_dir)
                os.system(cmd)
                logger.info('Downloading Dumpsys logs')

                adb_command(['am', 'force-stop', package], True)
                logger.info('Stopping Application')

                adb_command(
                    ['am', 'force-stop', 'opensecurity.screencast'], True)
                logger.info('Stopping ScreenCast Service')

                data = {'final': 'yes'}
                return HttpResponse(json.dumps(data),
                                    content_type='application/json')
            else:
                return print_n_send_error_response(request,
                                                   'Invalid Scan Hash',
                                                   True)
        else:
            return print_n_send_error_response(request,
                                               'Only POST allowed',
                                               True)
    except Exception:
        err = 'Data Collection & Clean Up failed'
        logger.exception(err)
        return print_n_send_error_response(request,
                                           err,
                                           True)

# AJAX


def exported_activity_tester(request):
    adb_command = env.adb_command

    """Exported Activity Tester."""
    logger.info('Exported Activity Tester')
    try:
        md5_hash = request.POST['md5']
        package = request.POST['pkg']
        if re.match('^[0-9a-f]{32}$', md5_hash):
            if re.findall(r';|\$\(|\|\||&&', package):
                return print_n_send_error_response(request,
                                                   'Possible RCE Attack',
                                                   True)
            if request.method == 'POST':
                app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                screen_dir = os.path.join(app_dir, 'screenshots-apk/')
                if not os.path.exists(screen_dir):
                    os.makedirs(screen_dir)
                data = {}
                static_android_db = StaticAnalyzerAndroid.objects.filter(
                    MD5=md5_hash)
                if static_android_db.exists():
                    logger.info('Fetching Exported Activity List from DB')
                    exported_act = python_list(
                        static_android_db[0].EXPORTED_ACT)
                    if exported_act:
                        exp_act_no = 0
                        logger.info('Starting Exported Activity Tester...')
                        logger.info('%s Exported Activities Identified',
                                    str(len(exported_act)))
                        for line in exported_act:
                            try:
                                exp_act_no += 1
                                expa = 'Launching Exported Activity'
                                logger.info('%s - %s. %s',
                                            expa,
                                            str(exp_act_no),
                                            line)
                                adb_command(['am',
                                             'start',
                                             '-n',
                                             package + '/' + line], True)
                                env.wait(4)
                                adb_command(['screencap',
                                             '-p',
                                             '/data/local/screen.png'], True)
                                # ? get appended from Air :-()
                                # if activity names are used
                                outfile = '{}expact-{}.png'.format(
                                    screen_dir, str(exp_act_no))
                                adb_command(['pull',
                                             '/data/local/screen.png',
                                             outfile])
                                logger.info('Activity Screenshot Taken')
                                adb_command(['am',
                                             'force-stop',
                                             package], True)
                                logger.info('Stopping App')
                            except Exception:
                                logger.exception('Exported Activity Tester')
                        data = {'expacttest': 'done'}
                    else:
                        logger.info(
                            'Exported Activity Tester - No Activity Found!')
                        data = {'expacttest': 'noact'}
                    return HttpResponse(json.dumps(data),
                                        content_type='application/json')
                else:
                    err = 'Entry does not exist in DB'
                    return print_n_send_error_response(request,
                                                       err,
                                                       True)
            else:
                return print_n_send_error_response(request,
                                                   'Only POST allowed',
                                                   True)
        else:
            return print_n_send_error_response(request,
                                               'Invalid Scan Hash',
                                               True)
    except Exception:
        err = 'Error Running Exported Activity Tests'
        logger.exception('ERROR] Exported Activity Tester')
        return print_n_send_error_response(request,
                                           err,
                                           True)

# AJAX


def activity_tester(request):
    adb_command = env.adb_command
    """Activity Tester."""
    logger.info('Activity Tester')
    try:
        md5_hash = request.POST['md5']
        package = request.POST['pkg']
        if re.match('^[0-9a-f]{32}$', md5_hash):
            if re.findall(r';|\$\(|\|\||&&', package):
                return print_n_send_error_response(request,
                                                   'Possible RCE Attack',
                                                   True)
            if request.method == 'POST':
                app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                screen_dir = os.path.join(app_dir, 'screenshots-apk/')
                if not os.path.exists(screen_dir):
                    os.makedirs(screen_dir)
                data = {}
                static_android_db = StaticAnalyzerAndroid.objects.filter(
                    MD5=md5_hash)
                if static_android_db.exists():
                    logger.info('Fetching Activity List from DB')
                    activities = python_list(static_android_db[0].ACTIVITIES)
                    if activities:
                        act_no = 0
                        logger.info('Starting Activity Tester...')
                        logger.info('%s Activities Identified',
                                    str(len(activities)))
                        for line in activities:
                            try:
                                act_no += 1
                                logger.info(
                                    'Launching Activity - %s. %s',
                                    str(act_no),
                                    line)
                                adb_command(['am',
                                             'start',
                                             '-n',
                                             package + '/' + line], True)
                                env.wait(4)
                                adb_command(
                                    ['screencap',
                                     '-p',
                                     '/data/local/screen.png'], True)
                                # ? get appended from Air :-()
                                # if activity names are used
                                outfile = ('{}act-{}.png'.format(
                                    screen_dir,
                                    act_no))
                                adb_command(['pull',
                                             '/data/local/screen.png',
                                             outfile])
                                logger.info('Activity Screenshot Taken')
                                adb_command(
                                    ['am', 'force-stop', package], True)
                                logger.info('Stopping App')
                            except Exception:
                                logger.exception('Activity Tester')
                        data = {'acttest': 'done'}
                    else:
                        logger.info('Activity Tester - No Activity Found!')
                        data = {'acttest': 'noact'}
                    return HttpResponse(json.dumps(data),
                                        content_type='application/json')
                else:
                    err = 'Entry does not exist in DB'
                    return print_n_send_error_response(request,
                                                       err,
                                                       True)
            else:
                return print_n_send_error_response(request,
                                                   'Only POST allowed',
                                                   True)
        else:
            return print_n_send_error_response(request,
                                               'Invalid Scan Hash',
                                               True)
    except Exception:
        logger.exception('Activity Tester')
        return print_n_send_error_response(request,
                                           'Error Running Activity Tester',
                                           True)

# AJAX


def dump_data(request):
    adb_command = env.adb_command

    """Downloading Application Data from Device."""
    logger.info('Downloading Application Data from Device')
    try:
        if request.method == 'POST':
            data = {}
            package = request.POST['pkg']
            md5_hash = request.POST['md5']
            if re.match('^[0-9a-f]{32}$', md5_hash):
                if re.findall(r';|\$\(|\|\||&&', package):
                    return print_n_send_error_response(request,
                                                       'Possible RCE Attack',
                                                       True)
                apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
                stop_capfuzz(settings.PROXY_PORT)
                files_loc = '/data/local/'
                logger.info('Creating TAR of Application Files.')
                adb_command(['tar', '-cvf', files_loc + package + '.tar',
                             '/data/data/' + package + '/'], True)
                logger.info('Dumping Application Files')
                adb_command(['pull',
                             files_loc + package + '.tar',
                             apk_dir + package + '.tar'])
                logger.info('Stopping ADB')
                adb_command(['kill-server'])
                data = {'dump': 'yes'}
                return HttpResponse(json.dumps(data),
                                    content_type='application/json')
            else:
                return print_n_send_error_response(request,
                                                   'Invalid Scan Hash',
                                                   True)
        else:
            return print_n_send_error_response(request,
                                               'Only POST allowed',
                                               True)
    except Exception:
        logger.exception('Downloading Application Data from Device')
        err = 'Application Data Dump from Device failed'
        return print_n_send_error_response(request,
                                           err,
                                           True)
