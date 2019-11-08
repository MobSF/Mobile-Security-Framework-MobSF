# -*- coding: utf_8 -*-
"""Available Actions."""
import logging
import os

from django.conf import settings
from django.views.decorators.http import require_http_methods

from DynamicAnalyzer.views.android.operations import (
    invalid_params,
    is_attack_pattern,
    is_md5,
    json_response,
    strict_package_check)
from DynamicAnalyzer.views.android.environment import Environment
from DynamicAnalyzer.views.android.tests_xposed import download_xposed_log
from DynamicAnalyzer.tools.webproxy import stop_httptools

from MobSF.utils import python_list

from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)

# AJAX


@require_http_methods(['POST'])
def activity_tester(request):
    """Exported & non exported activity Tester."""
    data = {}
    try:
        env = Environment()
        test = request.POST['test']
        md5_hash = request.POST['hash']
        package = request.POST['package']
        if is_attack_pattern(package) or not is_md5(md5_hash):
            return invalid_params()
        app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        screen_dir = os.path.join(app_dir, 'screenshots-apk/')
        if not os.path.exists(screen_dir):
            os.makedirs(screen_dir)
        static_android_db = StaticAnalyzerAndroid.objects.filter(
            MD5=md5_hash)
        if not static_android_db.exists():
            data = {'status': 'failed',
                    'message': 'App details not found in database'}
            return json_response(data)
        iden = ''
        if test == 'exported':
            iden = 'Exported '
            logger.info('Exported activity tester')
            activities = python_list(static_android_db[0].EXPORTED_ACT)
        else:
            logger.info('Activity tester')
            activities = python_list(static_android_db[0].ACTIVITIES)
        logger.info('Fetching %sactivities for %s', iden, package)
        if not activities:
            msg = 'No {}Activites found'.format(iden)
            logger.info(msg)
            data = {'status': 'failed',
                    'message': msg}
            return json_response(data)
        act_no = 0
        logger.info('Starting %sActivity Tester...', iden)
        logger.info('%s %sActivities Identified',
                    str(len(activities)), iden)
        for activity in activities:
            act_no += 1
            logger.info(
                'Launching %sActivity - %s. %s',
                iden,
                str(act_no),
                activity)
            if test == 'exported':
                file_iden = 'expact'
            else:
                file_iden = 'act'
            outfile = ('{}{}-{}.png'.format(
                screen_dir,
                file_iden,
                act_no))
            env.launch_n_capture(package, activity, outfile)
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('%sActivity tester', iden)
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def download_data(request):
    """Download Application Data from Device."""
    logger.info('Downloading app data')
    data = {}
    try:
        env = Environment()
        package = request.POST['package']
        md5_hash = request.POST['hash']
        if is_attack_pattern(package) or not is_md5(md5_hash):
            return invalid_params()
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        stop_httptools(settings.PROXY_PORT)
        files_loc = '/data/local/'
        logger.info('Archiving files created by app')
        env.adb_command(['tar', '-cvf', files_loc + package + '.tar',
                         '/data/data/' + package + '/'], True)
        logger.info('Downloading Archive')
        env.adb_command(['pull', files_loc + package + '.tar',
                         apk_dir + package + '.tar'])
        logger.info('Stopping ADB server')
        env.adb_command(['kill-server'])
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Downloading application data')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)

# AJAX


@require_http_methods(['POST'])
def collect_logs(request):
    """Collecting Data and Cleanup."""
    logger.info('Collecting Data and Cleaning Up')
    data = {}
    try:
        env = Environment()
        md5_hash = request.POST['hash']
        package = request.POST['package']
        if (not strict_package_check(package)
                or not is_md5(md5_hash)):
            return invalid_params()
        apk_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        lout = os.path.join(apk_dir, 'logcat.txt')
        dout = os.path.join(apk_dir, 'dump.txt')
        logger.info('Downloading logcat logs')
        logcat = env.adb_command(['logcat',
                                  '-d',
                                  package + ':V',
                                  '*:*'])
        with open(lout, 'wb') as flip:
            flip.write(logcat)
        logger.info('Downloading dumpsys logs')
        dumpsys = env.adb_command(['dumpsys'], True)
        with open(dout, 'wb') as flip:
            flip.write(dumpsys)
        if env.get_android_version() < 5:
            download_xposed_log(apk_dir)
        env.adb_command(['am', 'force-stop', package], True)
        logger.info('Stopping app')
        # Unset Global Proxy
        env.unset_global_proxy()
        data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Data Collection & Clean Up failed')
        data = {'status': 'failed', 'message': str(exp)}
    return json_response(data)
