# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import time

from shelljob import proc

from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render

from DynamicAnalyzer.views.android.environment import Environment
from DynamicAnalyzer.views.android.operations import (
    is_attack_pattern,
    is_md5)
from DynamicAnalyzer.tools.webproxy import (
    start_fuzz_ui,
    stop_capfuzz)

from MobSF.utils import (get_device,
                         print_n_send_error_response)


from StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


def dynamic_analysis(request):
    """Android Dynamic Analysis Entry point."""
    apks = StaticAnalyzerAndroid.objects.filter(
        ZIPPED='&type=apk').order_by('-id')
    context = {'apks': apks,
               'identifier': get_device(),
               'title': 'MobSF Dynamic Analysis'}
    template = 'dynamic_analysis/dynamic_analysis.html'
    return render(request, template, context)


def dynamic_analyzer(request):
    """Android Dynamic Analyzer Environment."""
    logger.info('Creating Dynamic Analysis Environment')
    try:
        bin_hash = request.GET['hash']
        package = request.GET['package']
        launcher = request.GET['mainactivity']
        if (is_attack_pattern(package)
                or is_attack_pattern(launcher)
                or not is_md5(bin_hash)):
            return print_n_send_error_response(request,
                                               'Invalid Parameters')
        identifier = get_device()
        if not identifier:
            msg = ('MobSF cannot find android instance identifier. '
                   'Please set ANALYZER_IDENTIFIER in MobSF/settings.py')
            return print_n_send_error_response(request, msg)
        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + identifier
            return print_n_send_error_response(request, msg)
        android_version = env.get_android_version()
        if not env.is_mobsfyied(android_version):
            msg = ('This Android instance is not MobSfyed. '
                   'MobSFying the android runtime environment')
            logger.warning(msg)
            if not env.mobsfy_init():
                return print_n_send_error_response(
                    request,
                    'Failed to MobSFy the instance')
        # Clean up previous analysis
        env.dz_cleanup(bin_hash)
        # Configure Web Proxy
        env.configure_proxy(package)
        # Identify Emvironment
        if android_version >= 5:
            # ADB Reverse TCP
            env.enable_adb_reverse_tcp()
        # Start Clipboard monitor
        env.start_clipmon()
        # Get Screen Resolution
        screen_width, screen_height = env.get_screen_res()
        logger.info('Installing APK')
        app_dir = os.path.join(settings.UPLD_DIR,
                               bin_hash + '/')  # APP DIRECTORY
        apk_path = app_dir + bin_hash + '.apk'  # APP PATH
        env.adb_command(['install', '-r', apk_path], False, True)
        if launcher:
            run_app = package + '/' + launcher
            logger.info('Launching APK Main Activity')
            env.adb_command(['am', 'start', '-n', run_app],
                            True, True)
        logger.info('Testing Environment is Ready!')
        context = {'screen_witdth': screen_width,
                   'screen_height': screen_height,
                   'package': package,
                   'md5': bin_hash,
                   'version': android_version,
                   'title': 'Dynamic Analyzer'}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        return render(request, template, context)
    except Exception:
        logger.exception('DynamicAnalyzer')
        return print_n_send_error_response(request,
                                           'Dynamic Analysis Failed.')


def capfuzz_start(request):
    """Start CapFuzz UI."""
    logger.info('Starting CapFuzz Web UI')
    try:
        stop_capfuzz(settings.PROXY_PORT)
        start_fuzz_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('CapFuzz UI Started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = ('http://localhost:{}'
               '/dashboard/{}'.format(
                   str(settings.PROXY_PORT),
                   project))
        return HttpResponseRedirect(url)
    except Exception:
        logger.exception('Starting CapFuzz Web UI')
        err = 'Error Starting CapFuzz UI'
        return print_n_send_error_response(request, err)


def logcat(request):
    logger.info('Starting Logcat streaming')
    try:
        view = request.GET.get('view')
        if view:
            template = 'dynamic_analysis/android/logcat.html'
            return render(request, template, None)
        adb = os.environ['MOBSF_ADB'] if 'MOBSF_ADB' in os.environ else 'adb'
        g = proc.Group()
        g.run([adb, 'logcat'])

        def read_process():
            while g.is_pending():
                lines = g.readlines()
                for _, line in lines:
                    time.sleep(.2)
                    yield 'data:{}\n\n'.format(line)
        return StreamingHttpResponse(read_process(),
                                     content_type='text/event-stream')
    except Exception:
        logger.exception('Logcat Streaming')
        err = 'Error in Logcat streaming'
        return print_n_send_error_response(request, err)
