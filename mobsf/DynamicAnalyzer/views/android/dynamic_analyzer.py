# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import time
from pathlib import Path

from shelljob import proc

from django.http import (HttpResponseRedirect,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render

from mobsf.DynamicAnalyzer.views.android.environment import Environment
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
    strict_package_check,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    start_httptools_ui,
    stop_httptools,
)
from mobsf.MobSF.utils import (
    get_config_loc,
    get_device,
    get_proxy_ip,
    is_md5,
    print_n_send_error_response,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid

logger = logging.getLogger(__name__)


def dynamic_analysis(request, api=False):
    """Android Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk').order_by('-id')
        for apk in apks:
            temp_dict = {
                'ICON_FOUND': apk.ICON_FOUND,
                'MD5': apk.MD5,
                'APP_NAME': apk.APP_NAME,
                'VERSION_NAME': apk.VERSION_NAME,
                'FILE_NAME': apk.FILE_NAME,
                'PACKAGE_NAME': apk.PACKAGE_NAME,
            }
            scan_apps.append(temp_dict)
        try:
            identifier = get_device()
        except Exception:
            msg = ('Is Android VM running? MobSF cannot'
                   ' find android instance identifier.'
                   ' Please run an android instance and refresh'
                   ' this page. If this error persists,'
                   ' set ANALYZER_IDENTIFIER in '
                   f'{get_config_loc()}')
            return print_n_send_error_response(request, msg, api)
        proxy_ip = get_proxy_ip(identifier)
        context = {'apps': scan_apps,
                   'identifier': identifier,
                   'proxy_ip': proxy_ip,
                   'proxy_port': settings.PROXY_PORT,
                   'title': 'MobSF Dynamic Analysis',
                   'version': settings.MOBSF_VER}
        if api:
            return context
        template = 'dynamic_analysis/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request,
                                           exp,
                                           api)


def dynamic_analyzer(request, checksum, api=False):
    """Android Dynamic Analyzer Environment."""
    logger.info('Creating Dynamic Analysis Environment')
    try:
        no_device = False
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Invalid Parameters',
                api)
        try:
            identifier = get_device()
        except Exception:
            no_device = True
        if no_device or not identifier:
            msg = ('Is the android instance running? MobSF cannot'
                   ' find android instance identifier. '
                   'Please run an android instance and refresh'
                   ' this page. If this error persists,'
                   ' set ANALYZER_IDENTIFIER in '
                   f'{get_config_loc()}')
            return print_n_send_error_response(request, msg, api)
        env = Environment(identifier)
        if not env.connect_n_mount():
            msg = 'Cannot Connect to ' + identifier
            return print_n_send_error_response(request, msg, api)
        version = env.get_android_version()
        logger.info('Android Version identified as %s', version)
        xposed_first_run = False
        if not env.is_mobsfyied(version):
            msg = ('This Android instance is not MobSfyed/Outdated.\n'
                   'MobSFying the android runtime environment')
            logger.warning(msg)
            if not env.mobsfy_init():
                return print_n_send_error_response(
                    request,
                    'Failed to MobSFy the instance',
                    api)
            if version < 5:
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you MobSFyed the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            return print_n_send_error_response(request, msg, api)
        # Clean up previous analysis
        env.dz_cleanup(checksum)
        # Configure Web Proxy
        env.configure_proxy(package)
        # Supported in Android 5+
        env.enable_adb_reverse_tcp(version)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        # Start Clipboard monitor
        env.start_clipmon()
        # Get Screen Resolution
        screen_width, screen_height = env.get_screen_res()
        apk_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.apk'
        # Install APK
        status, output = env.install_apk(apk_path.as_posix(), package)
        if not status:
            # Unset Proxy
            env.unset_global_proxy()
            msg = (f'This APK cannot be installed. Is this APK '
                   f'compatible the Android VM/Emulator?\n{output}')
            return print_n_send_error_response(
                request,
                msg,
                api)
        logger.info('Testing Environment is Ready!')
        context = {'screen_witdth': screen_width,
                   'screen_height': screen_height,
                   'package': package,
                   'hash': checksum,
                   'android_version': version,
                   'version': settings.MOBSF_VER,
                   'title': 'Dynamic Analyzer'}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(
            request,
            'Dynamic Analysis Failed.',
            api)


def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        stop_httptools(settings.PROXY_PORT)
        start_httptools_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('httptools UI started')
        if request.GET['project']:
            project = request.GET['project']
        else:
            project = ''
        url = ('http://localhost:{}'
               '/dashboard/{}'.format(
                   str(settings.PROXY_PORT),
                   project))
        return HttpResponseRedirect(url)  # lgtm [py/reflective-xss]
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        return print_n_send_error_response(request, err)


def logcat(request, api=False):
    logger.info('Starting Logcat streaming')
    try:
        pkg = request.GET.get('package')
        if pkg:
            if not strict_package_check(pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            template = 'dynamic_analysis/android/logcat.html'
            return render(request, template, {'package': pkg})
        if api:
            app_pkg = request.POST['package']
        else:
            app_pkg = request.GET.get('app_package')
        if app_pkg:
            if not strict_package_check(app_pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            adb = os.environ['MOBSF_ADB']
            g = proc.Group()
            g.run([adb, 'logcat', app_pkg + ':V', '*:*'])

            def read_process():
                while g.is_pending():
                    lines = g.readlines()
                    for _, line in lines:
                        time.sleep(.01)
                        yield 'data:{}\n\n'.format(line)
            return StreamingHttpResponse(read_process(),
                                         content_type='text/event-stream')
        return print_n_send_error_response(
            request,
            'Invalid parameters',
            api)
    except Exception:
        logger.exception('Logcat Streaming')
        err = 'Error in Logcat streaming'
        return print_n_send_error_response(request, err, api)
