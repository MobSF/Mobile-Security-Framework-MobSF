# -*- coding: utf_8 -*-
"""Android Dynamic Analysis."""
import logging
import os
import time
from pathlib import Path
from json import dump

from shelljob import proc


from django.http import (HttpResponseRedirect,
                         JsonResponse,
                         StreamingHttpResponse)
from django.conf import settings
from django.shortcuts import render
from django.db.models import ObjectDoesNotExist
from django.views.decorators.http import require_http_methods

from mobsf.DynamicAnalyzer.forms import (
    AndroidDeviceSelectionForm,
    AndroidDynamicAnalysisForm,
)
from mobsf.DynamicAnalyzer.tools.apk_patcher import GadgetPatcher
from mobsf.DynamicAnalyzer.views.android.environment import (
    ANDROID_API_SUPPORTED,
    Environment,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    start_httptools_ui,
    stop_httptools,
)
from mobsf.MobSF.utils import (
    get_android_devices,
    get_android_dm_exception_msg,
    get_config_loc,
    get_device,
    get_proxy_ip,
    is_md5,
    print_n_send_error_response,
    python_dict,
    python_list,
    strict_package_check,
)
from mobsf.MobSF.forms import FormUtil
from mobsf.MobSF.views.scanning import add_to_recent_scan
from mobsf.StaticAnalyzer.models import StaticAnalyzerAndroid
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['GET', 'POST'])
def android_dynamic_analysis(request, api=False):
    """Android Dynamic Analysis Entry point."""
    try:
        scan_apps = []
        device_packages = {}
        and_ver = None
        and_sdk = None
        runtime = None
        devices = get_android_devices()
        device_form = AndroidDeviceSelectionForm(
            devices,
            request.POST if request.method == 'POST' else None,
        )
        if request.method == 'POST' and device_form.is_valid():
            request.session['android_device_identifier'] = (
                device_form.cleaned_data['identifier'])
            return HttpResponseRedirect(request.path)
        apks = StaticAnalyzerAndroid.objects.filter(
            APP_TYPE='apk')

        for apk in reversed(apks):

            logcat = Path(settings.UPLD_DIR) / apk.MD5 / 'logcat.txt'
            temp_dict = {
                'ICON_PATH': apk.ICON_PATH,
                'MD5': apk.MD5,
                'APP_NAME': apk.APP_NAME,
                'VERSION_NAME': apk.VERSION_NAME,
                'FILE_NAME': apk.FILE_NAME,
                'PACKAGE_NAME': apk.PACKAGE_NAME,
                'DYNAMIC_REPORT_EXISTS': logcat.exists(),
            }
            scan_apps.append(temp_dict)
        try:
            identifier = get_device(request)
        except Exception:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)
        try:
            if identifier:
                env = Environment(identifier)
                env.connect()
                if api:
                    device_packages = env.get_device_packages()
                    if device_packages:
                        pkg_file = Path(settings.DWD_DIR) / 'packages.json'
                        with pkg_file.open('w', encoding='utf-8') as target:
                            dump(device_packages, target)
                and_ver = env.get_android_version()
                and_sdk = env.get_android_sdk()
                runtime = env.get_environment()
        except Exception:
            pass
        context = {'apps': scan_apps,
                   'identifier': identifier,
                   'android_version': and_ver,
                   'android_sdk': and_sdk,
                   'runtime': runtime,
                   'devices': devices,
                   'device_form': device_form,
                   'android_supported': ANDROID_API_SUPPORTED,
                   'proxy_ip': get_proxy_ip(identifier),
                   'proxy_port': settings.PROXY_PORT,
                   'settings_loc': get_config_loc(),
                   'device_packages': device_packages,
                   'title': 'MobSF Dynamic Analysis',
                   'version': settings.MOBSF_VER}
        if api:
            return context
        template = 'dynamic_analysis/android/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis')
        return print_n_send_error_response(request, exp, api)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['GET'])
def android_device_apps(request):
    """Load installed device apps without blocking the main page."""
    try:
        identifier = get_device(request)
        if not identifier:
            return JsonResponse({
                'status': 'failed',
                'message': 'No Android device selected',
            }, status=400)
        refresh = request.GET.get('refresh', '0')
        if refresh not in ('0', '1'):
            return JsonResponse({
                'status': 'failed',
                'message': 'Invalid refresh option',
            }, status=400)
        env = Environment(identifier)
        if not env.connect():
            return JsonResponse({
                'status': 'failed',
                'message': 'Selected Android device is unavailable',
            }, status=503)
        device_packages = env.get_device_packages(refresh=refresh == '1')
        pkg_file = Path(settings.DWD_DIR) / 'packages.json'
        with pkg_file.open('w', encoding='utf-8') as target:
            dump(device_packages, target)
        return JsonResponse({
            'status': 'ok',
            'packages': device_packages,
        })
    except Exception:
        logger.exception('Loading Android device apps')
        return JsonResponse({
            'status': 'failed',
            'message': 'Failed to load installed applications',
        }, status=500)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def android_package_status(request):
    """Check whether Gadget installation needs user confirmation."""
    analysis_form = AndroidDynamicAnalysisForm(request.POST)
    checksum = request.POST.get('hash')
    if not analysis_form.is_valid() or not is_md5(checksum):
        return JsonResponse({
            'status': 'failed',
            'message': 'Invalid parameters',
        }, status=400)
    package = get_package_name(checksum)
    identifier = get_device(request)
    if not package or not identifier:
        return JsonResponse({
            'status': 'failed',
            'message': 'App or Android device is unavailable',
        }, status=400)
    try:
        env = Environment(identifier)
        if not env.connect():
            raise RuntimeError('Selected Android device is unavailable')
        mode = (
            analysis_form.cleaned_data.get('device_mode')
            or 'auto'
        )
        runtime = env.get_environment()
        selected_mode = mode
        if runtime != 'physical':
            selected_mode = 'legacy'
        elif mode == 'auto':
            profile = env.get_device_profile(probe_root=True)
            selected_mode = 'rooted' if profile.has_root else 'gadget'
        installed = env.has_package(package)
        return JsonResponse({
            'status': 'ok',
            'installed': installed,
            'selected_mode': selected_mode,
            'confirmation_required': (
                installed and selected_mode == 'gadget'
            ),
        })
    except Exception:
        logger.exception('Checking Android package status')
        return JsonResponse({
            'status': 'failed',
            'message': 'Failed to check the installed application',
        }, status=500)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def dynamic_analyzer(request, checksum, api=False):
    """Android Dynamic Analyzer Environment."""
    try:
        identifier = None
        activities = None
        deeplinks = None
        exported_activities = None
        env = None
        physical = False
        proxy_configured = False
        previous_proxy = ''
        gadget_marker = None
        proxy_state_file = None
        analysis_form = AndroidDynamicAnalysisForm(request.POST)
        if not analysis_form.is_valid():
            return print_n_send_error_response(
                request,
                FormUtil.errors_message(analysis_form),
                api,
            )
        options = analysis_form.cleaned_data
        device_mode = options.get('device_mode') or 'auto'
        reinstall = options.get('re_install') or '1'
        install = options.get('install') or '1'
        uninstall_existing = options.get('uninstall_existing') or '0'
        if not is_md5(checksum):
            # We need this check since checksum is not validated
            # in REST API
            return print_n_send_error_response(
                request,
                'Invalid Hash',
                api)
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum',
                api)
        logger.info('Creating Dynamic Analysis Environment for %s', package)
        try:
            identifier = get_device(request)
        except Exception:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)
        if not identifier:
            return print_n_send_error_response(
                request, get_android_dm_exception_msg(), api)

        # Get activities from the static analyzer results
        try:
            static_android_db = StaticAnalyzerAndroid.objects.get(
                MD5=checksum)
            exported_activities = python_list(
                static_android_db.EXPORTED_ACTIVITIES)
            activities = python_list(
                static_android_db.ACTIVITIES)
            deeplinks = python_dict(
                static_android_db.BROWSABLE_ACTIVITIES)
        except ObjectDoesNotExist:
            logger.warning(
                'Failed to get Activities/Deeplinks. '
                'Static Analysis not completed for the app.')
        env = Environment(identifier)
        if not env.connect():
            msg = f'Cannot connect to {identifier}'
            return print_n_send_error_response(request, msg, api)
        runtime = env.get_environment()
        physical = runtime == 'physical'
        profile = env.get_device_profile(
            probe_root=physical and device_mode != 'gadget')
        selected_mode = device_mode
        if not physical:
            if device_mode == 'gadget':
                return print_n_send_error_response(
                    request,
                    'Frida Gadget mode requires a physical Android device',
                    api,
                )
            selected_mode = 'legacy'
        elif device_mode == 'auto':
            selected_mode = 'rooted' if profile.has_root else 'gadget'
        if selected_mode == 'rooted' and not profile.has_root:
            return print_n_send_error_response(
                request,
                f'Android root is {profile.root_status}. '
                'Use Frida Gadget mode for this device.',
                api,
            )
        if selected_mode != 'gadget' and not env.connect_n_mount():
            msg = f'Cannot prepare {identifier} for dynamic analysis'
            return print_n_send_error_response(request, msg, api)
        version = profile.android_version
        logger.info('Android Version identified as %s', version)
        xposed_first_run = False
        if selected_mode != 'gadget' and not env.is_mobsfyied(version):
            msg = ('This Android instance is not MobSFyed/Outdated.\n'
                   'MobSFying the android runtime environment')
            logger.warning(msg)
            if not env.mobsfy_init():
                return print_n_send_error_response(
                    request,
                    'Failed to MobSFy the instance',
                    api)
            if version < 5:
                # Start Clipboard monitor
                env.start_clipmon()
                xposed_first_run = True
        if xposed_first_run:
            msg = ('Have you MobSFyed the instance before'
                   ' attempting Dynamic Analysis?'
                   ' Install Framework for Xposed.'
                   ' Restart the device and enable'
                   ' all Xposed modules. And finally'
                   ' restart the device once again.')
            return print_n_send_error_response(request, msg, api)
        app_dir = Path(settings.UPLD_DIR) / checksum
        gadget_marker = app_dir / '.mobsf-gadget-mode'
        proxy_state_file = app_dir / '.mobsf-proxy-state'
        if gadget_marker.is_symlink() or proxy_state_file.is_symlink():
            raise RuntimeError('Unsafe dynamic-analysis state path')
        # Clean up previous analysis
        env.dz_cleanup(checksum)
        apk_path = app_dir / f'{checksum}.apk'
        user_ca_trusted = False
        if selected_mode == 'gadget':
            if install != '1':
                return print_n_send_error_response(
                    request,
                    'Frida Gadget mode must install the patched APK',
                    api,
                )
            package_installed = env.has_package(package)
            if package_installed and uninstall_existing != '1':
                return print_n_send_error_response(
                    request,
                    'Confirmation is required before uninstalling the '
                    'existing app and installing a re-signed Gadget APK.',
                    api,
                )
            patcher = GadgetPatcher(
                app_dir,
                apk_path,
                profile.abi,
            )
            apk_path = patcher.patch()
            user_ca_trusted = patcher.user_ca_trusted
            if package_installed and not env.uninstall_package(package):
                return print_n_send_error_response(
                    request,
                    'Failed to uninstall the existing application',
                    api,
                )
        else:
            gadget_marker.unlink(missing_ok=True)
        reverse_created = False
        if physical:
            previous_proxy = env.get_global_proxy()
            reverse_created = not env.has_adb_reverse_tcp()
        # Configure Web Proxy
        env.configure_proxy(package, request)
        # Supported in Android 5+
        if not physical or reverse_created:
            env.enable_adb_reverse_tcp(version)
        if physical:
            with proxy_state_file.open('w', encoding='utf-8') as state:
                dump({
                    'proxy': previous_proxy,
                    'remove_reverse': reverse_created,
                }, state)
        # Apply Global Proxy to device
        env.set_global_proxy(version)
        proxy_configured = True
        if install == '1':
            status, output = env.install_apk(
                apk_path.as_posix(),
                package,
                '0' if selected_mode == 'gadget' else reinstall,
                modify_verifier=selected_mode != 'gadget',
            )
            if not status:
                if physical:
                    env.restore_global_proxy(previous_proxy)
                    if reverse_created:
                        env.disable_adb_reverse_tcp()
                    proxy_state_file.unlink(missing_ok=True)
                else:
                    env.unset_global_proxy()
                msg = 'This APK cannot be installed on the Android device.'
                if selected_mode != 'gadget':
                    msg = f'{msg}\n{output}'
                return print_n_send_error_response(
                    request,
                    msg,
                    api)
        if selected_mode == 'gadget':
            gadget_marker.write_text(identifier, encoding='utf-8')
        logger.info('Testing Environment is Ready!')
        context = {'package': package,
                   'hash': checksum,
                   'android_version': version,
                   'device_mode': selected_mode,
                   'user_ca_trusted': user_ca_trusted,
                   'version': settings.MOBSF_VER,
                   'activities': activities,
                   'exported_activities': exported_activities,
                   'deeplinks': deeplinks,
                   'title': 'Dynamic Analyzer'}
        template = 'dynamic_analysis/android/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        if env and physical and proxy_configured:
            env.restore_global_proxy(previous_proxy)
            if reverse_created:
                env.disable_adb_reverse_tcp()
        if proxy_state_file:
            proxy_state_file.unlink(missing_ok=True)
        if gadget_marker:
            gadget_marker.unlink(missing_ok=True)
        logger.exception('Dynamic Analyzer')
        return print_n_send_error_response(
            request,
            'Dynamic Analysis Failed.',
            api)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def httptools_start(request):
    """Start httprools UI."""
    logger.info('Starting httptools Web UI')
    try:
        httptools_url = get_http_tools_url(request)
        stop_httptools(httptools_url)
        start_httptools_ui(settings.PROXY_PORT)
        time.sleep(3)
        logger.info('httptools UI started')
        if request.POST['project']:
            project = request.POST['project']
        else:
            project = ''
        url = f'{httptools_url}/dashboard/{project}'
        return HttpResponseRedirect(url)
    except Exception:
        logger.exception('Starting httptools Web UI')
        err = 'Error Starting httptools UI'
        return print_n_send_error_response(request, err)


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['GET', 'POST'])
def logcat(request, api=False):
    logger.info('Starting Logcat streaming')
    try:
        if request.method == 'GET':
            pkg = request.GET.get('package')
            if pkg and strict_package_check(pkg):
                template = 'dynamic_analysis/android/logcat.html'
                return render(request, template, {'package': pkg})
            return print_n_send_error_response(
                request,
                'Invalid package name',
                api)
        if api:
            app_pkg = request.POST['package']
        else:
            app_pkg = request.POST.get('app_package')
        if app_pkg:
            if not strict_package_check(app_pkg):
                return print_n_send_error_response(
                    request,
                    'Invalid package name',
                    api)
            adb = os.environ['MOBSF_ADB']
            g = proc.Group()
            g.run([
                adb,
                '-s',
                get_device(request),
                'logcat',
                app_pkg + ':V',
                '*:*',
            ])

            def read_process():
                while g.is_pending():
                    lines = g.readlines()
                    for _, line in lines:
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


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def trigger_static_analysis(request, checksum):
    """On device APK Static Analysis."""
    try:
        identifier = None
        if not is_md5(checksum):
            return print_n_send_error_response(
                request,
                'Invalid MD5')
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(
                request,
                'Cannot get package name from checksum')
        try:
            identifier = get_device(request)
        except Exception:
            err = 'Cannot connect to Android Runtime'
            return print_n_send_error_response(request, err)
        env = Environment(identifier)
        scan_type = env.get_apk(checksum, package)
        if not scan_type:
            err = 'Failed to download APK file'
            return print_n_send_error_response(request, err)
        file_name = f'{package}.apk'
        if scan_type == 'apks':
            file_name = f'{file_name}s'
        data = {
            'analyzer': 'static_analyzer',
            'status': 'success',
            'hash': checksum,
            'scan_type': scan_type,
            'file_name': file_name,
        }
        add_to_recent_scan(data)
        return HttpResponseRedirect(f'/static_analyzer/{checksum}/')
    except Exception:
        msg = 'On device APK Static Analysis'
        logger.exception(msg)
        return print_n_send_error_response(request, msg)
