# -*- coding: utf_8 -*-
"""iOS Dynamic Analysis."""
import logging
import os
import time
from threading import Thread
from pathlib import Path

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_http_methods


from mobsf.MobSF.utils import (
    IOS_DEVICE_ID_REGEX,
    SSH_DEVICE_ID_REGEX,
    parse_host_port,
    print_n_send_error_response,
    strict_package_check,
    is_md5,
    get_md5,
)

from mobsf.DynamicAnalyzer.views.common.shared import (
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.DynamicAnalyzer.forms import UploadFileForm
from mobsf.DynamicAnalyzer.views.ios.helpers import (
    get_local_ipa_list,
    configure_proxy,
)
from mobsf.DynamicAnalyzer.views.ios.device.device import IOSDevice
from mobsf.DynamicAnalyzer.views.ios.device.connect import IOSConnector
from mobsf.DynamicAnalyzer.views.ios.device.environment import IOSEnvironment
from mobsf.DynamicAnalyzer.views.ios.device.frida import FridaIOSDevice
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)
OK = 'ok'
FAILED = 'failed'


@login_required
@permission_required(Permissions.SCAN)
def dynamic_analysis_device(request, api=False):
    """The iOS Device Dynamic Analysis Entry point."""
    try:
        device_id = request.GET.get('device_id', '')
        scan_apps = get_local_ipa_list()
        connector = IOSConnector()
        wifi_devices = get_ios_devices_over_wifi()
        if os.getenv('MOBSF_PLATFORM') == 'docker':
            devices = []
        else:
            devices = connector.get_usb_devices()
        context = {
            'selected_device': device_id,
            'apps': scan_apps,
            'usb_devices': devices,
            'wifi_devices': wifi_devices,
            'title': 'MobSF Dynamic Analysis Jailbroken Device',
            'version': settings.MOBSF_VER,
        }
        if api:
            return context
        template = 'dynamic_analysis/ios/device/dynamic_analysis.html'
        return render(request, template, context)
    except Exception as exp:
        logger.exception('iOS Jailbroken Device Dynamic Analysis')
        return print_n_send_error_response(request, exp, api)


@login_required
@permission_required(Permissions.SCAN)
def dynamic_analyzer_device(request, api=False):
    """Dynamic Analyzer for Jailbroken iOS devices."""
    try:
        if api:
            bundleid = request.POST.get('bundle_id')
            device_id = request.POST.get('device_id')
            form = None
        else:
            bundleid = request.GET.get('bundle_id')
            device_id = request.GET.get('device_id')
            form = UploadFileForm()
        if not bundleid or not strict_package_check(bundleid):
            return print_n_send_error_response(
                request,
                'Invalid iOS Bundle id',
                api)
        checksum = get_md5(bundleid.encode('utf-8'))
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            return print_n_send_error_response(
                request,
                error,
                api)

        app_dir = Path(settings.UPLD_DIR) / checksum
        if not app_dir.exists():
            app_dir.mkdir()
        configure_proxy(request, bundleid, None)
        env = IOSEnvironment(ios_device)
        env.setup_or_start_frida()
        context = {
            'checksum': checksum,
            'device_id': device_id,
            'bundle_id': bundleid,
            'version': settings.MOBSF_VER,
            'form': form,
            'title': 'iOS Device Dynamic Analyzer'}
        template = 'dynamic_analysis/ios/device/dynamic_analyzer.html'
        if api:
            return context
        return render(request, template, context)
    except Exception:
        logger.exception('iOS Device Dynamic Analyzer')
        return print_n_send_error_response(
            request,
            'iOS Device Dynamic Analysis Failed.',
            api)


# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def ios_instrument_device(request, api=False):
    """Instrument app with frida."""
    data = {
        'status': FAILED,
        'message': ''}
    try:
        action = request.POST.get('frida_action', 'spawn')
        pid = request.POST.get('pid')
        new_bundle_id = request.POST.get('new_bundle_id')
        device_id = request.POST['device_id']
        bundle_id = request.POST['bundle_id']
        md5_hash = get_md5(bundle_id.encode('utf-8'))
        default_hooks = request.POST['default_hooks']
        dump_hooks = request.POST['dump_hooks']
        auxiliary_hooks = request.POST['auxiliary_hooks']
        code = request.POST['frida_code']

        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        if new_bundle_id and not strict_package_check(new_bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)

        # Fill extras
        extras = {}
        screenshot_action = request.POST.get('screenshot_action')
        if screenshot_action:
            extras['screenshot_action'] = screenshot_action.strip()
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
        frida_obj = FridaIOSDevice(
            ios_device,
            None,
            md5_hash,
            bundle_id,
            default_hooks.split(','),
            dump_hooks.split(','),
            auxiliary_hooks.split(','),
            extras,
            code)
        if action == 'run':
            frida_obj.run_app()
        if action == 'spawn':
            logger.info('Starting Instrumentation')
            frida_obj.spawn()
        elif action == 'ps':
            logger.info('Enumerating running applications')
            data['message'] = frida_obj.ps()
        elif action == 'get':
            # Get injected Frida script.
            data['message'] = frida_obj.get_script(nolog=True)
        elif action == 'capture':
            # Capture screenshot
            Thread(target=download_screenshot, args=(ios_device, md5_hash), daemon=True).start()

        if action in ('spawn', 'session', 'capture'):
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
        data['message'] = str(exp)
    return send_response(data, api)


# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def ssh_execute_device(request, api=False):
    """Execute commands in iOS device over SSH."""
    data = {
        'status': FAILED,
        'message': 'Failed to execute command'}
    try:
        device_id = request.POST['device_id']
        cmd = request.POST['cmd']
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        out, err, _ = ios_device.execute_command(cmd)
        message = f'{out}\n{err}'
        data['status'] = OK
        data['message'] = message
    except Exception as exp:
        data['message'] = str(exp)
        logger.exception('Executing Commands in iOS device')
    return send_response(data, api)


# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def upload_file_device(request, api=False):
    """Upload file to device."""
    err_msg = 'Failed to upload file'
    data = {
        'status': FAILED,
        'message': err_msg,
    }
    try:
        device_id = request.POST['device_id']
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            fobject = request.FILES['file']
            upload = ios_device.upload_file_object(
                fobject, fobject.name)
            if upload:
                data['status'] = OK
                data['message'] = 'Successfully uploaded file'
            else:
                data['message'] = 'Failed to upload file'
    except Exception as exp:
        logger.exception(err_msg)
        data['message'] = str(exp)
    return send_response(data, api)
   

# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST', 'GET'])
def system_logs_device(request, api=False):
    """Show system logs."""
    data = {
        'status': FAILED,
        'message': 'Failed to get system logs',
    }
    try:
        pid = request.GET.get('pid')
        if request.method == 'POST':
            device_id = request.POST['device_id']
            if pid and not pid.isdigit():
                data['message'] = 'Invalid PID'
                return send_response(data, api)
            ios_device, error = validate_and_connect_device(device_id)
            if error:
                data['message'] = error
                return send_response(data, api)
            cmd = 'oslog'
            if pid:
                cmd = f'oslog -p {pid}'
            out, err, _ = ios_device.execute_command(cmd, timeout=9)
            message = f'{out}\n{err}'
            data['status'] = OK
            data['message'] = message
            return send_response(data, api)
        # GET request
        logger.info('Getting logs')
        device_id = request.GET['device_id']
        if pid and not pid.isdigit():
            data['message'] = 'Invalid PID'
            return send_response(data, api)
        usb = IOS_DEVICE_ID_REGEX.match(device_id)
        wifi = SSH_DEVICE_ID_REGEX.match(device_id)
        if not (usb or wifi):
            data['message'] = 'Invalid device id or SSH connection string format'
            return send_response(data, api)
        template = 'dynamic_analysis/ios/device/system_logs.html'
        return render(request,
                      template,
                      {'device_id': device_id,
                       'pid': pid,
                       'version': settings.MOBSF_VER,
                       'title': 'Live logs'})
    except Exception as exp:
        logger.exception('Getting logs')
        data['message'] = str(exp)
    return send_response(data, api)


# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def ps_device(request, api=False):
    """Get list of running processes on iOS device."""
    data = {
        'status': FAILED,
        'message': 'Failed to get process list',
    }
    try:
        device_id = request.POST.get('device_id', '')
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        processes = ios_device.ps()
        if processes:
            data['status'] = OK
            data['message'] = processes
        else:
            data['message'] = 'No processes found'
            
    except Exception as exp:
        logger.exception('Getting process list failed')
        data['message'] = str(exp)
    return send_response(data, api)


# JSON API    
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def get_ios_device(request, api=False):
    """Get details of selected iOS device."""
    data = {
        'status': 'failed',
        'message': 'Failed to connect to iOS device',
    }
    try:
        device_id = request.POST.get('device_id', '')
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        data['apps'] = ios_device.list_applications()
        data['status'] = OK
        data['message'] = 'Successfully connected to iOS device'
    except Exception:
        logger.exception('Failed to connect to iOS device')
    return send_response(data, api)


# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def install_ipa_device(request, api=False):
    """Install an IPA file on the device."""
    data = {
        'status': 'failed',
        'message': 'Failed to install IPA on device',
    }
    try:
        device_id = request.POST.get('device_id', '')
        # Checksum from IPA SAST Upload location
        checksum = request.POST.get('checksum', '')
        if not is_md5(checksum):
            data['message'] = 'Invalid checksum format'
            return send_response(data, api)
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        if not ios_device.install_ipa(checksum):
            data['message'] = 'Failed to install IPA'
            return send_response(data, api)
        data['status'] = OK
        data['message'] = f'Successfully installed IPA'
    except Exception:
        logger.exception('Failed to install IPA on iOS device')
    return send_response(data, api)


# Helpers
def get_ios_devices_over_wifi():
    """Get available iOS devices over WiFi."""
    devices = []
    connect_strings = None
    connect_strings_settings = getattr(settings, 'IOS_ANALYZER_IDENTIFIERS', '')
    if os.getenv('MOBSF_IOS_ANALYZER_IDENTIFIERS'):
        connect_strings = os.getenv('MOBSF_IOS_ANALYZER_IDENTIFIERS')
    elif connect_strings_settings:
        connect_strings = connect_strings_settings
    try:
        if not connect_strings:
            return devices
        if ',' in connect_strings:
            # Multiple devices
            for device in connect_strings.split(','):
                devices.append(parse_host_port(device.strip()))
        else:
            # Single device
            devices.append(parse_host_port(connect_strings.strip()))
    except ValueError:
        pass
    return devices


def get_ios_device_wifi_connect_string(ssh_string):
    """Get iOS device connect string."""
    available_devices = get_ios_devices_over_wifi()
    if not ssh_string:
        return None, None
    ip, port = parse_host_port(ssh_string)
    if (ip, port) in available_devices:
        return ip, port
    return None, None


def download_screenshot(ios_device, checksum):
    """Download screenshot from device."""
    try:
        time.sleep(5)
        timestamp = time.strftime("%Y%m%d%H%M%S")
        path = Path(settings.DWD_DIR) / f'{checksum}-sshot-{timestamp}.png'
        ios_device.download_file("/tmp/screenshot.png", path)
    except Exception as exp:
        logger.error('Failed to download screenshot from iOS device')
        logger.error(exp)

def validate_and_connect_device(device_id):
    """Validate device_id and establish connection to iOS device."""
    usb = IOS_DEVICE_ID_REGEX.match(device_id)
    wifi = SSH_DEVICE_ID_REGEX.match(device_id)
    if not (usb or wifi):
        return None, 'Invalid device id or SSH connection string format'
    
    connector = IOSConnector()
    if usb:
        connected = connector.connect_usb(device_id)
        if not connected:
            return None, 'Failed to connect to iOS device over USB'
    else:
        ip, port = get_ios_device_wifi_connect_string(device_id)
        connected = connector.connect_wifi(ip, port)
        if not connected:
            return None, 'Failed to connect to iOS device over WiFi'
    ios_device = IOSDevice(connector)
    
    return ios_device, None
