# -*- coding: utf_8 -*-
"""Dynamic Analyzer Reporting for iOS devices."""
import logging
import shutil
from pathlib import Path
import json

from django.conf import settings
from django.shortcuts import render
from django.template.defaulttags import register
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
from mobsf.DynamicAnalyzer.views.ios.analysis import (
    get_screenshots,
    ios_api_analysis,
    run_analysis,
)
from mobsf.DynamicAnalyzer.views.ios.device.dynamic_analyzer import (
    validate_and_connect_device,
    OK,
    FAILED,
)
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    stop_httptools,
)
from mobsf.MobSF.utils import (
    base64_decode,
    is_md5,
    get_md5,
    key,
    pretty_json,
    print_n_send_error_response,
    replace,
    strict_package_check,
    IOS_DEVICE_ID_REGEX,
    SSH_DEVICE_ID_REGEX,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)


logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('replace', replace)
register.filter('pretty_json', pretty_json)
register.filter('base64_decode', base64_decode)


def download_app_data_device(ios_device, checksum):
    """Download App data from device."""
    app_dir = Path(settings.UPLD_DIR) / checksum
    container_file = app_dir / 'mobsf_app_container_path.txt'
    if container_file.exists():
        app_container = container_file.read_text(
            'utf-8').splitlines()[0].strip()
        tarfile = f'/tmp/{checksum}-app-container.tar'
        localtar = app_dir / f'{checksum}-app-container.tar'
        ios_device.execute_command(f'tar -C {app_container} -cvf {tarfile} .')
        ios_device.download_file(tarfile, localtar)
        if localtar.exists():
            dst = Path(settings.DWD_DIR) / f'{checksum}-app_data.tar'
            shutil.copyfile(localtar, dst)

# JSON API
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def download_data_device(request, bundle_id, api=False):
    """Download Application Data from Device."""
    logger.info('Downloading application data')
    data = {
        'status': FAILED,
        'message': 'Failed to Download application data'}
    try:
        device_id = request.POST['device_id']
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        checksum = get_md5(bundle_id.encode('utf-8'))
        # App Container download
        logger.info('Downloading app container data')
        download_app_data_device(ios_device, checksum)
        # Stop HTTPS Proxy
        stop_httptools(get_http_tools_url(request))
        # Move HTTP raw logs to download directory
        flows = Path.home() / '.httptools' / 'flows'
        webf = flows / f'{bundle_id}.flow.txt'
        dwd = Path(settings.DWD_DIR)
        dweb = dwd / f'{checksum}-web_traffic.txt'
        if webf.exists():
            shutil.copyfile(webf, dweb)
        data = {
            'status': OK,
            'message': 'Downloaded application data',
        }
    except Exception as exp:
        logger.exception('Downloading application data')
        data['message'] = str(exp)
    return send_response(data, api)


@login_required
def view_report_device(request, bundle_id, api=False):
    """Dynamic Analysis Report Generation."""
    logger.info('iOS Dynamic Analysis Report Generation')
    try:
        if api:
            device_id = request.POST.get('device_id')
        else:
            device_id = request.GET.get('device_id')
        if device_id:
            usb = IOS_DEVICE_ID_REGEX.match(device_id)
            wifi = SSH_DEVICE_ID_REGEX.match(device_id)
            if not (usb or wifi):
                return print_n_send_error_response(
                    request,
                    'Invalid device id or SSH connection string format',
                    api)
        if not strict_package_check(bundle_id):
            # bundle_id is not validated in REST API.
            # Also bundleid is not strictly validated
            # in URL path.
            return print_n_send_error_response(
                request,
                'Invalid iOS Bundle id',
                api)
        checksum = get_md5(bundle_id.encode('utf-8'))
        app_dir = Path(settings.UPLD_DIR) / checksum
        download_dir = settings.DWD_DIR
        tools_dir = settings.TOOLS_DIR
        frida_log = app_dir / 'mobsf_frida_out.txt'
        data_dir = app_dir / 'DYNAMIC_DeviceData'
        if not (frida_log.exists() or data_dir.exists()):
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg, api)
        api_analysis = ios_api_analysis(app_dir)
        dump_analysis = run_analysis(app_dir, bundle_id, checksum)
        trk = Trackers.Trackers(checksum, app_dir, tools_dir)
        trackers = trk.get_trackers_domains_or_deps(
            dump_analysis['domains'], None)
        screenshots = get_screenshots(checksum, download_dir)
        logger.info('Report generation completed')
        context = {
            'hash': checksum,
            'device_id': device_id,
            'version': settings.MOBSF_VER,
            'title': 'iOS Dynamic Analysis Report',
            'bundleid': bundle_id,
            'trackers': trackers,
            'screenshots': screenshots,
            'frida_logs': frida_log.exists(),
        }
        context.update(api_analysis)
        context.update(dump_analysis)
        template = 'dynamic_analysis/ios/device/dynamic_report.html'
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        logger.exception('Dynamic Analysis Report Generation')
        err = f'Error Generating Dynamic Analysis Report. {str(exp)}'
        return print_n_send_error_response(request, err, api)


# JSON API + File Download
@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def download_file_device(request, api=False):
    """Download file from device."""
    err_msg = 'Failed to download file'
    data = {
        'status': FAILED,
        'message': err_msg,
    }
    try:
        remote_path = request.POST['file']
        device_id = request.POST['device_id']
        ios_device, error = validate_and_connect_device(device_id)
        if error:
            data['message'] = error
            return send_response(data, api)
        fo = ios_device.download_file_object(remote_path)
        if fo:
            response = HttpResponse(fo, content_type='application/octet-stream')
            response['Content-Disposition'] = f'inline; filename={Path(remote_path).name}'
            return response
        else:
            data['message'] = 'Failed to download file'
    except Exception as exp:
        logger.exception(err_msg)
        data['message'] = str(exp)
    return send_response(data, api)


# JSON API
@login_required
def ios_api_monitor(request, api=False):
    try:
        data = {
            'status': FAILED,
            'message': 'Failed to get API monitor data',
        }
        if api:
            checksum = request.POST['checksum']
            stream = True
        else:
            checksum = request.GET.get('checksum', '')
            stream = request.GET.get('stream', '')
        bundle_id = request.GET.get('bundle_id', '')
        if bundle_id and not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        if not is_md5(checksum):
            data['message'] = 'Invalid checksum format'
            return send_response(data, api)
        if stream:
            app_dir = Path(settings.UPLD_DIR) / checksum
            apimon_file = app_dir / 'mobsf_dump_file.txt'
            data = {}
            if not apimon_file.exists():
                data['message'] = 'Data does not exist.'
                return send_response(data, api)
            # Read the file and parse each line as JSON
            lines = apimon_file.read_text(encoding='utf-8').splitlines()
            # remove all duplicate lines
            lines = list(set(lines))
            api_data = []
            
            for line in lines:
                if line.strip():
                    try:
                        # Parse each line as JSON
                        json_obj = json.loads(line)
                        
                        # Determine the API type based on the keys in the JSON object
                        api_type = None
                        if 'cookies' in json_obj:
                            api_type = 'Cookies'
                        elif 'keychain' in json_obj:
                            api_type = 'Keychain'
                        elif 'json' in json_obj:
                            api_type = 'JSON Data'
                        elif 'network' in json_obj:
                            api_type = 'Network Request'
                        elif 'sql' in json_obj:
                            api_type = 'SQL Query'
                        elif 'filename' in json_obj:
                            api_type = 'File Access'
                        elif 'crypto' in json_obj:
                            api_type = 'Crypto'
                        elif 'files' in json_obj:
                            api_type = 'Files'
                        elif 'nslog' in json_obj:
                            api_type = 'Logs'
                        elif 'credentialstorage' in json_obj:
                            api_type = 'Credentials'
                        elif 'nsuserdefaults' in json_obj:
                            api_type = 'UserDefaults'
                        elif 'pasteboard' in json_obj:
                            api_type = 'Pasteboard'
                        elif 'textinput' in json_obj:
                            api_type = 'Text Inputs'
                        elif 'datadir' in json_obj:
                            api_type = 'Data Directory'
                        else:
                            # If no known key, use the first key as API type
                            api_type = list(json_obj.keys())[0] if json_obj else 'Unknown'
                        
                        # Create the data object for DataTable
                        api_data.append({
                            'api': api_type,
                            'data': json_obj
                        })
                    except json.JSONDecodeError:
                        # Skip invalid JSON lines
                        continue
            
            data['data'] = api_data
            return send_response(data, api)
        template = 'dynamic_analysis/ios/api_monitor.html'
        return render(request,
                      template,
                      {'checksum': checksum,
                       'bundle_id': bundle_id,
                       'version': settings.MOBSF_VER,
                       'title': 'API Monitor'})
    except Exception:
        logger.exception('API monitor streaming')
        err = 'Error in API monitor streaming'
        return print_n_send_error_response(request, err, api)
