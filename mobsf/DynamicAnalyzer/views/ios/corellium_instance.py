# -*- coding: utf_8 -*-
"""Instance Operation APIs."""
import logging
import re
import shutil
import time
from base64 import b64encode
from pathlib import Path

from paramiko.ssh_exception import SSHException

from django.conf import settings
from django.views.decorators.http import require_http_methods
from django.http import (
    HttpResponse,
)
from django.shortcuts import (
    render,
)

from mobsf.MobSF.utils import (
    common_check,
    get_md5,
    id_generator,
    is_md5,
    print_n_send_error_response,
    strict_package_check,
)
from mobsf.DynamicAnalyzer.forms import UploadFileForm
from mobsf.DynamicAnalyzer.tools.webproxy import (
    get_http_tools_url,
    stop_httptools,
)
from mobsf.DynamicAnalyzer.views.common.shared import (
    send_response,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_ssh import (
    ssh_execute_cmd,
    ssh_file_download,
    ssh_file_upload,
    ssh_jump_host,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_apis import (
    CorelliumAPI,
    CorelliumAgentAPI,
    CorelliumInstanceAPI,
    CorelliumModelsAPI,
    OK,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.MobSF.views.authorization import (
    Permissions,
    permission_required,
)

logger = logging.getLogger(__name__)


# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def start_instance(request, api=False):
    """Start iOS VM instance."""
    logger.info('Starting iOS VM instance')
    data = {
        'status': 'failed',
        'message': 'Failed to start instance'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        r = ci.start_instance()
        if r == OK:
            data = {
                'status': OK,
                'message': 'Starting VM Instance'}
        elif r:
            data['message'] = r
    except Exception as exp:
        logger.exception('Start iOS VM instance')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def stop_instance(request, api=False):
    """Stop iOS VM instance."""
    logger.info('Stopping iOS VM instance')
    data = {
        'status': 'failed',
        'message': 'Failed to stop instance'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        r = ci.stop_instance()
        if r == OK:
            data = {
                'status': OK,
                'message': 'Instance stopped'}
        elif r:
            data['message'] = r
    except Exception as exp:
        logger.exception('Stopping iOS VM instance')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def unpause_instance(request, api=False):
    """Unpause iOS VM instance."""
    logger.info('Unpausing iOS VM instance')
    data = {
        'status': 'failed',
        'message': 'Failed to unpause instance'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        r = ci.unpause_instance()
        if r == OK:
            data = {
                'status': OK,
                'message': 'Instance unpaused'}
        elif r:
            data['message'] = r
    except Exception as exp:
        logger.exception('Unpausing iOS VM instance')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def reboot_instance(request, api=False):
    """Reboot iOS VM instance."""
    logger.info('Rebooting iOS VM instance')
    data = {
        'status': 'failed',
        'message': 'Failed to reboot instance'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        r = ci.reboot_instance()
        if r == OK:
            data = {
                'status': OK,
                'message': 'Rebooting instance'}
        elif r:
            data['message'] = r
    except Exception as exp:
        logger.exception('Rebooting iOS VM instance')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def destroy_instance(request, api=False):
    """Destroy iOS VM instance."""
    logger.info('Destroying iOS VM instance')
    data = {
        'status': 'failed',
        'message': 'Failed to destroy instance'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        r = ci.remove_instance()
        if r == OK:
            data = {
                'status': OK,
                'message': 'Destroying instance'}
        elif r:
            data['message'] = r
    except Exception as exp:
        logger.exception('Destroying iOS VM instance')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def list_apps(request, api=False):
    """List installed apps."""
    logger.info('Listing installed applications')
    data = {
        'status': 'failed',
        'message': 'Failed to list installed apps'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ca = CorelliumAgentAPI(instance_id)
        # Get apps in device
        r = ca.list_apps()
        app_list = []
        bundle_ids = []
        if r and r.get('apps'):
            for i in r.get('apps'):
                bundle = i['bundleID']
                bundle_ids.append(f'bundleID={bundle}')
        elif r and r.get('error'):
            data['message'] = r.get('error')
            verbose = r.get('originalError')
            if verbose:
                data['message'] += f' {verbose}'
            return send_response(data, api)
        else:
            data['message'] = 'Failed to list apps'
            return send_response(data, api)
        # Get app icons
        logger.info('Getting all application icons')
        ic = ca.get_icons('&'.join(bundle_ids))
        for i in r.get('apps'):
            bundleid = i['bundleID']
            checksum = get_md5(bundleid.encode('utf-8'))
            dump_file = Path(
                settings.UPLD_DIR) / checksum / 'mobsf_dump_file.txt'
            if ic and ic.get('icons'):
                icon_url = ic['icons'].get(bundleid)
            else:
                icon_url = ''
            app_list.append({
                'applicationType': i['applicationType'],
                'name': i['name'],
                'bundleID': bundleid,
                'icon': icon_url,
                'checksum': checksum,
                'reportExists': dump_file.exists(),
            })
        data = {
            'status': OK,
            'message': app_list}

    except Exception as exp:
        logger.exception('Listing installed apps')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def get_supported_models(request, api=False):
    """Get Supported iOS VM models."""
    data = {
        'status': 'failed',
        'message': 'Failed to obtain iOS models'}
    try:
        cm = CorelliumModelsAPI()
        r = cm.get_models()
        if r:
            data = {'status': OK, 'message': r}
    except Exception as exp:
        logger.exception('Obtaining iOS models')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def get_supported_os(request, api=False):
    """Get Supported iOS OS versions."""
    data = {
        'status': 'failed',
        'message': 'Failed to obtain iOS versions'}
    try:
        model = request.POST['model']
        cm = CorelliumModelsAPI()
        r = cm.get_supported_os(model)
        if r:
            data = {'status': OK, 'message': r}
    except Exception as exp:
        logger.exception('Obtaining iOS versions')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def create_vm_instance(request, api=False):
    """Create and iOS VM in Corellium."""
    logger.info('Creating Corellium iOS VM instance')
    data = {
        'status': 'failed',
        'message': 'Failed to create an iOS VM'}
    try:
        project_id = request.POST['project_id']
        flavor = request.POST['flavor']
        version = request.POST['version']
        name = request.POST.get('name')
        if not name:
            name = 'MobSF iOS'
        if not re.match(r'^[a-zA-Z0-9 _-]+$', name):
            data['message'] = (
                'Invalid VM name. '
                'Can only contain '
                'letters, numbers, '
                'spaces, hyphens, '
                'and underscores')
            return send_response(data, api)
        if not re.match(r'^iphone\d*\w+', flavor):
            data['message'] = 'Invalid iOS flavor'
            return send_response(data, api)
        if not re.match(r'^\d+\.\d+\.*\d*', version):
            data['message'] = 'Invalid iOS version'
            return send_response(data, api)
        failed = common_check(project_id)
        if failed:
            return send_response(failed, api)
        c = CorelliumAPI(project_id)
        r = c.create_ios_instance(name, flavor, version)
        if r:
            data = {
                'status': OK,
                'message': f'Created a new instance with id: {r}'}
    except Exception as exp:
        logger.exception('Creating Corellium iOS VM')
        data['message'] = str(exp)
    return send_response(data, api)
# Helpers for AppSync Install Check & IPA Install


def check_appsync(target):
    """Check and install AppSync Unified."""
    check_install = 'apt list --installed | grep \'ai.akemi.appinst\''
    # Check if AppSync Unified is installed
    out = ssh_execute_cmd(target, check_install)
    if 'ai.akemi.appinst' not in out:
        # Install AppSync Unified
        logger.info('AppSync Unified is not installed. '
                    'Attempting to install...')
        src_file = '/etc/apt/sources.list.d/cydia.list'
        src = 'deb https://cydia.akemi.ai/ ./'
        install_cmds = [
            f'grep -qxF \'{src}\' {src_file} || echo \'{src}\' >> {src_file}',
            'apt update',
            'apt install -y --allow-unauthenticated ai.akemi.appinst',
            'launchctl reboot userspace',
        ]
        for i in install_cmds:
            out = ssh_execute_cmd(target, i)
            logger.info(out)
        logger.info('Please wait for 15 seconds for the userspace to reboot.')
        time.sleep(15)


def appsync_ipa_install(ssh_string):
    """Install app using AppSync Unified."""
    target, jumpbox = ssh_jump_host(ssh_string)
    # AppSync Unified install check
    check_appsync(target)   # This will terminate SSH session
    if target:
        target.close()
    if jumpbox:
        jumpbox.close()
    # Install IPA with AppSync United
    logger.info('Attempting to install the IPA '
                'using AppSync Unified.')
    target, jumpbox = ssh_jump_host(ssh_string)
    out = ssh_execute_cmd(target, 'appinst /tmp/app.ipa')
    target.close()
    jumpbox.close()
    if 'Successfully installed' not in out:
        logger.error('AppSync IPA Install Failed.\n%s', out)
        return out
    logger.info(out)
    return OK
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def setup_environment(request, checksum, api=False):
    """Setup iOS Dynamic Analyzer Environment."""
    data = {
        'status': 'failed',
        'message': 'Failed to Setup Dynamic Analysis Environment'}
    try:
        if not is_md5(checksum):
            # Additional Check for REST API
            data['message'] = 'Invalid Hash'
            return send_response(data, api)
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ca = CorelliumAgentAPI(instance_id)
        if not ca.agent_ready():
            data['message'] = (
                f'Agent is not ready with {instance_id}'
                ', please wait.')
            return send_response(data, api)
        # Unlock iOS Device
        ca.unlock_device()
        # Upload IPA
        ipa_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.ipa'
        msg = ca.upload_ipa(ipa_path)
        if msg != OK:
            data['message'] = msg
            return send_response(data, api)
        # Install IPA
        msg = ca.install_ipa()
        if msg != OK:
            if 'Please re-sign.' in msg:
                # Try AppSync IPA Install
                ci = CorelliumInstanceAPI(instance_id)
                out = appsync_ipa_install(ci.get_ssh_connection_string())
                if out and out != OK:
                    data['message'] = out
                    return send_response(data, api)
            else:
                # Other install errors
                data['message'] = msg
                return send_response(data, api)
        msg = 'Testing Environment is Ready!'
        logger.info(msg)
        data['status'] = OK
        data['message'] = msg
    except Exception as exp:
        logger.exception('Creating iOS Dynamic Analyzer Environment')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def run_app(request, api=False):
    """Run an App."""
    data = {
        'status': 'failed',
        'message': 'Failed to run the app'}
    try:
        instance_id = request.POST['instance_id']
        bundle_id = request.POST['bundle_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        ca = CorelliumAgentAPI(instance_id)
        if (ca.agent_ready()
                and ca.unlock_device()
                and ca.run_app(bundle_id) == OK):
            data['status'] = OK
            data['message'] = 'App Started'
    except Exception as exp:
        logger.exception('Failed to run the app')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def stop_app(request, api=False):
    """Stop an App."""
    data = {
        'status': 'failed',
        'message': 'Failed to stop the app'}
    try:
        instance_id = request.POST['instance_id']
        bundle_id = request.POST['bundle_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        ca = CorelliumAgentAPI(instance_id)
        if (ca.agent_ready()
                and ca.unlock_device()
                and ca.stop_app(bundle_id) == OK):
            data['status'] = OK
            data['message'] = 'App Killed'
    except Exception as exp:
        logger.exception('Failed to stop the app')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def remove_app(request, api=False):
    """Remove an app from the device."""
    data = {
        'status': 'failed',
        'message': 'Failed to uninstall the app'}
    try:
        instance_id = request.POST['instance_id']
        bundle_id = request.POST['bundle_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        ca = CorelliumAgentAPI(instance_id)
        if (ca.agent_ready()
                and ca.remove_app(bundle_id) == OK):
            data['status'] = OK
            data['message'] = 'App uninstalled'
    except Exception as exp:
        logger.exception('Failed to uninstall the app')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def take_screenshot(request, api=False):
    """Take a Screenshot."""
    data = {
        'status': 'failed',
        'message': 'Failed to take screenshot'}
    try:
        instance_id = request.POST['instance_id']
        save = request.POST.get('save')
        checksum = request.POST.get('checksum')
        dwd = Path(settings.DWD_DIR)
        if save and checksum:
            if not is_md5(checksum):
                data['message'] = 'Invaid MD5 Hash'
                return send_response(data, api)
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        r = ci.screenshot()
        if r:
            data['status'] = OK
            if save == '1':
                sfile = dwd / f'{checksum}-sshot-{id_generator()}.png'
                sfile.write_bytes(r)
                data['message'] = 'Screenshot saved!'
            else:
                b64dat = b64encode(r).decode('utf-8')
                data['message'] = f'data:image/png;base64,{b64dat}'
    except Exception as exp:
        logger.exception('Failed to take screenshot')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def get_container_path(request, api=False):
    """Get App Container path."""
    err_msg = 'Failed to get app container path'
    data = {
        'status': 'failed',
        'message': err_msg}
    try:
        bundle_id = request.POST['bundle_id']
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        checksum = get_md5(bundle_id.encode('utf-8'))
        cfile = 'mobsf_app_container_path.txt'
        acfile = Path(settings.UPLD_DIR) / checksum / cfile
        if acfile.exists():
            data['status'] = OK
            data['message'] = acfile.read_text(
                'utf-8').splitlines()[0].strip()
    except Exception as exp:
        logger.exception(err_msg)
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def network_capture(request, api=False):
    """Enable/Disable Network Capture."""
    data = {
        'status': 'failed',
        'message': 'Failed to enable/disable network capture'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        state = request.POST.get('state')
        if state == 'on':
            msg = 'Enabled'
            logger.info('Enabling Network Capture')
            r = ci.start_network_capture()
        else:
            msg = 'Disabled'
            logger.info('Disabling Network Capture')
            r = ci.stop_network_capture()
        if r != OK:
            data['message'] = r
            return send_response(data, api)
        else:
            data = {
                'status': OK,
                'message': f'{msg} network capture'}
    except Exception as exp:
        logger.exception('Enabling/Disabling network capture')
        data['message'] = str(exp)
    return send_response(data, api)
# File Download


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['GET', 'POST'])
def live_pcap_download(request, api=False):
    """Download Network Capture."""
    data = {
        'status': 'failed',
        'message': 'Failed to download network capture'}
    try:
        if api:
            instance_id = request.POST['instance_id']
        else:
            instance_id = request.GET['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        pcap = ci.download_network_capture()
        if pcap:
            res = HttpResponse(
                pcap,
                content_type='application/vnd.tcpdump.pcap')
            res['Content-Disposition'] = (
                f'inline; filename={instance_id}-network.pcap')
            return res
        else:
            data['message'] = 'Failed to download pcap'
    except Exception as exp:
        logger.exception('Download network capture')
        data['message'] = str(exp)
    return send_response(data, api)


# AJAX
SSH_TARGET = None


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def ssh_execute(request, api=False):
    """Execute commands in VM over SSH."""
    global SSH_TARGET
    res = ''
    data = {
        'status': 'failed',
        'message': 'Failed to execute command'}
    try:
        instance_id = request.POST['instance_id']
        cmd = request.POST['cmd']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        if not SSH_TARGET:
            logger.info('Setting up SSH tunnel')
            SSH_TARGET, _jmp = ssh_jump_host(
                ci.get_ssh_connection_string())
        try:
            res = ssh_execute_cmd(SSH_TARGET, cmd)
        except SSHException:
            logger.info('SSH session not active, setting up again')
            SSH_TARGET, _jmp = ssh_jump_host(
                ci.get_ssh_connection_string())
            res = ssh_execute_cmd(SSH_TARGET, cmd)
        data = {'status': OK, 'message': res}
    except Exception as exp:
        data['message'] = str(exp)
        logger.exception('Executing Commands')
    return send_response(data, api)
# Helper Download app data tarfile


def download_app_data(ci, checksum):
    """Download App data from device."""
    app_dir = Path(settings.UPLD_DIR) / checksum
    container_file = app_dir / 'mobsf_app_container_path.txt'
    if container_file.exists():
        app_container = container_file.read_text(
            'utf-8').splitlines()[0].strip()
        target, jumpbox = ssh_jump_host(
            ci.get_ssh_connection_string())
        tarfile = f'/tmp/{checksum}-app-container.tar'
        localtar = app_dir / f'{checksum}-app-container.tar'
        ssh_execute_cmd(
            target, f'tar -C {app_container} -cvf {tarfile} .')
        with target.open_sftp() as sftp:
            sftp.get(tarfile, localtar)
        target.close()
        jumpbox.close()
        if localtar.exists():
            dst = Path(settings.DWD_DIR) / f'{checksum}-app_data.tar'
            shutil.copyfile(localtar, dst)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def download_data(request, bundle_id, api=False):
    """Download Application Data from Device."""
    logger.info('Downloading application data')
    data = {
        'status': 'failed',
        'message': 'Failed to Download application data'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        ci = CorelliumInstanceAPI(instance_id)
        checksum = get_md5(bundle_id.encode('utf-8'))
        # App Container download
        logger.info('Downloading app container data')
        download_app_data(ci, checksum)
        # Stop HTTPS Proxy
        stop_httptools(get_http_tools_url(request))
        # Move HTTP raw logs to download directory
        flows = Path.home() / '.httptools' / 'flows'
        webf = flows / f'{bundle_id}.flow.txt'
        dwd = Path(settings.DWD_DIR)
        dweb = dwd / f'{checksum}-web_traffic.txt'
        if webf.exists():
            shutil.copyfile(webf, dweb)
        # Pcap download
        logger.info('Downloading network capture')
        pcap = ci.download_network_capture()
        if pcap:
            dwd = Path(settings.DWD_DIR)
            pcap_file = dwd / f'{checksum}-network.pcap'
            pcap_file.write_bytes(pcap)
            data = {
                'status': OK,
                'message': 'Downloaded application data',
            }
        else:
            data['message'] = 'Failed to download pcap'
            return send_response(data, api)
    except Exception as exp:
        logger.exception('Downloading application data')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def touch(request, api=False):
    """Sending Touch/Swipe/Text Events."""
    data = {
        'status': 'failed',
        'message': '',
    }
    try:
        x_axis = request.POST.get('x')
        y_axis = request.POST.get('y')
        event = request.POST.get('event')

        max_x = request.POST.get('max_x', 0)
        max_y = request.POST.get('max_y', 0)
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        res = ci.device_input(
            event,
            x_axis,
            y_axis,
            max_x,
            max_y)
        if res != 'ok':
            data['message'] = res
        else:
            data = {'status': 'ok'}
    except Exception as exp:
        logger.exception('Sending Touchscreen Events')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX + HTML


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST', 'GET'])
def system_logs(request, api=False):
    """Show system logs."""
    data = {
        'status': 'failed',
        'message': 'Failed to get system logs',
    }
    try:
        if request.method == 'POST':
            instance_id = request.POST['instance_id']
            failed = common_check(instance_id)
            if failed:
                return send_response(failed, api)
            ci = CorelliumInstanceAPI(instance_id)
            data = {'status': 'ok', 'message': ci.console_log()}
            return send_response(data, api)
        logger.info('Getting system logs')
        instance_id = request.GET['instance_id']
        failed = common_check(instance_id)
        if failed:
            return print_n_send_error_response(
                request, failed['message'], api)
        template = 'dynamic_analysis/ios/system_logs.html'
        return render(request,
                      template,
                      {'instance_id': instance_id,
                       'version': settings.MOBSF_VER,
                       'title': 'Live System logs'})
    except Exception as exp:
        err = 'Getting system logs'
        logger.exception(err)
        if request.method == 'POST':
            data['message'] = str(exp)
            return send_response(data, api)
        return print_n_send_error_response(request, err, api)
# AJAX


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def upload_file(request, api=False):
    """Upload file to device."""
    err_msg = 'Failed to upload file'
    data = {
        'status': 'failed',
        'message': err_msg,
    }
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            ci = CorelliumInstanceAPI(instance_id)
            fobject = request.FILES['file']
            ssh_file_upload(
                ci.get_ssh_connection_string(),
                fobject,
                fobject.name)
            data = {'status': 'ok'}
    except Exception as exp:
        logger.exception(err_msg)
        data['message'] = str(exp)
    return send_response(data, api)
# File Download


@login_required
@permission_required(Permissions.SCAN)
@require_http_methods(['POST'])
def download_file(request, api=False):
    """Download file from device."""
    try:
        global SSH_TARGET
        instance_id = request.POST['instance_id']
        rfile = request.POST['file']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        ci = CorelliumInstanceAPI(instance_id)
        if not SSH_TARGET:
            logger.info('Setting up SSH tunnel')
            SSH_TARGET, _jmp = ssh_jump_host(
                ci.get_ssh_connection_string())
        try:
            fl = ssh_file_download(SSH_TARGET, rfile)
        except SSHException:
            logger.info('SSH session not active, setting up again')
            SSH_TARGET, _jmp = ssh_jump_host(
                ci.get_ssh_connection_string())
            fl = ssh_file_download(SSH_TARGET, rfile)
        if not fl:
            fl = b'File not found'
    except Exception:
        logger.exception('Failed to download file')
    response = HttpResponse(fl, content_type='application/octet-stream')
    response['Content-Disposition'] = f'inline; filename={Path(rfile).name}'
    return response
