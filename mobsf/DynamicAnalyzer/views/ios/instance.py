# -*- coding: utf_8 -*-
"""Instance Operation APIs."""

import json
import logging
import os
import random
import re
import subprocess
import threading
from base64 import b64encode
from pathlib import Path

from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.core.signing import (
    BadSignature,
    Signer)

from mobsf.MobSF.utils import (
    cmd_injection_check,
    get_adb,
    get_device,
    is_md5,
    is_number,
    strict_package_check,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    invalid_params,
    is_attack_pattern,
    send_response,
)
from mobsf.DynamicAnalyzer.views.ios.utils import (
    common_check,
    SALT,
)
from mobsf.DynamicAnalyzer.views.ios.corellium_apis import (
    CorelliumAPI,
    CorelliumAgentAPI,
    CorelliumInstanceAPI,
    CorelliumModelsAPI,
    OK,
)
from mobsf.StaticAnalyzer.models import StaticAnalyzerIOS



logger = logging.getLogger(__name__)


# AJAX


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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
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


@require_http_methods(['POST'])
def list_apps(request, api=False):
    """List installed apps."""
    logger.info('Listing installed apps')
    data = {
        'status': 'failed',
        'message': 'Failed to list installed apps'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
        r = ci.list_apps()
        if r and r.get('apps'):
            data = {
                'status': OK,
                'message': r['apps']}
        elif r and r.get('error'):
            data['message'] = r.get('error')
    except Exception as exp:
        logger.exception('Listing installed apps')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@require_http_methods(['POST'])
def get_supported_models(request, api=False):
    """Get Supported iOS VM models."""
    data = {
        'status': 'failed',
        'message': 'Failed to obtain iOS models'}
    try:
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        if not apikey:
            data = {
                'status': 'failed',
                'message': 'Missing corellium API key'}
            return send_response(data, api)
        cm = CorelliumModelsAPI(apikey)
        r = cm.get_models()
        if r:
            data = {'status': OK, 'message': r}
    except Exception as exp:
        logger.exception('Obtaining iOS models')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@require_http_methods(['POST'])
def get_supported_os(request, api=False):
    """Get Supported iOS OS versions."""
    data = {
        'status': 'failed',
        'message': 'Failed to obtain iOS versions'}
    try:
        model = request.POST['model']
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        if not apikey:
            data['message'] = 'Missing corellium API key'
            return send_response(data, api)
        cm = CorelliumModelsAPI(apikey)
        r = cm.get_supported_os(model)
        if r:
            data = {'status': OK, 'message': r}
    except Exception as exp:
        logger.exception('Obtaining iOS versions')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


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
        if not re.match(r'^iphone\d*\w+', flavor):
            data['message'] = 'Invalid iOS flavor'
            return send_response(data, api)
        if not re.match(r'^\d+\.\d+\.*\d*', version):
            data['message'] = 'Invalid iOS version'
            return send_response(data, api)
        failed = common_check(project_id)
        if failed:
            return send_response(failed, api)
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        c = CorelliumAPI(apikey, project_id)
        r = c.create_ios_instance(flavor, version)
        if r:
            data = {
                'status': OK, 
                'message': f'Created a new instance with id: {r}'}
    except Exception as exp:
        logger.exception('Creating Corellium iOS VM')
        data['message'] = str(exp)
    return send_response(data, api)

# AJAX


@require_http_methods(['POST'])
def setup_environment(request, checksum, api=False):
    """Setup iOS Dynamic Analyzer Environment."""
    data = {
        'status': 'failed',
        'message': 'Failed to Setup Dynamic Analysis Environment'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ca = CorelliumAgentAPI(apikey, instance_id)
        if not ca.agent_ready():
            data['message'] = (
                f'Agent is not ready with {instance_id}'
                ', please wait.')
            return send_response(data, api)
        # Unlock iOS Device
        ca.unlock_instance()
        # Install IPA
        ipa_path = Path(settings.UPLD_DIR) / checksum / f'{checksum}.ipa'
        msg = ca.upload_ipa(ipa_path)
        if msg != OK:
            data['message'] = msg
            return send_response(data, api)
        msg = ca.install_ipa()
        if msg != OK:
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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        if not strict_package_check(bundle_id):
            data['message'] = 'Invalid iOS Bundle id'
            return send_response(data, api)
        ca = CorelliumAgentAPI(apikey, instance_id)
        if ca.agent_ready() and ca.unlock_instance() and ca.run_app(bundle_id) == OK:
            data['status'] = OK
            data['message'] = 'App Started'
    except Exception as exp:
        logger.exception('Failed to run the app')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


@require_http_methods(['POST'])
def take_screenshot(request, api=False):
    """Take a Screenshot."""
    data = {
        'status': 'failed',
        'message': 'Failed to take screenshot'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
        r = ci.screenshot()
        if r:
            b64dat = b64encode(r).decode('utf-8')
            data['status'] = OK
            data['message'] = f'data:image/png;base64,{b64dat}'
    except Exception as exp:
        logger.exception('Failed to take screenshot')
        data['message'] = str(exp)
    return send_response(data, api)
# AJAX


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
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
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
# AJAX


@require_http_methods(['POST'])
def ssh_execute(request, api=False):
    """Execute commands in VM over SSH."""
    data = {
        'status': 'failed',
        'message': 'Failed to execute command'}
    try:
        instance_id = request.POST['instance_id']
        failed = common_check(instance_id)
        if failed:
            return send_response(failed, api)
        apikey = getattr(settings, 'CORELLIUM_API_KEY', '')
        ci = CorelliumInstanceAPI(apikey, instance_id)
        cmd = request.POST.get('cmd')
        ssh = request.POST.get('ssh')
        try:
            signer = Signer(salt=SALT)
            ssh = signer.unsign_object(ssh)
        except (TypeError, BadSignature, json.decoder.JSONDecodeError):
            ssh = None
        if not ssh:
            # Fallback when session does not exist.
            # For ex: REST API
            logger.warning('Invalid signature, generating SSH connection string')
            ssh = ci.get_ssh_connection_string()
        argz = ssh.split(' ') + cmd.split(' ')
        out = subprocess.Popen(
            argz,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).communicate()
        err_str = ''
        err = out[1].decode('utf8', 'ignore').split('\n')
        if len(err) > 1:
            err = err[1:]
            err_str = '\n'.join(err)
        res = (f"{out[0].decode('utf8', 'ignore')}{err_str}")
        data = {'status': OK, 'message': res}
    except Exception as exp:
        data['message'] = str(exp)
        logger.exception('Executing Commands')
        return send_response(data, api)
    return send_response(data, api)
