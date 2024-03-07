# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.DynamicAnalyzer.views.ios import (
    corellium_instance,
    dynamic_analyzer,
    report,
    tests_frida,
)


FAILED = 'failed'
ERROR = 'error'
INSTANCE_ID = 'instance_id'
BUNDLE_ID = 'bundle_id'


# Dynamic Analyzer APIs
@request_method(['POST'])
@csrf_exempt
def api_ios_dynamic_analysis(request):
    """POST - iOS Dynamic Analysis Entrypoint."""
    resp = dynamic_analyzer.dynamic_analysis(request, True)
    if ERROR in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_ios_dynamic_analyzer(request):
    """POST - iOS Dynamic Analyzer."""
    params = {INSTANCE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = dynamic_analyzer.dynamic_analyzer(request, True)
    if ERROR in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


# Corellium Instance Operations
@request_method(['POST'])
@csrf_exempt
def api_corellium_get_supported_models(request):
    """POST - Corellium Get Supported iOS Models."""
    resp = corellium_instance.get_supported_models(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_get_supported_ios_versions(request):
    """POST - Corellium Get Supported iOS Versions."""
    if 'model' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.get_supported_os(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_create_ios_instance(request):
    """POST - Corellium Create an iOS Instance."""
    params = {'name', 'project_id', 'flavor', 'version'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.create_vm_instance(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_start_instance(request):
    """POST - Start Corellium Instance."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.start_instance(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_stop_instance(request):
    """POST - Stop Corellium Instance."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.stop_instance(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_unpause_instance(request):
    """POST - Unpause Corellium Instance."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.unpause_instance(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_reboot_instance(request):
    """POST - Reboot Corellium Instance."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.reboot_instance(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_destroy_instance(request):
    """POST - Destroy Corellium Instance."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.destroy_instance(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_corellium_instance_list_apps(request):
    """POST - Corellium Instance List Apps."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.list_apps(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


# Dynamic Analyzer Helpers
@request_method(['POST'])
@csrf_exempt
def api_setup_environment(request):
    """POST - Setup Dynamic Analyzer Environment."""
    params = {INSTANCE_ID, 'hash'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.setup_environment(
        request,
        request.POST['hash'],
        True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_run_app(request):
    """POST - Run an App."""
    params = {INSTANCE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.run_app(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_stop_app(request):
    """POST - Run an App."""
    params = {INSTANCE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.stop_app(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_remove_app(request):
    """POST - Remove an App from Device."""
    params = {INSTANCE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.remove_app(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_take_screenshot(request):
    """POST - Take a Screenshot."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.take_screenshot(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_get_app_container_path(request):
    """POST - Get App Container path."""
    if BUNDLE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.get_container_path(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_network_capture(request):
    """POST - Enable/Disable Network Capture."""
    params = {INSTANCE_ID, 'state'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.network_capture(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_live_pcap_download(request):
    """POST - Download Network Capture file."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.live_pcap_download(request, True)
    if resp.get('Content-Disposition'):
        # PCAP file http response
        return resp
    elif resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_ssh_execute(request):
    """POST - Execute commands in VM over SSH."""
    params = {INSTANCE_ID, 'cmd'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.ssh_execute(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_download_app_data(request):
    """POST - Download Application Data from Device."""
    params = {INSTANCE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.download_data(
        request,
        request.POST[BUNDLE_ID],
        True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_instance_input(request):
    """POST - Sending Touch/Swipe/Text Events."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.touch(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_system_logs(request):
    """POST - Get system logs."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.system_logs(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_file_upload(request):
    """POST - Upload file to device."""
    if INSTANCE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.upload_file(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_file_download(request):
    """POST - Download file from device."""
    params = {INSTANCE_ID, 'file'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = corellium_instance.download_file(request, True)
    if resp.get('Content-Disposition'):
        # file http response
        return resp
    elif resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


# Frida APIs
@request_method(['POST'])
@csrf_exempt
def api_ios_instrument(request):
    """POST - Frida Instrument."""
    params = {
        INSTANCE_ID,
        BUNDLE_ID,
        'hash',
        'default_hooks',
        'dump_hooks',
        'auxiliary_hooks',
        'frida_code'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = tests_frida.ios_instrument(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


# Report APIs
@request_method(['POST'])
@csrf_exempt
def api_ios_view_report(request):
    """POST - iOS Dynamic Analysis report."""
    params = {INSTANCE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = report.ios_view_report(
        request,
        request.POST[BUNDLE_ID],
        True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)
