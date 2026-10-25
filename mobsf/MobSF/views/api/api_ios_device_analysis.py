# -*- coding: utf_8 -*-
"""MobSF REST API V 1 - iOS Jailbroken Device."""

from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.DynamicAnalyzer.views.ios.device import (
    dynamic_analyzer as ios_device,
    report as device_report,
)


FAILED = 'failed'
ERROR = 'error'
DEVICE_ID = 'device_id'
BUNDLE_ID = 'bundle_id'


@request_method(['POST'])
@csrf_exempt
def api_device_dynamic_analysis(request):
    """POST - iOS Device Dynamic Analysis Entrypoint."""
    if DEVICE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.dynamic_analysis_device(request, True)
    if ERROR in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_get(request):
    """POST - Get iOS Device Details and List Apps."""
    if DEVICE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.get_ios_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_install_ipa(request):
    """POST - Install IPA on iOS Device."""
    params = {DEVICE_ID, 'checksum'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.install_ipa_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_dynamic_analyzer(request):
    """POST - iOS Device Dynamic Analyzer."""
    params = {DEVICE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.dynamic_analyzer_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_file_upload(request):
    """POST - Upload file to iOS Device."""
    if DEVICE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    if 'file' not in request.FILES:
        return make_api_response(
            {'error': 'Missing File'}, 422)
    resp = ios_device.upload_file_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_ssh_execute(request):
    """POST - Execute commands on iOS Device over SSH."""
    params = {DEVICE_ID, 'cmd'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.ssh_execute_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_instrument(request):
    """POST - Frida Instrument on iOS Device."""
    params = {
        DEVICE_ID,
        BUNDLE_ID,
        'default_hooks',
        'dump_hooks',
        'auxiliary_hooks',
        'frida_code'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.ios_instrument_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_system_logs(request):
    """POST - Get system logs from iOS Device."""
    if DEVICE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.system_logs_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_ps(request):
    """POST - Get running processes on iOS Device."""
    if DEVICE_ID not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = ios_device.ps_device(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_file_download(request):
    """POST - Download file from iOS Device."""
    params = {DEVICE_ID, 'file'}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = device_report.download_file_device(request, True)
    if resp.get('Content-Disposition'):
        # file http response
        return resp
    elif resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_api_monitor(request):
    """POST - iOS Device API Monitor."""
    if 'checksum' not in request.POST:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = device_report.ios_api_monitor(request, True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_download_app_data(request):
    """POST - Download Application Data from iOS Device."""
    params = {DEVICE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = device_report.download_data_device(
        request,
        request.POST[BUNDLE_ID],
        True)
    if resp.get('status') == FAILED:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_device_report_json(request):
    """POST - iOS Device Dynamic Analysis Report."""
    params = {DEVICE_ID, BUNDLE_ID}
    if set(request.POST) < params:
        return make_api_response(
            {'error': 'Missing Parameters'}, 422)
    resp = device_report.view_report_device(
        request,
        request.POST[BUNDLE_ID],
        True)
    if 'error' in resp:
        return make_api_response(resp, 500)
    return make_api_response(resp, 200)
