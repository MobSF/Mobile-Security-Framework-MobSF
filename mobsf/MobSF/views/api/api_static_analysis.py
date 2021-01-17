# -*- coding: utf_8 -*-
"""MobSF REST API V 1."""

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from mobsf.MobSF.views.helpers import request_method
from mobsf.MobSF.views.home import RecentScans, Upload, delete_scan
from mobsf.MobSF.views.api.api_middleware import make_api_response
from mobsf.StaticAnalyzer.views.android import view_source
from mobsf.StaticAnalyzer.views.android.static_analyzer import static_analyzer
from mobsf.StaticAnalyzer.views.ios import view_source as ios_view_source
from mobsf.StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from mobsf.StaticAnalyzer.views.shared_func import (
    compare_apps,
    pdf,
)
from mobsf.StaticAnalyzer.views.windows import windows


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API."""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['GET'])
@csrf_exempt
def api_recent_scans(request):
    """GET - get recent scans."""
    scans = RecentScans(request)
    resp = scans.recent_scans()
    if 'error' in resp:
        return make_api_response(resp, 500)
    else:
        return make_api_response(resp, 200)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API."""
    params = {'scan_type', 'hash', 'file_name'}
    if set(request.POST) >= params:
        scan_type = request.POST['scan_type']
        # APK, Android ZIP and iOS ZIP
        if scan_type in {'xapk', 'apk', 'zip'}:
            resp = static_analyzer(request, True)
            if 'type' in resp:
                # For now it's only ios_zip
                request.POST._mutable = True
                request.POST['scan_type'] = 'ios'
                resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # IPA
        elif scan_type == 'ipa':
            resp = static_analyzer_ios(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
        # APPX
        elif scan_type == 'appx':
            resp = windows.staticanalyzer_windows(request, True)
            if 'error' in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan."""
    if 'hash' in request.POST:
        resp = delete_scan(request, True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF."""
    params = {'hash'}
    if set(request.POST) == params:
        resp = pdf(request, api=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'pdf_dat' in resp:
            response = HttpResponse(
                resp['pdf_dat'], content_type='application/pdf')
            response['Access-Control-Allow-Origin'] = '*'
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'PDF Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report."""
    params = {'hash'}
    if set(request.POST) == params:
        resp = pdf(request, api=True, jsonres=True)
        if 'error' in resp:
            if resp.get('error') == 'Invalid scan hash':
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif 'report_dat' in resp:
            response = make_api_response(resp['report_dat'], 200)
        elif resp.get('report') == 'Report not Found':
            response = make_api_response(resp, 404)
        else:
            response = make_api_response(
                {'error': 'JSON Generation Error'}, 500)
    else:
        response = make_api_response(
            {'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_view_source(request):
    """View Source for android & ios source file."""
    params = {'file', 'type', 'hash'}
    if set(request.POST) >= params:
        if request.POST['type'] in {'eclipse', 'studio',
                                    'apk', 'java', 'smali'}:
            resp = view_source.run(request, api=True)
        else:
            resp = ios_view_source.run(request, api=True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response({'error': 'Missing Parameters'}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_compare(request):
    """Compare 2 apps."""
    params = {'hash1', 'hash2'}
    if set(request.POST) >= params:
        resp = compare_apps(
            request,
            request.POST['hash1'],
            request.POST['hash2'],
            True)
        if 'error' in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response({'error': 'Missing Parameters'}, 422)
    return response
