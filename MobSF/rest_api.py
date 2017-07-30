"""
MobSF REST API V 1
"""
import json

from .forms import UploadFileForm
from MobSF.views import (
    upload,
    delete_scan
)
from MobSF.utils import (
    api_key
)
from StaticAnalyzer.views.shared_func import (
    pdf
)
from StaticAnalyzer.views.android.static_analyzer import static_analyzer
from StaticAnalyzer.views.ios.static_analyzer import static_analyzer_ios
from StaticAnalyzer.views.windows import staticanalyzer_windows

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt


def make_api_response(data, status=200):
    """Make API Response"""
    api_resp = HttpResponse(json.dumps(
        data), content_type="application/json; charset=utf-8", status=status)
    api_resp['Access-Control-Allow-Origin'] = '*'
    return api_resp


def api_auth(meta):
    """Check if API Key Matches"""
    if "HTTP_AUTHORIZATION" in meta:
        return bool(api_key() == meta["HTTP_AUTHORIZATION"])
    return False


@csrf_exempt
def api_upload(request):
    """POST - Upload API"""
    if api_auth(request.META):
        if request.method == 'POST':
            resp = upload(request, True)
            if "error" in resp:
                response = make_api_response(resp, 500)
            else:
                response = make_api_response(resp)
        else:
            response = make_api_response({"error": "Method Not Allowed"}, 405)
    else:
        response = make_api_response(
            {"error": "You are unauthorized to make this request."}, 401)
    return response


@csrf_exempt
def api_scan(request):
    """POST - Scan API"""
    if api_auth(request.META):
        if request.method == 'POST':
            params = ['scan_type', 'hash', 'file_name']
            if set(request.POST) >= set(params):
                scan_type = request.POST['scan_type']
                # APK, Android ZIP and iOS ZIP
                if scan_type in ["apk", "zip"]:
                    resp = static_analyzer(request, True)
                    if "type" in resp:
                        # For now it's only ios_zip
                        request.POST._mutable = True
                        request.POST['scan_type'] = "ios"
                        resp = static_analyzer_ios(request, True)
                    if "error" in resp:
                        response = make_api_response(resp, 500)
                    else:
                        response = make_api_response(resp, 200)
                # IPA
                elif scan_type == "ipa":
                    resp = static_analyzer_ios(request, True)
                    if "error" in resp:
                        response = make_api_response(resp, 500)
                    else:
                        response = make_api_response(resp, 200)
                # APPX
                elif scan_type == "appx":
                    resp = staticanalyzer_windows(request, True)
                    if "error" in resp:
                        response = make_api_response(resp, 500)
                    else:
                        response = make_api_response(resp, 200)
            else:
                response = make_api_response(
                    {"error": "Missing Parameters"}, 422)
        else:
            response = make_api_response({"error": "Method Not Allowed"}, 405)
    else:
        response = make_api_response(
            {"error": "You are unauthorized to make this request."}, 401)
    return response


@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan"""
    if api_auth(request.META):
        if request.method == 'POST':
            if "hash" in request.POST:
                resp = delete_scan(request, True)
                if "error" in resp:
                    response = make_api_response(resp, 500)
                else:
                    response = make_api_response(resp, 200)
            else:
                response = make_api_response(
                    {"error": "Missing Parameters"}, 422)
        else:
            response = make_api_response({"error": "Method Not Allowed"}, 405)
    else:
        response = make_api_response(
            {"error": "You are unauthorized to make this request."}, 401)
    return response


@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF"""
    if api_auth(request.META):
        if request.method == 'POST':
            params = ['scan_type', 'hash']
            if set(request.POST) == set(params):
                resp = pdf(request, api=True)
                if "error" in resp:
                    response = make_api_response(resp, 500)
                elif "pdf_dat" in resp:
                    response = HttpResponse(
                        resp["pdf_dat"], content_type='application/pdf')
                else:
                    response = make_api_response(
                        {"error": "PDF Generation Error"}, 500)
            else:
                response = make_api_response(
                    {"error": "Missing Parameters"}, 422)
        else:
            response = make_api_response({"error": "Method Not Allowed"}, 405)
    else:
        response = make_api_response(
            {"error": "You are unauthorized to make this request."}, 401)
    return response
