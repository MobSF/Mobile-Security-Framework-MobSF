"""
MobSF REST API V 1
"""
import json

from .forms import UploadFileForm
from MobSF.views import (
    Upload,
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

from django.http import HttpResponse, JsonResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.views.decorators.csrf import csrf_exempt


def make_api_response(data, status=200):
    """Make API Response"""
    api_resp = HttpResponse(json.dumps(
        data, sort_keys=True,
        indent=4, separators=(',', ': ')), content_type="application/json; charset=utf-8", status=status)
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
    if request.method == 'POST':
        upload = Upload(request)
        return upload.upload_api()
    else:
        return HttpResponseNotAllowed(['post'])



@csrf_exempt
def api_scan(request):
    """POST - Scan API"""
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
    
    return response


@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan"""
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

    return response


@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF"""
    if request.method == 'POST':
        params = ['scan_type', 'hash']
        if set(request.POST) == set(params):
            resp = pdf(request, api=True)
            if "error" in resp:
                if "Invalid scan hash" == resp.get("error"):
                    response = make_api_response(resp, 400)
                else:
                    response = make_api_response(resp, 500)
            elif "pdf_dat" in resp:
                response = HttpResponse(
                    resp["pdf_dat"], content_type='application/pdf')
            elif "Report not Found" == resp.get("report"):
                response = make_api_response(resp, 404)
            elif "Type is not Allowed" == resp.get("scan_type"):
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(
                    {"error": "PDF Generation Error"}, 500)
        else:
            response = make_api_response(
                {"error": "Missing Parameters"}, 422)
    else:
        response = make_api_response({"error": "Method Not Allowed"}, 405)
    return response


@csrf_exempt
def api_json_report(request):
    """Generate JSON Report"""
    if request.method == 'POST':
        params = ['scan_type', 'hash']
        if set(request.POST) == set(params):
            resp = pdf(request, api=True)
            if "error" in resp:
                if "Invalid scan hash" == resp.get("error"):
                    response = make_api_response(resp, 400)
                else:
                    response = make_api_response(resp, 500)
            elif "report_dat" in resp:
                response = make_api_response(resp["report_dat"], 200)
            elif "Report not Found" == resp.get("report"):
                response = make_api_response(resp, 404)
            elif "Type is not Allowed" == resp.get("scan_type"):
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(
                    {"error": "JSON Generation Error"}, 500)
        else:
            response = make_api_response(
                {"error": "Missing Parameters"}, 422)
    else:
        response = make_api_response({"error": "Method Not Allowed"}, 405)
    return response
