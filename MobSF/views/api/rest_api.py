"""
MobSF REST API V 1
"""

from django.http import (
    HttpResponse,
    JsonResponse
)
from django.views.decorators.csrf import csrf_exempt

from MobSF.views.home import (
    Upload,
    delete_scan
)
from MobSF.utils import (
    api_key,
    request_method
)
from MobSF.forms import (
    ViewSourceForm, 
    FormUtil
)
from StaticAnalyzer.views.shared_func import (
    pdf
)
from StaticAnalyzer.views.android.static_analyzer import (
    static_analyzer
)
from StaticAnalyzer.views.ios.static_analyzer import (
    static_analyzer_ios
)
from StaticAnalyzer.views.windows import (
    staticanalyzer_windows
)
from StaticAnalyzer.views.android.view_source import (
    ViewSource
)




def make_api_response(data, status=200):
    """Make API Response"""
    resp = JsonResponse(data=data, status=status)
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Access-Control-Allow-Methods'] = 'POST'
    resp['Access-Control-Allow-Headers'] = 'Authorization'
    return resp


def api_auth(meta):
    """Check if API Key Matches"""
    if "HTTP_AUTHORIZATION" in meta:
        return bool(api_key() == meta["HTTP_AUTHORIZATION"])
    return False


@request_method(['POST'])
@csrf_exempt
def api_upload(request):
    """POST - Upload API"""
    upload = Upload(request)
    resp, code = upload.upload_api()
    return make_api_response(resp, code)


@request_method(['POST'])
@csrf_exempt
def api_scan(request):
    """POST - Scan API"""
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
    return response


@request_method(['POST'])
@csrf_exempt
def api_delete_scan(request):
    """POST - Delete a Scan"""
    if "hash" in request.POST:
        resp = delete_scan(request, True)
        if "error" in resp:
            response = make_api_response(resp, 500)
        else:
            response = make_api_response(resp, 200)
    else:
        response = make_api_response(
            {"error": "Missing Parameters"}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_pdf_report(request):
    """Generate and Download PDF"""
    params = ['scan_type', 'hash']
    if set(request.POST) == set(params):
        resp = pdf(request, api=True)
        if "error" in resp:
            if resp.get("error") == "Invalid scan hash":
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif "pdf_dat" in resp:
            response = HttpResponse(
                resp["pdf_dat"], content_type='application/pdf')
            response["Access-Control-Allow-Origin"] = "*"
        elif resp.get("report") == "Report not Found":
            response = make_api_response(resp, 404)
        elif resp.get("scan_type") == "Type is not Allowed":
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(
                {"error": "PDF Generation Error"}, 500)
    else:
        response = make_api_response(
            {"error": "Missing Parameters"}, 422)
    return response


@request_method(['POST'])
@csrf_exempt
def api_json_report(request):
    """Generate JSON Report"""
    params = ['scan_type', 'hash']
    if set(request.POST) == set(params):
        resp = pdf(request, api=True)
        if "error" in resp:
            if resp.get("error") == "Invalid scan hash":
                response = make_api_response(resp, 400)
            else:
                response = make_api_response(resp, 500)
        elif "report_dat" in resp:
            response = make_api_response(resp["report_dat"], 200)
        elif resp.get("report") == "Report not Found":
            response = make_api_response(resp, 404)
        elif resp.get("scan_type") == "Type is not Allowed":
            response = make_api_response(resp, 400)
        else:
            response = make_api_response(
                {"error": "JSON Generation Error"}, 500)
    else:
        response = make_api_response(
            {"error": "Missing Parameters"}, 422)
    return response


BAD_REQUEST = 400
@request_method(['GET'])
@csrf_exempt
def api_viewsource_android(request):
    """
    viewsource for android file
    """
    viewsource_form = ViewSourceForm(request.GET)
    if not viewsource_form.is_valid():
        return JsonResponse(FormUtil.errors_message(viewsource_form), status=BAD_REQUEST)

    view_source = ViewSource(request)
    return JsonResponse(view_source.api())
    

