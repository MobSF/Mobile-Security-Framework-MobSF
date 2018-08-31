# -*- coding: utf_8 -*-
"""
MobSF File Upload and Home Routes
"""
import json
import os
import platform
import re
import shutil
from wsgiref.util import FileWrapper

from django.conf import settings
from django.http import (
    HttpResponse,
    HttpResponseRedirect,
    JsonResponse
)
from django.shortcuts import render
from MobSF.forms import (
    FormUtil,
    UploadFileForm
)
from MobSF.views.scanning import Scanning
from MobSF.utils import (
    FileType,
    PrintException,
    api_key,
    isDirExists,
    isFileExists,
    print_n_send_error_response
)
from StaticAnalyzer.models import (
    RecentScansDB,
    StaticAnalyzerAndroid,
    StaticAnalyzerIOSZIP,
    StaticAnalyzerIPA,
    StaticAnalyzerWindows
)

LINUX_PLATFORM = ["Darwin", "Linux"]
HTTP_BAD_REQUEST = 400


def index(request):
    """
    Index Route
    """
    context = {'version': settings.MOBSF_VER}
    template = "general/index.html"
    return render(request, template, context)


class Upload(object):
    """
    Handle File Upload based on App type
    """

    def __init__(self, request):
        self.request = request
        self.form = UploadFileForm(request.POST, request.FILES)
        self.file_content_type = None
        self.file_name_lower = None
        self.file_type = None

    @staticmethod
    def as_view(request):
        upload = Upload(request)
        return upload.upload_html()

    def upload_html(self):
        response_data = {
            'url': '',
            'description': '',
            'status': 'error'
        }
        request = self.request
        resp = HttpResponse(json.dumps(response_data),
                            content_type="application/json; charset=utf-8")
        resp['Access-Control-Allow-Origin'] = '*'

        if request.method != 'POST':
            response_data['description'] = 'Method not Supported!'
            print("\n[ERROR] Method not Supported!")
            form = UploadFileForm()
            resp['status'] = HTTP_BAD_REQUEST
            return resp

        if not self.form.is_valid():
            response_data['description'] = 'Invalid Form Data!'
            print("\n[ERROR] Invalid Form Data!")
            resp['status'] = HTTP_BAD_REQUEST
            return resp

        self.file_content_type = request.FILES['file'].content_type
        self.file_name_lower = request.FILES['file'].name.lower()
        self.file_type = FileType(self.file_content_type, self.file_name_lower)
        if not self.file_type.is_allow_file():
            response_data['description'] = 'File format not Supported!'
            print("\n[ERROR] File format not Supported!")
            resp['status'] = HTTP_BAD_REQUEST
            return resp

        if self.file_type.is_ipa():
            if platform.system() not in LINUX_PLATFORM:
                data = {
                    'error': "Static Analysis of iOS IPA requires Mac or Linux",
                    'url': 'mac_only/',
                    'status': 'success'
                }
                print("\n[ERROR] Static Analysis of iOS IPA requires Mac or Linux")
                return data

        data = self.upload()

        response_data['url'] = data['url']
        response_data['status'] = data['status']
        return HttpResponse(json.dumps(response_data),
                            content_type="application/json; charset=utf-8")

    def upload_api(self):
        """
        API File Upload
        """
        api_response = {}
        request = self.request
        if not self.form.is_valid():
            api_response['error'] = FormUtil.errors_message(self.form)
            return api_response, HTTP_BAD_REQUEST
        self.file_content_type = request.FILES['file'].content_type
        self.file_name_lower = request.FILES['file'].name.lower()
        self.file_type = FileType(self.file_content_type, self.file_name_lower)
        if not self.file_type.is_allow_file():
            api_response["error"] = "File format not Supported!"
            return api_response, HTTP_BAD_REQUEST
        data = self.upload()
        api_response = {
            'scan_type': data['scan_type'],
            'hash': data['hash'],
            'file_name': data['file_name']
        }
        return api_response, 200

    def upload(self):
        request = self.request
        scanning = Scanning(request)
        file_type = self.file_content_type
        file_name_lower = self.file_name_lower

        print("[INFO] MIME Type: {} FILE: {}".format(
            file_type, file_name_lower))
        if self.file_type.is_apk():
            return scanning.scan_apk()
        elif self.file_type.is_zip():
            return scanning.scan_zip()
        elif self.file_type.is_ipa():
            return scanning.scan_ipa()
        # Windows APPX
        elif self.file_type.is_appx():
            return scanning.scan_appx()


def api_docs(request):
    """
    API Docs Route
    """
    context = {'title': 'REST API Docs', 'api_key': api_key()}
    template = "general/apidocs.html"
    return render(request, template, context)


def about(request):
    """
    About Route
    """
    context = {'title': 'About'}
    template = "general/about.html"
    return render(request, template, context)


def error(request):
    """
    Error Route
    """
    context = {'title': 'Error'}
    template = "general/error.html"
    return render(request, template, context)


def zip_format(request):
    """
    Zip Format Message Route
    """
    context = {'title': 'Zipped Source Instruction'}
    template = "general/zip.html"
    return render(request, template, context)


def mac_only(request):
    """
    Mac Ony Message Route
    """
    context = {'title': 'Supports OSX Only'}
    template = "general/ios.html"
    return render(request, template, context)


def not_found(request):
    """
    Not Found Route
    """
    context = {'title': 'Not Found'}
    template = "general/not_found.html"
    return render(request, template, context)


def recent_scans(request):
    """
    Show Recent Scans Route
    """
    db_obj = RecentScansDB.objects.all().order_by('-TS')
    context = {'title': 'Recent Scans', 'entries': db_obj}
    template = "general/recent.html"
    return render(request, template, context)


def search(request):
    """
    Search Scan by MD5 Route
    """
    md5 = request.GET['md5']
    if re.match('[0-9a-f]{32}', md5):
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if db_obj.exists():
            return HttpResponseRedirect('/' + db_obj[0].URL)
        else:
            return HttpResponseRedirect('/not_found')
    return HttpResponseRedirect('/error/')


def download(request):
    """
    Download from MobSF Route
    """
    try:
        if request.method == 'GET':
            allowed_exts = settings.ALLOWED_EXTENSIONS
            filename = request.path.replace("/download/", "", 1)
            # Security Checks
            if "../" in filename:
                print("\n[ATTACK] Path Traversal Attack detected")
                return HttpResponseRedirect('/error/')
            ext = os.path.splitext(filename)[1]
            if ext in allowed_exts:
                dwd_file = os.path.join(settings.DWD_DIR, filename)
                if os.path.isfile(dwd_file):
                    wrapper = FileWrapper(open(dwd_file, "rb"))
                    response = HttpResponse(
                        wrapper, content_type=allowed_exts[ext])
                    response['Content-Length'] = os.path.getsize(dwd_file)
                    return response
    except:
        PrintException("Error Downloading File")
    return HttpResponseRedirect('/error/')


def delete_scan(request, api=False):
    """
    Delete Scan from DB and remove the scan related files
    """
    try:
        if request.method == 'POST':
            if api:
                md5_hash = request.POST['hash']
            else:
                md5_hash = request.POST['md5']
            data = {'deleted': 'no'}
            if re.match('[0-9a-f]{32}', md5_hash):
                # Delete DB Entries
                scan = RecentScansDB.objects.filter(MD5=md5_hash)
                if scan.exists():
                    RecentScansDB.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerAndroid.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerIPA.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerIOSZIP.objects.filter(MD5=md5_hash).delete()
                    StaticAnalyzerWindows.objects.filter(MD5=md5_hash).delete()
                    # Delete Upload Dir Contents
                    app_upload_dir = os.path.join(settings.UPLD_DIR, md5_hash)
                    if isDirExists(app_upload_dir):
                        shutil.rmtree(app_upload_dir)
                    # Delete Download Dir Contents
                    dw_dir = settings.DWD_DIR
                    for item in os.listdir(dw_dir):
                        item_path = os.path.join(dw_dir, item)
                        # Delete all related files
                        if isFileExists(item_path) and item.startswith(md5_hash + "-"):
                            os.remove(item_path)
                        # Delete related directories
                        if isDirExists(item_path) and item.startswith(md5_hash + "-"):
                            shutil.rmtree(item_path)
                    data = {'deleted': 'yes'}
            if api:
                return data
            else:
                return HttpResponse(json.dumps(data), content_type='application/json; charset=utf-8')
    except Exception as exp:
        msg = str(exp)
        exp_doc = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)
