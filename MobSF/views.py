# -*- coding: utf_8 -*-
"""
MobSF File Upload and Home Routes
"""
import os
import hashlib
import platform
import json
import re

from wsgiref.util import FileWrapper
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils import timezone
from MobSF.utils import PrintException
from MobSF.models import RecentScansDB
from .forms import UploadFileForm


def add_to_recent_scan(name, md5, url):
    """
    Add Entry to Database under Recent Scan
    """
    try:
        db_obj = RecentScansDB.objects.filter(MD5=md5)
        if not db_obj.exists():
            new_db_obj = RecentScansDB(
                NAME=name, MD5=md5, URL=url, TS=timezone.now())
            new_db_obj.save()
    except:
        PrintException("[ERROR] Adding Scan URL to Database")


def index(request):
    """
    Index Route
    """
    context = {'version': settings.MOBSF_VER}
    template = "index.html"
    return render(request, template, context)


def handle_uploaded_file(filecnt, typ):
    """
    Write Uploaded File
    """
    md5 = hashlib.md5()  # modify if crash for large
    for chunk in filecnt.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    anal_dir = os.path.join(settings.UPLD_DIR, md5sum + '/')
    if not os.path.exists(anal_dir):
        os.makedirs(anal_dir)
    with open(anal_dir + md5sum + typ, 'wb+') as destination:
        for chunk in filecnt.chunks():
            destination.write(chunk)
    return md5sum


def upload(request):
    """
    Handle File Upload based on App type
    """
    try:
        response_data = {}
        response_data['url'] = ''
        response_data['description'] = ''
        response_data['status'] = ''
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                file_type = request.FILES['file'].content_type
                print "[INFO] MIME Type: " + file_type + " FILE: " + request.FILES['file'].name
                if ((file_type in settings.APK_MIME) and
                        request.FILES['file'].name.lower().endswith('.apk')):
                        # APK
                    md5 = handle_uploaded_file(request.FILES['file'], '.apk')
                    response_data['url'] = ('StaticAnalyzer/?name=' + request.FILES['file'].name +
                                            '&type=apk&checksum=' + md5)
                    response_data['status'] = 'success'
                    add_to_recent_scan(
                        request.FILES['file'].name, md5, response_data['url'])
                    print "\n[INFO] Performing Static Analysis of Android APK"
                elif ((file_type in settings.ZIP_MIME) and
                      request.FILES['file'].name.lower().endswith('.zip')):
                      # Android /iOS Zipped Source
                    md5 = handle_uploaded_file(request.FILES['file'], '.zip')
                    response_data['url'] = ('StaticAnalyzer/?name=' + request.FILES['file'].name +
                                            '&type=zip&checksum=' + md5)
                    response_data['status'] = 'success'
                    add_to_recent_scan(
                        request.FILES['file'].name, md5, response_data['url'])
                    print "\n[INFO] Performing Static Analysis of Android/iOS Source Code"
                elif ((file_type in settings.IPA_MIME) and
                      request.FILES['file'].name.lower().endswith('.ipa')):
                      # iOS Binary
                    if platform.system() == "Darwin":  # Check for Mac OS X
                        md5 = handle_uploaded_file(
                            request.FILES['file'], '.ipa')
                        response_data['url'] = ('StaticAnalyzer_iOS/?name=' +
                                                request.FILES['file'].name +
                                                '&type=ipa&checksum=' + md5)
                        response_data['status'] = 'success'
                        add_to_recent_scan(
                            request.FILES['file'].name, md5, response_data['url'])
                        print "\n[INFO] Performing Static Analysis of iOS IPA"
                    else:
                        response_data['url'] = 'mac_only/'
                        response_data['status'] = 'success'
                        print "\n[ERROR] Static Analysis of iOS IPA requires OSX"
                elif (file_type in settings.APPX_MIME) and request.FILES['file'].name.lower().endswith('.appx'):   #Windows APPX
                    md5=handle_uploaded_file(request.FILES['file'],'.appx')
                    response_data['url'] = 'StaticAnalyzer_Windows/?name='+request.FILES['file'].name+'&type=appx&checksum='+md5
                    response_data['status'] = 'success'
                    add_to_recent_scan(
                        request.FILES['file'].name,md5,response_data['url'])
                    print "\n[INFO] Performing Static Analysis of Windows APP"
                else:
                    response_data['url'] = ''
                    response_data['description'] = 'File format not Supported!'
                    response_data['status'] = 'error'
                    print "\n[ERROR] File format not Supported!"

            else:
                response_data['url'] = ''
                response_data['description'] = 'Invalid Form Data!'
                response_data['status'] = 'error'
                print "\n[ERROR] Invalid Form Data!"
        else:
            response_data['url'] = ''
            response_data['description'] = 'Method not Supported!'
            response_data['status'] = 'error'
            print "\n[ERROR] Method not Supported!"
            form = UploadFileForm()
        resp = HttpResponse(json.dumps(response_data),
                            content_type="application/json")
        resp['Access-Control-Allow-Origin'] = '*'
        return resp
    except:
        PrintException("[ERROR] Uploading File:")


def about(request):
    """
    About Route
    """
    context = {'title': 'About'}
    template = "about.html"
    return render(request, template, context)


def error(request):
    """
    Error Route
    """
    context = {'title': 'Error'}
    template = "error.html"
    return render(request, template, context)


def zip_format(request):
    """
    Zip Format Message Route
    """
    context = {'title': 'Zipped Source Instruction'}
    template = "zip.html"
    return render(request, template, context)


def mac_only(request):
    """
    Mac Ony Message Route
    """
    context = {'title': 'Supports OSX Only'}
    template = "ios.html"
    return render(request, template, context)


def not_found(request):
    """
    Not Found Route
    """
    context = {'title': 'Not Found'}
    template = "not_found.html"
    return render(request, template, context)


def recent_scans(request):
    """
    Show Recent Scans Route
    """
    db_obj = RecentScansDB.objects.all().order_by('-TS')
    context = {'title': 'Recent Scans', 'entries': db_obj}
    template = "recent.html"
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
                print "\n[ATTACK] Path Traversal Attack detected"
                return HttpResponseRedirect('/error/')
            ext = os.path.splitext(filename)[1]
            if ext in allowed_exts:
                dwd_file = os.path.join(settings.DWD_DIR, filename)
                if os.path.isfile(dwd_file):
                    wrapper = FileWrapper(file(dwd_file))
                    response = HttpResponse(
                        wrapper, content_type=allowed_exts[ext])
                    response['Content-Length'] = os.path.getsize(dwd_file)
                    return response
    except:
        PrintException("Error Downloading File")
    return HttpResponseRedirect('/error/')
