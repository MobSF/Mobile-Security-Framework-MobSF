# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils import timezone
from django.utils.encoding import smart_str
from django.core.servers.basehttp import FileWrapper

from MobSF.utils import PrintException, filename_from_path
from MobSF.models import RecentScansDB
from .forms import UploadFileForm

import os, hashlib, platform, json,shutil,re

def PushtoRecent(NAME,MD5,URL):
    try:
        DB=RecentScansDB.objects.filter(MD5=MD5)
        if not DB.exists():
            NDB=RecentScansDB(NAME=NAME,MD5=MD5,URL=URL,TS=timezone.now())
            NDB.save()
    except:
        PrintException("[ERROR] Adding Scan URL to Database")

def index(request):
    context = {'version': settings.MOBSF_VER}
    template="index.html"
    return render(request,template,context)

def handle_uploaded_file(f,typ):
    md5 = hashlib.md5() #modify if crash for large 
    for chunk in f.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    ANAL_DIR=os.path.join(settings.UPLD_DIR, md5sum+'/')
    if not os.path.exists(ANAL_DIR):
        os.makedirs(ANAL_DIR)
    with open(ANAL_DIR+ md5sum+typ, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk) 
    return md5sum

def Upload(request):
    try:
        response_data = {}
        response_data['url'] = ''
        response_data['description'] = ''
        response_data['status'] = ''
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                file_type =request.FILES['file'].content_type
                print "[INFO] MIME Type: " + file_type + " FILE: " + str(request.FILES['file'].name)
                if (file_type=="application/octet-stream" or file_type=="application/vnd.android.package-archive" or file_type=="application/x-zip-compressed") and request.FILES['file'].name.lower().endswith('.apk'):     #APK
                    md5=handle_uploaded_file(request.FILES['file'],'.apk')
                    response_data['url'] = 'StaticAnalyzer/?name='+request.FILES['file'].name+'&type=apk&checksum='+md5
                    response_data['status'] = 'success'
                    PushtoRecent(request.FILES['file'].name,md5,response_data['url'])
                    print "\n[INFO] Performing Static Analysis of Android APK"
                elif (file_type=="application/zip" or file_type=="application/octet-stream" or file_type=="application/x-zip-compressed") and request.FILES['file'].name.lower().endswith('.zip'):   #Android /iOS Zipped Source
                    md5=handle_uploaded_file(request.FILES['file'],'.zip')
                    response_data['url'] = 'StaticAnalyzer/?name='+request.FILES['file'].name+'&type=zip&checksum='+md5
                    response_data['status'] = 'success'
                    PushtoRecent(request.FILES['file'].name,md5,response_data['url'])
                    print "\n[INFO] Performing Static Analysis of Android/iOS Source Code"
                elif ((file_type=="application/octet-stream" or file_type=="application/x-itunes-ipa" or file_type=="application/x-zip-compressed") and request.FILES['file'].name.lower().endswith('.ipa')):   #iOS Binary
                    if platform.system()=="Darwin":
                        md5=handle_uploaded_file(request.FILES['file'],'.ipa')
                        response_data['url'] = 'StaticAnalyzer_iOS/?name='+request.FILES['file'].name+'&type=ipa&checksum='+md5
                        response_data['status'] = 'success'
                        PushtoRecent(request.FILES['file'].name,md5,response_data['url'])
                        print "\n[INFO] Performing Static Analysis of iOS IPA"
                    else:
                        response_data['url'] = 'MAC_ONLY/'
                        response_data['status'] = 'success'
                        print "\n[ERROR] Static Analysis of iOS IPA requires OSX"
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
        r= HttpResponse(json.dumps(response_data),content_type="application/json")
        r['Access-Control-Allow-Origin']='*'
        return r
    except:
        PrintException("[ERROR] Uploading File:")

def about(request):
    context = {'title': 'About'}
    template="about.html"
    return render(request,template,context)

def error(request):
    context = {'title':'Error'}
    template ="error.html"
    return render(request,template,context)

def ZIP_FORMAT(request):
    context = {'title':'Zipped Source Instruction'}
    template ="zip.html"
    return render(request,template,context)

def MAC_ONLY(request):
    context = {'title':'Supports OSX Only'}
    template ="ios.html"
    return render(request,template,context)

def NotFound(request):
    context = {'title':'Not Found'}
    template ="not_found.html"
    return render(request,template,context)

def RecentScans(request):
    DB=RecentScansDB.objects.all().order_by('-TS')
    context = {'title': 'Recent Scans','entries': DB }
    template="recent.html"
    return render(request,template,context)

def Search(request):
    MD5=request.GET['md5']
    if re.match('[0-9a-f]{32}',MD5):
        DB=RecentScansDB.objects.filter(MD5=MD5)
        if DB.exists():
            return HttpResponseRedirect('/'+DB[0].URL)
        else:
            return HttpResponseRedirect('/NotFound')
    return HttpResponseRedirect('/error/') 

def Download(request):
    try:
        if request.method == 'GET':
            allowed_exts = settings.ALLOWED_EXTENSIONS
            filename = request.path.replace("/download/","",1)
            #Security Checks
            if ("../") in filename:
                print "\n[ATTACK] Path Traversal Attack detected"
                return HttpResponseRedirect('/error/')
            ext = os.path.splitext(filename)[1]
            if (ext in allowed_exts):
                dwd_file = os.path.join(settings.DWD_DIR,filename)
                if os.path.isfile(dwd_file):
                    wrapper = FileWrapper(file(dwd_file))
                    response = HttpResponse(wrapper, content_type=allowed_exts[ext])
                    response['Content-Length'] = os.path.getsize(dwd_file)
                    return response
    except:
        PrintException("Error Downloading File")
    return HttpResponseRedirect('/error/') 


