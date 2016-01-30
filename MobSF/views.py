# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from .forms import UploadFileForm
from django.conf import settings
from django.utils import timezone
import os, hashlib, platform, json,shutil,re

from MobSF.models import RecentScansDB
#Clean up work
DIR = settings.BASE_DIR
CERTSDIR= os.path.join(DIR,'logs/')
if os.path.exists(CERTSDIR):
    shutil.rmtree(CERTSDIR)
    os.makedirs(CERTSDIR)
def PushtoRecent(NAME,MD5,URL):
    try:
        DB=RecentScansDB.objects.filter(MD5=MD5)
        if not DB.exists():
            NDB=RecentScansDB(NAME=NAME,MD5=MD5,URL=URL,TS=timezone.now())
            NDB.save()
    except Exception as e:
        print "\n[ERROR] Adding Scan URL to Database: " + str(e)

def index(request):
    print "[INFO] Mobile Security Framework v0.8.9_dev_beta"
    context = {}
    template="index.html"
    return render(request,template,context)
def handle_uploaded_file(f,typ):
    DIR = settings.BASE_DIR
    md5 = hashlib.md5() #modify if crash for large 
    for chunk in f.chunks():
        md5.update(chunk)
    md5sum = md5.hexdigest()
    ANAL_DIR=os.path.join(DIR,'uploads/'+md5sum+'/')
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
                if (file_type=="application/octet-stream" or file_type=="application/vnd.android.package-archive" or file_type=="application/x-zip-compressed") and request.FILES['file'].name.endswith('.apk'):     #APK
                    md5=handle_uploaded_file(request.FILES['file'],'.apk')
                    response_data['url'] = 'StaticAnalyzer/?name='+request.FILES['file'].name+'&type=apk&checksum='+md5
                    response_data['status'] = 'success'
                    PushtoRecent(request.FILES['file'].name,md5,response_data['url'])
                elif (file_type=="application/zip" or file_type=="application/octet-stream" or file_type=="application/x-zip-compressed") and request.FILES['file'].name.endswith('.zip'):   #Android /iOS Zipped Source
                    md5=handle_uploaded_file(request.FILES['file'],'.zip')
                    response_data['url'] = 'StaticAnalyzer/?name='+request.FILES['file'].name+'&type=zip&checksum='+md5
                    response_data['status'] = 'success'
                    PushtoRecent(request.FILES['file'].name,md5,response_data['url'])
                elif ((file_type=="application/octet-stream" or file_type=="application/x-itunes-ipa" or file_type=="application/x-zip-compressed") and request.FILES['file'].name.endswith('.ipa')):   #iOS Binary
                    if platform.system()=="Darwin":
                        md5=handle_uploaded_file(request.FILES['file'],'.ipa')
                        response_data['url'] = 'StaticAnalyzer_iOS/?name='+request.FILES['file'].name+'&type=ipa&checksum='+md5
                        response_data['status'] = 'success'
                        PushtoRecent(request.FILES['file'].name,md5,response_data['url'])
                    else:
                        response_data['url'] = 'MAC_ONLY/'
                        response_data['status'] = 'success'
                else:
                    response_data['url'] = ''
                    response_data['description'] = 'File format not Supported!'
                    response_data['status'] = 'error'
            else:
                response_data['url'] = ''
                response_data['description'] = 'Invalid Form Data!'
                response_data['status'] = 'error'
        else:
            response_data['url'] = ''
            response_data['description'] = 'Method not Supported!'
            response_data['status'] = 'error'
            form = UploadFileForm()
        r= HttpResponse(json.dumps(response_data),content_type="application/json")
        r['Access-Control-Allow-Origin']='*'
        return r
    except Exception as e:
        print "\n[ERROR] Uploading File:  " + str(e)
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
    else:
        return HttpResponseRedirect('/error/') 

