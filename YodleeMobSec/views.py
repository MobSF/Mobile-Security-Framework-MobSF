from django.shortcuts import render
from django.http import HttpResponseRedirect
from .forms import UploadFileForm
from django.conf import settings
import os, hashlib
# Create your views here.

def index(request):
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
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            file_type =request.FILES['file'].content_type
            print file_type
            if file_type=="application/octet-stream" and request.FILES['file'].name.endswith('.apk'):     #APK
                md5=handle_uploaded_file(request.FILES['file'],'.apk')
                return HttpResponseRedirect('/StaticAnalyzer/?name='+request.FILES['file'].name+'&type=apk&checksum='+md5)  
            elif (file_type=="application/zip" or file_type=="application/octet-stream") and request.FILES['file'].name.endswith('.zip'):   #Android Zipped Source
                md5=handle_uploaded_file(request.FILES['file'],'.zip')
                return HttpResponseRedirect('/StaticAnalyzer/?name='+request.FILES['file'].name+'&type=zip&checksum='+md5)
            else:
                 return HttpResponseRedirect('/')
        else:
             return HttpResponseRedirect('/')
    else:
        form = UploadFileForm()
    return HttpResponseRedirect('/')
def about(request):
    context = {'title': 'About'}
    template="about.html"
    return render(request,template,context)
def features(request):
    context = {'title': 'Feature'}
    template="features.html"
    return render(request,template,context)
def error(request):
    context = {'title':'Error'}
    template ="error.html"
    return render(request,template,context)
def Android_ZIP_FORMAT(request):
    context = {'title':'Android ZIP Source Instruction'}
    template ="androidzip.html"
    return render(request,template,context)