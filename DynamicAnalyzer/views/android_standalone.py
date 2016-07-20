"""
Standalone Android Dynamic Analysis
"""
# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.conf import settings
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.html import escape
from DynamicAnalyzer.views.android import RefreshVM, getADB, getIdentifier, Connect
from DynamicAnalyzer.pyWebProxy.pywebproxy import *

import subprocess


def DynamicAnalyzer(request):
    print "\n[INFO] Starting Standalone Android Dynamic Analyzer"
    TOOLS_DIR=os.path.join(settings.BASE_DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
    Proxy("","","","")
    if settings.REAL_DEVICE:
        print "\n[INFO] MobSF will perform Dynamic Analysis on real Android Device"
    else:
        #Refersh VM
        RefreshVM(settings.UUID,settings.SUUID,settings.VBOX)
    Connect(TOOLS_DIR)
    print GetPackages(TOOLS_DIR)
    context = {'md5' : '',
               'pkg' : '',
               'lng' : '',
               'title': 'Start Testing',}
    template="dynamic_analysis/start_test_standalone.html"
    return render(request,template,context)

def GetPackages(TOOLSDIR):
    adb=getADB(TOOLSDIR)
    args=[adb, "-s", getIdentifier(), "shell", "ls", "/data/data"]
    #prolly a better way to get packages is needed
    try:
        return subprocess.check_output(args)
    except:
        return "error"