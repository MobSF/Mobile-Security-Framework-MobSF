"""
Standalone Android Dynamic Analysis
"""
# -*- coding: utf_8 -*-
import os
import subprocess
from django.shortcuts import render
from django.conf import settings
from DynamicAnalyzer.views.android.android_virtualbox_vm import (
    refresh_vm
)
from DynamicAnalyzer.views.android.android_dyn_shared import (
    connect,
    get_identifier,
)
from DynamicAnalyzer.pyWebProxy.pywebproxy import Proxy
from MobSF.utils import getADB


def dynamic_analyzer_standalone(request):
    """Standalone Dynamic Analysis"""
    print "\n[INFO] Starting Standalone Android Dynamic Analyzer"
    toolsdir = os.path.join(
        settings.BASE_DIR, 'DynamicAnalyzer/tools/')  # TOOLS DIR
    Proxy("", "", "", "")
    if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_REAL_DEVICE":
        print "\n[INFO] MobSF will perform Dynamic Analysis on real Android Device"
    else:
        # Refersh VM
        refresh_vm(settings.UUID, settings.SUUID, settings.VBOX)
    connect(toolsdir)
    print get_packages(toolsdir)
    context = {'md5': '',
               'pkg': '',
               'lng': '',
               'title': 'Start Testing', }
    template = "dynamic_analysis/start_test_standalone.html"
    return render(request, template, context)


def get_packages(toolsdir):
    """Get List of Pacakges"""
    adb = getADB(toolsdir)
    args = [adb, "-s", get_identifier(), "shell", "ls", "/data/data"]
    # prolly a better way to get packages is needed
    try:
        return subprocess.check_output(args)
    except:
        return "error"
