# -*- coding: utf_8 -*-
"""Windows Analysis Module."""
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from shared_func import FileSize
from shared_func import HashGen
from shared_func import Unzip

from StaticAnalyzer.models import StaticAnalyzerWindows

from MobSF.utils import PrintException
from MobSF.utils import isFileExists

from lxml import etree

import re
import os
import subprocess

try:
    import xhtml2pdf.pisa as pisa
except ImportError:
    PrintException("[ERROR] xhtml2pdf is not installed. Cannot generate PDF reports")

try:
    import StringIO
    StringIO = StringIO.StringIO
except ImportError:
    from io import StringIO

##############################################################
# Code to support Windows Static Code Anlysis
##############################################################
#Windows Support Functions
def staticanalyzer_windows(request):
    """Analyse a windows app."""
    try:
        #Input validation
        print "[INFO] Windows Static Analysis Started"
        typ = request.GET['type']
        rescan = str(request.GET.get('rescan', 0))
        m = re.match('^[0-9a-f]{32}$', request.GET['checksum'])
        if (m) and (typ in ['appx']):
            APP_NAME = request.GET['name'] #APP ORGINAL NAME
            MD5 = request.GET['checksum']  #MD5
            APP_DIR = os.path.join(settings.UPLD_DIR, MD5+'/') #APP DIRECTORY
            TOOLS_DIR = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/tools/windows/')  #TOOLS DIR
            if typ == 'appx':
                #DB
                DB = StaticAnalyzerWindows.objects.filter(MD5=MD5)
                if DB.exists() and rescan == '0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                        'title' : DB[0].TITLE,
                        'name' : DB[0].APP_NAME,
                        'size' : DB[0].SIZE,
                        'md5': DB[0].MD5,
                        'sha1' : DB[0].SHA1,
                        'sha256' : DB[0].SHA256,
                        'bin_name' : DB[0].BINNAME,
                        'bin_anal' : DB[0].BIN_ANAL,
                        'strings' : DB[0].STRINGS
                    }
                else:
                    print "[INFO] Windows Binary Analysis Started"
                    APP_PATH = APP_DIR + MD5 + '.appx'      # Filename and dir
                    #BIN_DIR = os.path.join(APP_DIR, "Payload/") # Not needed, root dir
                    # ANALYSIS BEGINS
                    SIZE = str(FileSize(APP_PATH)) + 'MB'   # FILE SIZE
                    # Generate hashes
                    SHA1, SHA256 = HashGen(APP_PATH)
                    # EXTRACT APPX
                    print "[INFO] Extracting APPX"
                    Unzip(APP_PATH, APP_DIR)
                    # BIN_NAME, BIN_ANAL, STRINGS = BinaryAnalysis(BIN_DIR, TOOLS_DIR, APP_DIR)
                    xml_dic = parse_xml(APP_DIR)
                    BIN_NAME = binary_analysis(TOOLS_DIR, APP_DIR)
                    # Saving to DB
                    print "\n[INFO] Connecting to DB"
                    if rescan == '1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerWindows.objects.filter(
                            MD5=MD5
                        ).update(
                            TITLE='Static Analysis',
                            APP_NAME=APP_NAME,
                            PUB_NAME=xml_dic['pub_name'],
                            SIZE=SIZE,
                            MD5=MD5,
                            SHA1=SHA1,
                            SHA256=SHA256,
                            BINNAME=BIN_NAME,
                            VERSION= xml_dic['version'],
                            ARCH=xml_dic['arch'],
                            COMPILER_VERSION=xml_dic['compiler_version'],
                            VISUAL_STUDIO_VERSION=xml_dic['visual_studio_version'],
                            VISUAL_STUDIO_EDITION=xml_dic['visual_studio_edition'],
                            TARGET_OS=xml_dic['target_os'],
                            APPX_DLL_VERSION=xml_dic['appx_dll_version'],
                            PROJ_GUID=xml_dic['proj_guid'],
                            OPTI_TOOL=xml_dic['opti_tool'],
                            TARGET_RUN=xml_dic['target_run'],
                            # BIN_ANAL=BIN_ANAL,
                            # STRINGS=STRINGS
                        )
                    elif rescan == '0':
                        print "\n[INFO] Saving to Database"
                        STATIC_DB = StaticAnalyzerWindows(
                            TITLE='Static Analysis',
                            APP_NAME=APP_NAME,
                            PUB_NAME=xml_dic['pub_name'],
                            SIZE=SIZE,
                            MD5=MD5,
                            SHA1=SHA1,
                            SHA256=SHA256,
                            BINNAME=BIN_NAME,
                            VERSION= xml_dic['version'],
                            ARCH=xml_dic['arch'],
                            COMPILER_VERSION=xml_dic['compiler_version'],
                            VISUAL_STUDIO_VERSION=xml_dic['visual_studio_version'],
                            VISUAL_STUDIO_EDITION=xml_dic['visual_studio_edition'],
                            TARGET_OS=xml_dic['target_os'],
                            APPX_DLL_VERSION=xml_dic['appx_dll_version'],
                            PROJ_GUID=xml_dic['proj_guid'],
                            OPTI_TOOL=xml_dic['opti_tool'],
                            TARGET_RUN=xml_dic['target_run'],
                            #BIN_ANAL=BIN_ANAL,
                            #STRINGS=STRINGS
                        )
                        STATIC_DB.save()
                    context = {
                        'title' : 'Static Analysis',
                        'name' : APP_NAME,
                        'pub_name' : xml_dic['pub_name'],
                        'size' : SIZE,
                        'md5': MD5,
                        'sha1' : SHA1,
                        'sha256' : SHA256,
                        'bin_name' : BIN_NAME,
                        'version' : xml_dic['version'],
                        'arch' : xml_dic['arch'],
                        'compiler_version' : xml_dic['compiler_version'],
                        'visual_studio_version' : xml_dic['visual_studio_version'],
                        'visual_studio_edition' : xml_dic['visual_studio_edition'],
                        'target_os' : xml_dic['target_os'],
                        'appx_dll_version' : xml_dic['appx_dll_version'],
                        'proj_guid' : xml_dic['proj_guid'],
                        'opti_tool' : xml_dic['opti_tool'],
                        'target_run' : xml_dic['target_run'],
                        #'bin_anal' : BIN_ANAL,
                        #'strings' : STRINGS,
                    }
                template = "windows_binary_analysis.html"
                return render(request, template, context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except Exception as e:
        PrintException("[ERROR] Static Analyzer Windows")
        context = {
            'title' : 'Error',
            'exp' : e.message,
            'doc' : e.__doc__
        }
        template = "error.html"
        return render(request, template, context)

def binary_analysis(TOOLS_DIR, APP_DIR):
    """Start binary analsis."""
    print "[INFO] Starting Binary Analysis - XML"
    dirs = os.listdir(APP_DIR)
    for d in dirs:
        if d.endswith(".exe"):
            break
    BIN_DIR = os.path.join(APP_DIR, d)         #Full Dir/Payload/x.app

    xml_file = os.path.join(APP_DIR, "AppxManifest.xml")
    xml_dic = {}

    BIN = d.replace(".exe", "")
    bin_name = BIN
    return bin_name

def parse_xml(APP_DIR):
    """Parse the AppxManifest file to get basic informations."""
    try:
        print "[INFO] Starting Binary Analysis - XML"
        xml_file = os.path.join(APP_DIR, "AppxManifest.xml")
        xml_dic = {}

        try:
            print "[INFO] Reading AppxManifest"
            # TODO (Parse XML, display)
            config = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
            xml = etree.XML(open(xml_file).read(), config)
            for child in xml.getchildren():
                if child.tag.endswith("}Identity"): # } to prevent conflict with PhoneIdentity..
                    print "[*] Found Identity"
                    xml_dic['version'] = child.get("Version")
                    xml_dic['arch'] = child.get("ProcessorArchitecture")
                elif child.tag.endswith("Properties"):
                    print("Found Properties")
                    for sub_child in child.getchildren():
                        if sub_child.tag.endswith("}DisplayName"):
                            xml_dic['app_name'] = sub_child.text # TODO(Needed? Compare to existing app_name)
                        elif sub_child.tag.endswith("}PublisherDisplayName"):
                            xml_dic['pub_name'] = sub_child.text
                elif child.tag.endswith("}Metadata"):
                    print "[*] Metadata found"
                    for sub_child in child.getchildren():
                        if sub_child.get('Name') == "cl.exe":
                            print "[*] compiler_version found"
                            xml_dic['compiler_version'] = sub_child.get('Version')
                        elif sub_child.get('Name') == "VisualStudio":
                            print "[*] visual_studio_version found"
                            xml_dic['visual_studio_version'] = sub_child.get('Version')
                        elif sub_child.get('Name') == "VisualStudioEdition":
                            print "[*] visual_studio_edition found"
                            xml_dic['visual_studio_edition'] = sub_child.get('Value')
                        elif sub_child.get('Name') == "OperatingSystem":
                            print "[*] target_os found"
                            xml_dic['target_os'] = sub_child.get('Version')
                        elif sub_child.get('Name') == "Microsoft.Build.AppxPackage.dll":
                            print "[*] appx_dll_version found"
                            xml_dic['appx_dll_version'] = sub_child.get('Version')
                        elif sub_child.get('Name') == "ProjectGUID":
                            print "[*] proj_guid found"
                            xml_dic['proj_guid'] = sub_child.get('Value')
                        elif sub_child.get('Name') == "OptimizingToolset":
                            print "[*] opti_tool found"
                            xml_dic['opti_tool'] = sub_child.get('Value')
                        elif sub_child.get('Name') == "TargetRuntime":
                            print "[*] target_run found"
                            xml_dic['target_run'] = sub_child.get('Value')
            # p = plistlib.readPlistFromString(XML)
        except:
            PrintException("[ERROR] - Reading from AppxManifest.xml")
        return xml_dic
    except Exception:
        PrintException("[ERROR] iOS Binary Analysis")
