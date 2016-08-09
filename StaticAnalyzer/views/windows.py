# -*- coding: utf_8 -*-
"""Windows Analysis Module."""
try:
    import StringIO
    StringIO = StringIO.StringIO
except ImportError:
    from io import StringIO

import re
import os
import subprocess

from lxml import etree

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from shared_func import FileSize
from shared_func import HashGen
from shared_func import Unzip

from StaticAnalyzer.models import StaticAnalyzerWindows

from MobSF.utils import PrintException

##############################################################
# Code to support Windows Static Code Anlysis
##############################################################
#Windows Support Functions
def staticanalyzer_windows(request):
    """Analyse a windows app."""
    try:
        #Input validation
        print "[INFO] Windows Static Analysis Started"
        app_dic = {} # Dict to store the binary attributes
        typ = request.GET['type']
        rescan = str(request.GET.get('rescan', 0))
        md5_regex = re.match('^[0-9a-f]{32}$', request.GET['checksum'])
        if (md5_regex) and (typ in ['appx']):
            app_dic['app_name'] = request.GET['name'] #APP ORGINAL NAME
            app_dic['md5'] = request.GET['checksum']
            app_dic['app_dir'] = os.path.join(settings.UPLD_DIR, app_dic['md5']+'/')
            app_dic['tools_dir'] = os.path.join(settings.BASE_DIR, 'StaticAnalyzer/tools/windows/')
            if typ == 'appx':
                # DB
                db_entry = StaticAnalyzerWindows.objects.filter(MD5=app_dic['md5'])
                if db_entry.exists() and rescan == '0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                        'title' : db_entry[0].TITLE,
                        'name' : db_entry[0].APP_NAME,
                        'pub_name' : db_entry[0].PUB_NAME,
                        'size' : db_entry[0].SIZE,
                        'md5': db_entry[0].MD5,
                        'sha1' : db_entry[0].SHA1,
                        'sha256' : db_entry[0].SHA256,
                        'bin_name' : db_entry[0].BINNAME,
                        'bin_anal' : db_entry[0].BIN_ANAL,
                        'version' :  db_entry[0].VERSION,
                        'arch' :  db_entry[0].ARCH,
                        'compiler_version' :  db_entry[0].COMPILER_VERSION,
                        'visual_studio_version' :  db_entry[0].VISUAL_STUDIO_VERSION,
                        'visual_studio_edition' :  db_entry[0].VISUAL_STUDIO_EDITION,
                        'target_os' :  db_entry[0].TARGET_OS,
                        'appx_dll_version' :  db_entry[0].APPX_DLL_VERSION,
                        'proj_guid' :  db_entry[0].PROJ_GUID,
                        'opti_tool' :  db_entry[0].OPTI_TOOL,
                        'target_run' :  db_entry[0].TARGET_RUN,
                        'strings' : db_entry[0].STRINGS
                    }
                else:
                    print "[INFO] Windows Binary Analysis Started"
                    app_dic['app_path'] = app_dic['app_dir'] + app_dic['md5'] + '.appx'
                    # ANALYSIS BEGINS
                    app_dic['size'] = str(FileSize(app_dic['app_path'])) + 'MB'
                    # Generate hashes
                    app_dic['sha1'], app_dic['sha256'] = HashGen(app_dic['app_path'])
                    # EXTRACT APPX
                    print "[INFO] Extracting APPX"
                    Unzip(app_dic['app_path'], app_dic['app_dir'])
                    xml_dic = _parse_xml(app_dic['app_dir'])
                    bin_an_dic = _binary_analysis(app_dic['tools_dir'], app_dic['app_dir'])
                    # Saving to db
                    print "\n[INFO] Connecting to DB"
                    if rescan == '1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerWindows.objects.filter(
                            MD5=app_dic['md5']
                        ).update(
                            TITLE='Static Analysis',
                            APP_NAME=app_dic['app_name'],
                            PUB_NAME=xml_dic['pub_name'],
                            SIZE=app_dic['size'],
                            MD5=app_dic['md5'],
                            SHA1=app_dic['sha1'],
                            SHA256=app_dic['sha256'],
                            BINNAME=bin_an_dic['bin_name'],
                            VERSION=xml_dic['version'],
                            ARCH=xml_dic['arch'],
                            COMPILER_VERSION=xml_dic['compiler_version'],
                            VISUAL_STUDIO_VERSION=xml_dic['visual_studio_version'],
                            VISUAL_STUDIO_EDITION=xml_dic['visual_studio_edition'],
                            TARGET_OS=xml_dic['target_os'],
                            APPX_DLL_VERSION=xml_dic['appx_dll_version'],
                            PROJ_GUID=xml_dic['proj_guid'],
                            OPTI_TOOL=xml_dic['opti_tool'],
                            TARGET_RUN=xml_dic['target_run'],
                            STRINGS=bin_an_dic['strings'],
                            # BIN_ANAL=BIN_ANAL,
                        )
                    elif rescan == '0':
                        print "\n[INFO] Saving to Database"
                        db_item = StaticAnalyzerWindows(
                            TITLE='Static Analysis',
                            APP_NAME=app_dic['app_name'],
                            PUB_NAME=xml_dic['pub_name'],
                            SIZE=app_dic['size'],
                            MD5=app_dic['md5'],
                            SHA1=app_dic['sha1'],
                            SHA256=app_dic['sha256'],
                            BINNAME=bin_an_dic['bin_name'],
                            VERSION=xml_dic['version'],
                            ARCH=xml_dic['arch'],
                            COMPILER_VERSION=xml_dic['compiler_version'],
                            VISUAL_STUDIO_VERSION=xml_dic['visual_studio_version'],
                            VISUAL_STUDIO_EDITION=xml_dic['visual_studio_edition'],
                            TARGET_OS=xml_dic['target_os'],
                            APPX_DLL_VERSION=xml_dic['appx_dll_version'],
                            PROJ_GUID=xml_dic['proj_guid'],
                            OPTI_TOOL=xml_dic['opti_tool'],
                            TARGET_RUN=xml_dic['target_run'],
                            STRINGS=bin_an_dic['strings'],
                            #BIN_ANAL=BIN_ANAL,
                        )
                        db_item.save()
                    context = {
                        'title' : 'Static Analysis',
                        'name' : app_dic['app_name'],
                        'pub_name' : xml_dic['pub_name'],
                        'size' : app_dic['size'],
                        'md5': app_dic['md5'],
                        'sha1' : app_dic['sha1'],
                        'sha256' : app_dic['sha256'],
                        'bin_name' : bin_an_dic['bin_name'],
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
                        'strings' : bin_an_dic['strings'],
                        #'bin_anal' : BIN_ANAL,
                    }
                template = "windows_binary_analysis.html"
                return render(request, template, context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except Exception as exception:
        PrintException("[ERROR] Static Analyzer Windows")
        context = {
            'title' : 'Error',
            'exp' : exception.message,
            'doc' : exception.__doc__
        }
        template = "error.html"
        return render(request, template, context)

def _binary_analysis(tools_dir, app_dir):
    """Start binary analsis."""
    print "[INFO] Starting Binary Analysis - XML"
    bin_an_dic = {}
    dirs = os.listdir(app_dir)
    for file_name in dirs:
        if file_name.endswith(".exe"):
            bin_an_dic['bin'] = file_name
            bin_an_dic['bin_name'] = file_name.replace(".exe", "")
            break
    if not bin_an_dic['bin_name']:
        PrintException("[ERROR] No executeable in appx.")

    bin_path = os.path.join(app_dir, bin_an_dic['bin'])

    args = ["strings", bin_path]
    bin_an_dic['strings'] = escape(subprocess.check_output(args))
    bin_an_dic['strings'] = bin_an_dic['strings'].replace("\n", "</br>")
    return bin_an_dic

def _parse_xml(app_dir):
    """Parse the AppxManifest file to get basic informations."""
    print "[INFO] Starting Binary Analysis - XML"
    xml_file = os.path.join(app_dir, "AppxManifest.xml")
    xml_dic = {}

    try:
        print "[INFO] Reading AppxManifest"
        config = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
        xml = etree.XML(open(xml_file).read(), config)
        for child in xml.getchildren():
            if child.tag.endswith("}Identity"): # } to prevent conflict with PhoneIdentity..
                xml_dic['version'] = child.get("Version")
                xml_dic['arch'] = child.get("ProcessorArchitecture")
            elif child.tag.endswith("Properties"):
                for sub_child in child.getchildren():
                    if sub_child.tag.endswith("}DisplayName"):
                        # TODO(Needed? Compare to existing app_name)
                        xml_dic['app_name'] = sub_child.text
                    elif sub_child.tag.endswith("}PublisherDisplayName"):
                        xml_dic['pub_name'] = sub_child.text
            elif child.tag.endswith("}Metadata"):
                xml_dic = __parse_xml_metadata(xml_dic, child)
    except:
        PrintException("[ERROR] - Reading from AppxManifest.xml")
    return xml_dic


def __parse_xml_metadata(xml_dic, xml_node):
    """Return the XML Metadata."""
    for child in xml_node.getchildren():
        if child.get('Name') == "cl.exe":
            xml_dic['compiler_version'] = child.get('Version')
        elif child.get('Name') == "VisualStudio":
            xml_dic['visual_studio_version'] = child.get('Version')
        elif child.get('Name') == "VisualStudioEdition":
            xml_dic['visual_studio_edition'] = child.get('Value')
        elif child.get('Name') == "OperatingSystem":
            xml_dic['target_os'] = child.get('Version')
        elif child.get('Name') == "Microsoft.Build.AppxPackage.dll":
            xml_dic['appx_dll_version'] = child.get('Version')
        elif child.get('Name') == "ProjectGUID":
            xml_dic['proj_guid'] = child.get('Value')
        elif child.get('Name') == "OptimizingToolset":
            xml_dic['opti_tool'] = child.get('Value')
        elif child.get('Name') == "TargetRuntime":
            xml_dic['target_run'] = child.get('Value')
    return xml_dic
