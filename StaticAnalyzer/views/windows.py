# -*- coding: utf_8 -*-
"""Windows Analysis Module."""
try:
    import StringIO
    StringIO = StringIO.StringIO
except ImportError:
    from io import StringIO

import ast
import re
import os
import subprocess

# Binskim analysis
import json
import requests

# XML-Manifest
from lxml import etree

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from shared_func import FileSize
from shared_func import HashGen
from shared_func import Unzip

from StaticAnalyzer.models import StaticAnalyzerWindows

from StaticAnalyzer.tools.strings import strings

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
                        'strings' : db_entry[0].STRINGS,
                        'bin_an_results' : ast.literal_eval(db_entry[0].BIN_AN_RESULTS),
                        'bin_an_warnings' : ast.literal_eval(db_entry[0].BIN_AN_WARNINGS)
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
                            BIN_AN_RESULTS=bin_an_dic['results'],
                            BIN_AN_WARNINGS=bin_an_dic['warnings'],
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
                            BIN_AN_RESULTS=bin_an_dic['results'],
                            BIN_AN_WARNINGS=bin_an_dic['warnings'],
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
                        'bin_an_results' : bin_an_dic['results'],
                        'bin_an_warnings' : bin_an_dic['warnings'],
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
    print "[INFO] Starting Binary Analysis"
    bin_an_dic = {}

    # Init optional sections to prevent None-Pointer-Errors
    bin_an_dic['results'] = []
    bin_an_dic['warnings'] = []

    # Search for exe
    dirs = os.listdir(app_dir)
    for file_name in dirs:
        if file_name.endswith(".exe"):
            bin_an_dic['bin'] = file_name
            bin_an_dic['bin_name'] = file_name.replace(".exe", "")
            break
    if not bin_an_dic['bin_name']:
        PrintException("[ERROR] No executeable in appx.")

    bin_path = os.path.join(app_dir, bin_an_dic['bin'])

    # Execute strings command
    bin_an_dic['strings'] = ""
    sl = list(strings(bin_path))
    sl = set(sl)  # Make unique
    sl = [escape(s) for s in sl]
    bin_an_dic['strings'] = "</br>".join(sl)

    # Execute binskim analysis if vm is available
    if settings.WINDOWS_VM_IP != "0.0.0.0":
        print "[INFO] WindowsVM configured."
        name = _upload_sample(bin_path)
        bin_an_dic = __binskim(name, bin_an_dic)
        bin_an_dic = __binscope(name, bin_an_dic)
    else:
        print "[INFO] WindowsVM not configured in settings.py. Skipping Binskim and Binscope."
        warning = {
            "rule_id": "VM",
            "status": "Info",
            "desc": "VM is not configured. Please read the readme.md in MobSF/install/windows."
        }
        bin_an_dic['results'].append(warning)


    return bin_an_dic

def _upload_sample(bin_path):
    """Upload sample to windows vm."""
    print "[INFO] Uploading sample."

    # Upload sample
    url = 'http://{}:5000/upload'.format(settings.WINDOWS_VM_IP)
    files = {'file': open(bin_path, 'rb')}
    response = requests.post(url, files=files)

    # Name of the sample is return by the remote machine
    name = response.text
    return name

def __binskim(name, bin_an_dic):
    """Run the binskim analysis."""
    print "[INFO] Running binskim."
    # Analyse the sample
    url = 'http://{}:5000/static_analyze/binskim/{}'.format(settings.WINDOWS_VM_IP, name.strip())
    response = requests.get(url)

    # Load output as json
    output = json.loads(response.text)

    # Parse output to results and warnings
    current_run = output['runs'][0]

    if 'results' in current_run:
        rules = output['runs'][0]['rules']
        for res in current_run['results']:
            result = {
                "rule_id": res['ruleId'],
                "status": "Insecure",
                "desc": rules[res['ruleId']]['shortDescription']
            }
            bin_an_dic['results'].append(result)
    else:
        print "[WARNING] binskim has no results."
        # Create an warining for the gui
        warning = {
            "rule_id": "No Binskim-Results",
            "status": "Info",
            "desc": "No results from Binskim."
        }
        bin_an_dic['warnings'].append(warning)

    if 'configurationNotifications' in current_run:
        for warn in current_run['configurationNotifications']:
            warning = {
                "rule_id": warn['ruleId'],
                "status": "Info",
                "desc": warn['message']
            }
            bin_an_dic['warnings'].append(warning)

    # Return updated dict
    return bin_an_dic

def __binscope(name, bin_an_dic):
    """Run the binskim analysis."""
    print "[INFO] Running binscope. This might take a while, depending on the binary size."
    # Analyse the sample
    url = (
        'http://{}:5000/static_analyze/binscope/{}'.format(settings.WINDOWS_VM_IP, name.strip())
    )
    response = requests.get(url)

    # Load output as json
    #output = json.loads(response.text)
    print response.text

    res = response.text[response.text.find('<'):]
    config = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
    xml_file = etree.XML(bytes(res), config)

    for item in xml_file.find('items').getchildren():
        if item.find('issueType') is not None:
            print "Type: {}".format(item.find('issueType').text)
            print "Result: {}".format(item.find('result').text)

            res = item.find('result').text

            if res == 'PASS':
                status = "Secure"
                try:
                    desc = item.find('Information').text
                except AttributeError:
                    desc = "No description provided by analysing tool."
            elif res == 'FAIL':
                status = "Insecure"

                if item.find('Failure1') is not None:
                    desc = item.find('Failure1').text
                elif item.find('Information') is not None:
                    desc = item.find('Information').text
                elif item.find('diagnostic') is not None:
                    status = "Info"
                    desc = item.find('diagnostic').text
                else:
                    desc = "No description provided by analysing tool."

            result = {
                "rule_id": item.find('issueType').text,
                "status": status,
                "desc": desc
            }
            bin_an_dic['results'].append(result)

    return bin_an_dic

def _parse_xml(app_dir):
    """Parse the AppxManifest file to get basic informations."""
    print "[INFO] Starting Binary Analysis - XML"
    xml_file = os.path.join(app_dir, "AppxManifest.xml")
    xml_dic = {
        'version' : '',
        'arch' : '',
        'app_name' : '',
        'pub_name' : '',
        'compiler_version' : '',
        'visual_studio_version' : '',
        'visual_studio_edition' : '',
        'target_os' : '',
        'appx_dll_version' : '',
        'proj_guid' : '',
        'opti_tool' : '',
        'target_run' : ''
    }

    try:
        print "[INFO] Reading AppxManifest"
        config = etree.XMLParser(remove_blank_text=True, resolve_entities=False)
        xml = etree.XML(open(xml_file).read(), config)
        for child in xml.getchildren():
            # } to prevent conflict with PhoneIdentity..
            if isinstance(child.tag, str) and child.tag.endswith("}Identity"):
                xml_dic['version'] = child.get("Version")
                xml_dic['arch'] = child.get("ProcessorArchitecture")
            elif isinstance(child.tag, str) and child.tag.endswith("Properties"):
                for sub_child in child.getchildren():
                    if sub_child.tag.endswith("}DisplayName"):
                        # TODO(Needed? Compare to existing app_name)
                        xml_dic['app_name'] = sub_child.text
                    elif sub_child.tag.endswith("}PublisherDisplayName"):
                        xml_dic['pub_name'] = sub_child.text
            elif isinstance(child.tag, str) and child.tag.endswith("}Metadata"):
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
