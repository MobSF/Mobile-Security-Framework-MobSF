# -*- coding: utf_8 -*-
"""Windows Analysis Module."""
import re
import os
import io
from os.path import expanduser
import platform

# Binskim/Binscope analysis
import xmlrpclib
import json
import base64
import rsa

# Local analysis
import configparser
import subprocess

# XML-Manifest
from lxml import etree

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from StaticAnalyzer.views.shared_func import (
    file_size,
    hash_gen,
    unzip
)

from StaticAnalyzer.models import StaticAnalyzerWindows

from StaticAnalyzer.tools.strings import strings

from MobSF.utils import (
    print_n_send_error_response,
    python_list,
    PrintException,
)


# Only used when xmlrpc is used
proxy = None
# Used to store the local config if windows analysis happens local
config = None

##############################################################
# Code to support Windows Static Code Analysis
##############################################################
# Windows Support Functions


def staticanalyzer_windows(request, api=False):
    """Analyse a windows app."""
    try:
        # Input validation
        print "[INFO] Windows Static Analysis Started"
        app_dic = {}  # Dict to store the binary attributes
        if api:
            typ = request.POST['scan_type']
            rescan = str(request.POST.get('re_scan', 0))
            checksum = request.POST['hash']
            filename = request.POST['file_name']
        else:
            typ = request.GET['type']
            rescan = str(request.GET.get('rescan', 0))
            checksum = request.GET['checksum']
            filename = request.GET['name']
        md5_regex = re.match('^[0-9a-f]{32}$', checksum)
        if (md5_regex) and (typ in ['appx']):
            app_dic['app_name'] = filename  # APP ORGINAL NAME
            app_dic['md5'] = checksum
            app_dic['app_dir'] = os.path.join(
                settings.UPLD_DIR, app_dic['md5'] + '/')
            app_dic['tools_dir'] = os.path.join(
                settings.BASE_DIR, 'StaticAnalyzer/tools/windows/')
            if typ == 'appx':
                # DB
                db_entry = StaticAnalyzerWindows.objects.filter(  # pylint: disable-msg=E1101
                    MD5=app_dic['md5']
                )
                if db_entry.exists() and rescan == '0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                        'title': db_entry[0].TITLE,
                        'name': db_entry[0].APP_NAME,
                        'pub_name': db_entry[0].PUB_NAME,
                        'size': db_entry[0].SIZE,
                        'md5': db_entry[0].MD5,
                        'sha1': db_entry[0].SHA1,
                        'sha256': db_entry[0].SHA256,
                        'bin_name': db_entry[0].BINNAME,
                        'version':  db_entry[0].VERSION,
                        'arch':  db_entry[0].ARCH,
                        'compiler_version':  db_entry[0].COMPILER_VERSION,
                        'visual_studio_version':  db_entry[0].VISUAL_STUDIO_VERSION,
                        'visual_studio_edition':  db_entry[0].VISUAL_STUDIO_EDITION,
                        'target_os':  db_entry[0].TARGET_OS,
                        'appx_dll_version':  db_entry[0].APPX_DLL_VERSION,
                        'proj_guid':  db_entry[0].PROJ_GUID,
                        'opti_tool':  db_entry[0].OPTI_TOOL,
                        'target_run':  db_entry[0].TARGET_RUN,
                        'files': python_list(db_entry[0].FILES),
                        'strings': python_list(db_entry[0].STRINGS),
                        'bin_an_results': python_list(db_entry[0].BIN_AN_RESULTS),
                        'bin_an_warnings': python_list(db_entry[0].BIN_AN_WARNINGS)
                    }
                else:
                    print "[INFO] Windows Binary Analysis Started"
                    app_dic['app_path'] = os.path.join(
                        app_dic['app_dir'], app_dic['md5'] + '.appx')
                    # ANALYSIS BEGINS
                    app_dic['size'] = str(file_size(app_dic['app_path'])) + 'MB'
                    # Generate hashes
                    app_dic['sha1'], app_dic[
                        'sha256'] = hash_gen(app_dic['app_path'])
                    # EXTRACT APPX
                    print "[INFO] Extracting APPX"
                    app_dic['files'] = unzip(
                        app_dic['app_path'], app_dic['app_dir'])
                    xml_dic = _parse_xml(app_dic['app_dir'])
                    bin_an_dic = _binary_analysis(app_dic)
                    # Saving to db
                    print "\n[INFO] Connecting to DB"
                    if rescan == '1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerWindows.objects.filter(  # pylint: disable-msg=E1101
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
                            VISUAL_STUDIO_VERSION=xml_dic[
                                'visual_studio_version'],
                            VISUAL_STUDIO_EDITION=xml_dic[
                                'visual_studio_edition'],
                            TARGET_OS=xml_dic['target_os'],
                            APPX_DLL_VERSION=xml_dic['appx_dll_version'],
                            PROJ_GUID=xml_dic['proj_guid'],
                            OPTI_TOOL=xml_dic['opti_tool'],
                            TARGET_RUN=xml_dic['target_run'],
                            FILES=app_dic['files'],
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
                            VISUAL_STUDIO_VERSION=xml_dic[
                                'visual_studio_version'],
                            VISUAL_STUDIO_EDITION=xml_dic[
                                'visual_studio_edition'],
                            TARGET_OS=xml_dic['target_os'],
                            APPX_DLL_VERSION=xml_dic['appx_dll_version'],
                            PROJ_GUID=xml_dic['proj_guid'],
                            OPTI_TOOL=xml_dic['opti_tool'],
                            TARGET_RUN=xml_dic['target_run'],
                            FILES=app_dic['files'],
                            STRINGS=bin_an_dic['strings'],
                            BIN_AN_RESULTS=bin_an_dic['results'],
                            BIN_AN_WARNINGS=bin_an_dic['warnings'],
                        )
                        db_item.save()
                    context = {
                        'title': 'Static Analysis',
                        'name': app_dic['app_name'],
                        'pub_name': xml_dic['pub_name'],
                        'size': app_dic['size'],
                        'md5': app_dic['md5'],
                        'sha1': app_dic['sha1'],
                        'sha256': app_dic['sha256'],
                        'bin_name': bin_an_dic['bin_name'],
                        'version': xml_dic['version'],
                        'arch': xml_dic['arch'],
                        'compiler_version': xml_dic['compiler_version'],
                        'visual_studio_version': xml_dic['visual_studio_version'],
                        'visual_studio_edition': xml_dic['visual_studio_edition'],
                        'target_os': xml_dic['target_os'],
                        'appx_dll_version': xml_dic['appx_dll_version'],
                        'proj_guid': xml_dic['proj_guid'],
                        'opti_tool': xml_dic['opti_tool'],
                        'target_run': xml_dic['target_run'],
                        'files': app_dic['files'],
                        'strings': bin_an_dic['strings'],
                        'bin_an_results': bin_an_dic['results'],
                        'bin_an_warnings': bin_an_dic['warnings'],
                    }
                template = "static_analysis/windows_binary_analysis.html"
                if api:
                    return context
                else:
                    return render(request, template, context)
            else:
                msg = "File type not supported"
                if api:
                    return print_n_send_error_response(request, msg, True)
                else:
                    return print_n_send_error_response(request, msg, False)
        else:
            msg = "Hash match failed or Invalid file extension"
            if api:
                return print_n_send_error_response(request, msg, True)
            else:
                return print_n_send_error_response(request, msg, False)
    except Exception as exception:
        msg = str(exception)
        exp_doc = exception.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp_doc)
        else:
            return print_n_send_error_response(request, msg, False, exp_doc)

def _get_token():
    """Get the authentication token for windows vm xmlrpc client."""
    challenge = proxy.get_challenge()
    priv_key = rsa.PrivateKey.load_pkcs1(
        open(settings.WINDOWS_VM_SECRET).read())
    signature = rsa.sign(challenge, priv_key, 'SHA-512')
    sig_b64 = base64.b64encode(signature)
    return sig_b64


def _binary_analysis(app_dic):
    """Start binary analsis."""
    print "[INFO] Starting Binary Analysis"
    bin_an_dic = {}

    # Init optional sections to prevent None-Pointer-Errors
    bin_an_dic['results'] = []
    bin_an_dic['warnings'] = []

    # Search for exe
    for file_name in app_dic['files']:
        if file_name.endswith(".exe"):
            bin_an_dic['bin'] = file_name
            bin_an_dic['bin_name'] = file_name.replace(".exe", "")
            break
    if not bin_an_dic['bin_name']:
        PrintException("[ERROR] No executeable in appx.")

    bin_path = os.path.join(app_dic['app_dir'], bin_an_dic['bin'])

    # Execute strings command
    bin_an_dic['strings'] = ""
    str_list = list(strings(bin_path))
    str_list = set(str_list)  # Make unique # pylint: disable-msg=R0204

    str_list = [s if isinstance(s, unicode) else unicode(
        s, encoding="utf-8", errors="replace") for s in str_list]
    str_list = [escape(s) for s in str_list]
    bin_an_dic['strings'] = str_list

    # Search for unsave function
    pattern = re.compile("(alloca|gets|memcpy|printf|scanf|sprintf|sscanf|strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|wcsncpy|wcstok|wmemcpy)")
    for elem in str_list:
        if pattern.match(elem[5:-5]):
            result = {
                "rule_id": 'Possible Insecure Function',
                "status": 'Insecure',
                "desc": "Possible Insecure Function detected: {}".format(elem[5:-5])
            }
            bin_an_dic['results'].append(result)

    # Execute binskim analysis if vm is available
    if platform.system() != 'Windows':
        if settings.WINDOWS_VM_IP:
            print "[INFO] Windows VM configured."
            global proxy
            proxy = xmlrpclib.ServerProxy(  # pylint: disable-msg=C0103
                "http://{}:{}".format(
                    settings.WINDOWS_VM_IP,
                    settings.WINDOWS_VM_PORT
                )
            )
            name = _upload_sample(bin_path)
            bin_an_dic = __binskim(name, bin_an_dic)
            bin_an_dic = __binscope(name, bin_an_dic)
        else:
            print "[INFO] Windows VM not configured in settings.py. Skipping Binskim and Binscope."
            warning = {
                "rule_id": "VM",
                "status": "Info",
                "desc": "VM is not configured. Please read the readme.md in MobSF/install/windows."
            }
            bin_an_dic['results'].append(warning)
    else:
        print "[INFO] Running lokal analysis."

        global config
        config = configparser.ConfigParser()
        # Switch to settings definded path if available
        config.read(expanduser("~") + "\\MobSF\\Config\\config.txt")

        # Run analysis functions
        bin_an_dic = __binskim(bin_path, bin_an_dic,
                               run_local=True, app_dir=app_dic['app_dir'])
        bin_an_dic = __binscope(bin_path, bin_an_dic,
                                run_local=True, app_dir=app_dic['app_dir'])

    return bin_an_dic


def _upload_sample(bin_path):
    """Upload sample to windows vm."""
    print "[INFO] Uploading sample."

    # Upload test
    with io.open(bin_path, mode="rb") as handle:
        binary_data = xmlrpclib.Binary(handle.read())

    # Name of the sample is return by the remote machine
    name = proxy.upload_file(binary_data, _get_token())

    return name


def __binskim(name, bin_an_dic, run_local=False, app_dir=None):
    """Run the binskim analysis."""
    print "[INFO] Running binskim."
    if run_local:
        bin_path = os.path.join(app_dir, bin_an_dic['bin'])

        # Set params for execution of binskim
        if platform.machine().endswith('64'):
            binskim_path = config['binskim']['file_x64']
        else:
            binskim_path = config['binskim']['file_x86']

        command = "analyze"
        path = bin_path
        output_p = "-o"
        output_d = bin_path + "_binskim"
        verbose = "-v"
        policy_p = "--config"
        policy_d = "default"  # TODO(Other policies?)

        # Assemble
        params = [
            binskim_path,
            command,
            path,
            output_p, output_d,
            verbose,
            policy_p, policy_d
        ]

        # Execute process
        pipe = subprocess.Popen(subprocess.list2cmdline(params))
        pipe.wait()  # Wait for the process to finish..

        # Open the file and return the json
        out_file = open(output_d)
        output = json.loads(out_file.read())
    else:
        # Analyse the sample
        response = proxy.binskim(name, _get_token())

        # Load output as json
        output = json.loads(response)

    bin_an_dic = __parse_binskim(bin_an_dic, output)
    return bin_an_dic


def __parse_binskim(bin_an_dic, output):
    """Parse output to results and warnings"""
    current_run = output['runs'][0]

    if 'results' in current_run:
        rules = output['runs'][0]['rules']
        for res in current_run['results']:
            if res['level'] != "pass":
                result = {
                    "rule_id": res['ruleId'],
                    "status": "Insecure",
                    "desc": rules[res['ruleId']]['shortDescription']
                }
                if len(res['formattedRuleMessage']["arguments"])>2:
                    result["info"] = res['formattedRuleMessage']["arguments"][2]
                else:
                    result["info"] = ""
            else:
                result = {
                    "rule_id": res['ruleId'],
                    "status": "Secure",
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


def __binscope(name, bin_an_dic, run_local=False, app_dir=None):
    """Run the binskim analysis."""
    print "[INFO] Running binscope. This might take a while, depending on the binary size."

    if run_local:
        global config
        bin_path = os.path.join(app_dir, bin_an_dic['bin'])

        # Set params for execution of binskim
        binscope_path = [config['binscope']['file']]
        target = [bin_path]
        out_type = ["/Red", "/v"]
        output = ["/l", target[0] + "_binscope"]
        checks = [
            '/Checks', 'ATLVersionCheck',
            '/Checks', 'ATLVulnCheck',
            '/Checks', 'AppContainerCheck',
            '/Checks', 'CompilerVersionCheck',
            '/Checks', 'DBCheck',
            '/Checks', 'DefaultGSCookieCheck',
            '/Checks', 'ExecutableImportsCheck',
            '/Checks', 'FunctionPointersCheck',
            '/Checks', 'GSCheck',
            '/Checks', 'GSFriendlyInitCheck',
            '/Checks', 'GSFunctionSafeBuffersCheck',
            '/Checks', 'HighEntropyVACheck',
            '/Checks', 'NXCheck',
            '/Checks', 'RSA32Check',
            '/Checks', 'SafeSEHCheck',
            '/Checks', 'SharedSectionCheck',
            '/Checks', 'VB6Check',
            '/Checks', 'WXCheck',
        ]

        # Assemble
        params = (
            binscope_path +
            target +
            out_type +
            output +
            checks
        )

        # Execute process
        p = subprocess.Popen(subprocess.list2cmdline(params))
        p.wait()  # Wait for the process to finish..

        # Open the file and return the json
        f = open(output[1])
        response = f.read()
    else:
        # Analyse the sample via rpc
        response = proxy.binscope(name, _get_token())

    res = response[response.find('<'):]
    config = etree.XMLParser(  # pylint: disable-msg=E1101
        remove_blank_text=True,
        resolve_entities=False
    )
    xml_file = etree.XML(bytes(res), config)  # pylint: disable-msg=E1101

    for item in xml_file.find('items').getchildren():
        if item.find('issueType') is not None:
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
        'version': '',
        'arch': '',
        'app_name': '',
        'pub_name': '',
        'compiler_version': '',
        'visual_studio_version': '',
        'visual_studio_edition': '',
        'target_os': '',
        'appx_dll_version': '',
        'proj_guid': '',
        'opti_tool': '',
        'target_run': ''
    }

    try:
        print "[INFO] Reading AppxManifest"
        config = etree.XMLParser(  # pylint: disable-msg=E1101
            remove_blank_text=True,
            resolve_entities=False
        )
        xml = etree.XML(open(xml_file).read(),
                        config)  # pylint: disable-msg=E1101
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
