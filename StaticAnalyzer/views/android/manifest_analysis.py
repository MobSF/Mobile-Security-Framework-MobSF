# -*- coding: utf_8 -*-
"""Module for android manifest analysis."""

import io
import os
import subprocess

from xml.dom import minidom

from django.conf import settings

from MobSF.utils import (
    PrintException,
    isFileExists
)

# pylint: disable=E0401
from .dvm_permissions import DVM_PERMISSIONS

def format_permissions(permissions):
    """Format the permissions for html output."""
    try:
        print "[INFO] Formatting Permissions"
        desc = ''
        for ech in permissions:
            desc = desc + '<tr><td>' + ech + '</td>'
            for local in permissions[ech]: #TODO(No idea what l stands for, using local as dummy)
                desc = desc + '<td>' + local + '</td>'
            desc = desc+ '</tr>'
        desc = desc.replace(
            'dangerous',
            '<span class="label label-danger">dangerous</span>').replace(
                'normal',
                '<span class="label label-info">normal</span>'
            ).replace(
                'signatureOrSystem',
                '<span class="label label-warning">SignatureOrSystem</span>'
            ).replace(
                'signature',
                '<span class="label label-success">signature</span>'
            )
        return desc
    except:
        PrintException("[ERROR] Formatting Permissions")

def get_manifest(app_dir, toosl_dir, typ, binary):
    """Get the manifest file."""
    try:
        dat = read_manifest(app_dir, toosl_dir, typ, binary).replace("\n", "")
        try:
            print "[INFO] Parsing AndroidManifest.xml"
            manifest = minidom.parseString(dat)
        except:
            PrintException("[ERROR] Pasrsing AndroidManifest.xml")
            manifest = minidom.parseString(
                (
                    r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android='
                    r'"http://schemas.android.com/apk/res/android" android:versionCode="Failed"  '
                    r'android:versionName="Failed" package="Failed"  '
                    r'platformBuildVersionCode="Failed" '
                    r'platformBuildVersionName="Failed XML Parsing" ></manifest>'
                )
            )
            print "[WARNING] Using Fake XML to continue the Analysis"
        return manifest
    except:
        PrintException("[ERROR] Parsing Manifest file")


def manifest_data(mfxml):
    """Extract manifest data."""
    try:
        print "[INFO] Extracting Manifest Data"
        svc = []
        act = []
        brd = []
        cnp = []
        lib = []
        perm = []
        dvm_perm = {}
        package = ''
        minsdk = ''
        maxsdk = ''
        targetsdk = ''
        mainact = ''
        androidversioncode = ''
        androidversionname = ''
        permissions = mfxml.getElementsByTagName("uses-permission")
        manifest = mfxml.getElementsByTagName("manifest")
        activities = mfxml.getElementsByTagName("activity")
        services = mfxml.getElementsByTagName("service")
        providers = mfxml.getElementsByTagName("provider")
        receivers = mfxml.getElementsByTagName("receiver")
        libs = mfxml.getElementsByTagName("uses-library")
        sdk = mfxml.getElementsByTagName("uses-sdk")
        for node in sdk:
            minsdk = node.getAttribute("android:minSdkVersion")
            maxsdk = node.getAttribute("android:maxSdkVersion")
            targetsdk = node.getAttribute("android:targetSdkVersion")
        for node in manifest:
            package = node.getAttribute("package")
            androidversioncode = node.getAttribute("android:versionCode")
            androidversionname = node.getAttribute("android:versionName")
        for activity in activities:
            act_2 = activity.getAttribute("android:name")
            act.append(act_2)
            if len(mainact) < 1:
                # ^ Fix for Shitty Manifest with more than one MAIN
                for sitem in activity.getElementsByTagName("action"):
                    val = sitem.getAttribute("android:name")
                    if val == "android.intent.action.MAIN":
                        mainact = activity.getAttribute("android:name")
                if mainact == '':
                    for sitem in activity.getElementsByTagName("category"):
                        val = sitem.getAttribute("android:name")
                        if val == "android.intent.category.LAUNCHER":
                            mainact = activity.getAttribute("android:name")
        for service in services:
            service_name = service.getAttribute("android:name")
            svc.append(service_name)

        for provider in providers:
            provider_name = provider.getAttribute("android:name")
            cnp.append(provider_name)

        for receiver in receivers:
            rec = receiver.getAttribute("android:name")
            brd.append(rec)

        for lib in libs:
            libary = lib.getAttribute("android:name")
            lib.append(libary)

        for permission in permissions:
            perm.append(permission.getAttribute("android:name"))

        for i in perm:
            prm = i
            pos = i.rfind(".")
            if pos != -1:
                prm = i[pos+1:]
            try:
                dvm_perm[i] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][prm]
            except KeyError:
                dvm_perm[i] = [
                    "dangerous",
                    "Unknown permission from android reference",
                    "Unknown permission from android reference"
                ]

        man_data_dic = {
            'services' : svc,
            'activities' : act,
            'receivers' : brd,
            'providers' : cnp,
            'libraries' : lib,
            'perm' : dvm_perm,
            'packagename' : package,
            'mainactivity' : mainact,
            'min_sdk' : minsdk,
            'max_sdk' : maxsdk,
            'target_sdk' : targetsdk,
            'androver' : androidversioncode,
            'androvername' : androidversionname
        }

        return man_data_dic
    except:
        PrintException("[ERROR] Extracting Manifest Data")


def manifest_analysis(mfxml, man_data_dic):
    """Analyse manifest file."""
    try:
        print "[INFO] Manifest Analysis Started"
        exp_count = dict.fromkeys(["act", "ser", "bro", "cnt"], 0)
        manifest = mfxml.getElementsByTagName("manifest")
        services = mfxml.getElementsByTagName("service")
        providers = mfxml.getElementsByTagName("provider")
        receivers = mfxml.getElementsByTagName("receiver")
        applications = mfxml.getElementsByTagName("application")
        datas = mfxml.getElementsByTagName("data")
        intents = mfxml.getElementsByTagName("intent-filter")
        actions = mfxml.getElementsByTagName("action")
        granturipermissions = mfxml.getElementsByTagName(
            "grant-uri-permission")
        permissions = mfxml.getElementsByTagName("permission")
        for node in manifest:
            package = node.getAttribute("package")
        ret_value = ''
        exported = []
        permission_dict = dict()
        # PERMISSION
        for permission in permissions:
            if permission.getAttribute("android:protectionLevel"):
                protectionlevel = permission.getAttribute(
                    "android:protectionLevel")
                if protectionlevel == "0x00000000":
                    protectionlevel = "normal"
                elif protectionlevel == "0x00000001":
                    protectionlevel = "dangerous"
                elif protectionlevel == "0x00000002":
                    protectionlevel = "signature"
                elif protectionlevel == "0x00000003":
                    protectionlevel = "signatureOrSystem"

                permission_dict[permission.getAttribute(
                    "android:name")] = protectionlevel
            elif permission.getAttribute("android:name"):
                permission_dict[permission.getAttribute(
                    "android:name")] = "normal"

        # APPLICATIONS
        for application in applications:

            if application.getAttribute("android:debuggable") == "true":
                ret_value = (
                    ret_value + (
                        '<tr><td>Debug Enabled For App <br>[android:debuggable=true]</td><td>'
                        '<span class="label label-danger">high</span></td><td>Debugging was enabled'
                        ' on the app which makes it easier for reverse engineers to hook a debugger'
                        ' to it. This allows dumping a stack trace and accessing debugging helper '
                        'classes.</td></tr>'
                    )
                )
            if application.getAttribute("android:allowBackup") == "true":
                ret_value = (
                    ret_value+ (
                        '<tr><td>Application Data can be Backed up<br>[android:allowBackup=true]'
                        '</td><td><span class="label label-warning">medium</span></td><td>This flag'
                        ' allows anyone to backup your application data via adb. It allows users '
                        'who have enabled USB debugging to copy application data off of the '
                        'device.</td></tr>'
                    )
                )
            elif application.getAttribute("android:allowBackup") == "false":
                pass
            else:
                ret_value = (
                    ret_value+ (
                        '<tr><td>Application Data can be Backed up<br>[android:allowBackup] flag '
                        'is missing.</td><td><span class="label label-warning">medium</span></td>'
                        '<td>The flag [android:allowBackup] should be set to false. By default it '
                        'is set to true and allows anyone to backup your application data via adb. '
                        'It allows users who have enabled USB debugging to copy application data '
                        'off of the device.</td></tr>'
                    )
                )
            if application.getAttribute("android:testOnly") == "true":
                # pylint: disable=C0301
                ret_value = (
                    ret_value+ (
                        '<tr><td>Application is in Test Mode <br>[android:testOnly=true]</td><td>'
                        '<span class="label label-danger">high</span></td><td> It may expose '
                        'functionality or data outside of itself that would cause a security hole.'
                        '</td></tr>'
                    )
                )
            for node in application.childNodes:
                appl_data = ''  # TODO(Applicaion Data? If not, pls rename.)
                if node.nodeName == 'activity':
                    itemname = 'Activity'
                    cnt_id = "act"
                    appl_data = 'n'
                elif node.nodeName == 'activity-alias':
                    itemname = 'Activity-Alias'
                    cnt_id = "act"
                    appl_data = 'n'
                elif node.nodeName == 'provider':
                    itemname = 'Content Provider'
                    cnt_id = "cnt"
                elif node.nodeName == 'receiver':
                    itemname = 'Broadcast Receiver'
                    cnt_id = "bro"
                elif node.nodeName == 'service':
                    itemname = 'Service'
                    cnt_id = "ser"
                else:
                    itemname = 'NIL'
                item = ''

                #Task Affinity
                if (
                        itemname  in ['Activity', 'Activity-Alias'] and
                        node.getAttribute("android:taskAffinity")
                ):
                    item = node.getAttribute("android:name")
                    ret_value = (
                        ret_value+ (
                            '<tr><td>TaskAffinity is set for Activity </br>(' + item +
                            ')</td><td><span class="label label-danger">high</span></td><td>If '
                            'taskAffinity is set, then other application could read the Intents '
                            'sent to Activities belonging to another task. Always use the default '
                            'setting keeping the affinity as the package name in order to prevent '
                            'sensitive information inside sent or received Intents from being read '
                            'by another application.</td></tr>'
                        )
                    )

                #LaunchMode
                if (
                        itemname in ['Activity', 'Activity-Alias'] and
                        (
                            node.getAttribute("android:launchMode") == 'singleInstance' or
                            node.getAttribute("android:launchMode") == 'singleTask'
                        )
                ):
                    item = node.getAttribute("android:name")
                    ret_value = (
                        ret_value + '<tr><td>Launch Mode of Activity ('+item + ') is not standard.'
                        '</td><td><span class="label label-danger">high</span></td><td>An Activity '
                        'should not be having the launch mode attribute set to '
                        '"singleTask/singleInstance" as it becomes root Activity and it is possible'
                        ' for other applications to read the contents of the calling Intent. So it '
                        'is required to use the "standard" launch mode attribute when sensitive '
                        'information is included in an Intent.</td></tr>'
                    )
                #Exported Check
                item = ''
                is_inf = False
                is_perm_exist = False
                if itemname != 'NIL':
                    if node.getAttribute("android:exported") == 'true':
                        perm = ''
                        item = node.getAttribute("android:name")
                        if node.getAttribute("android:permission"):
                            #permission exists
                            perm = (
                                '<strong>Permission: </strong>' +
                                node.getAttribute("android:permission")
                            )
                            is_perm_exist = True
                        if item != man_data_dic['mainactivity']:
                            if is_perm_exist:
                                prot = ""
                                if node.getAttribute("android:permission") in permission_dict:
                                    prot = (
                                        "</br><strong>protectionLevel: </strong>" +
                                        permission_dict[node.getAttribute("android:permission")]
                                    )
                                ret_value = (
                                    ret_value + '<tr><td><strong>' + itemname + '</strong> (' +
                                    item + ') is Protected by a permission.</br>' +
                                    perm + prot + ' <br>[android:exported=true]</td>' +
                                    '<td><span class="label label-info">info</span></td><td> A' +
                                    appl_data + ' ' + itemname +
                                    ' is found to be exported, but is protected by permission.' +
                                    '</td></tr>'
                                )
                            else:
                                if (itemname in ['Activity', 'Activity-Alias']):
                                    exported.append(item)
                                ret_value = (
                                    ret_value + '<tr><td><strong>' + itemname + '</strong> (' +
                                    item + ') is not Protected. <br>[android:exported=true]</td>' +
                                    '<td><span class="label label-danger">high</span></td><td> A' +
                                    appl_data + ' ' + itemname + ' is found to be shared with other'
                                    ' apps on the device therefore leaving it accessible to any '
                                    'other application on the device.</td></tr>'
                                )
                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                    elif node.getAttribute("android:exported") != 'false':
                        #Check for Implicitly Exported
                        #Logic to support intent-filter
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == "intent-filter":
                                is_inf = True
                        if is_inf:
                            item = node.getAttribute("android:name")
                            if node.getAttribute("android:permission"):
                                #permission exists
                                perm = (
                                    '<strong>Permission: </strong>' +
                                    node.getAttribute("android:permission")
                                )
                                is_perm_exist = True
                            if item != man_data_dic['mainactivity']:
                                if is_perm_exist:
                                    prot = ""
                                    if node.getAttribute("android:permission") in permission_dict:
                                        prot = (
                                            "</br><strong>protectionLevel: </strong>" +
                                            permission_dict[node.getAttribute("android:permission")]
                                        )
                                    ret_value = (
                                        ret_value + '<tr><td><strong>' + itemname + '</strong> (' +
                                        item + ') is Protected by a permission.</br>' + perm +
                                        prot + ' <br>[android:exported=true]</td>' +
                                        '<td><span class="label label-info">info</span></td>' +
                                        '<td> A' + appl_data + ' ' + itemname + ' is found to be ' +
                                        'exported, but is protected by permission.</td></tr>'
                                    )
                                else:
                                    if (itemname in ['Activity', 'Activity-Alias']):
                                        exported.append(item)
                                    ret_value = (
                                        ret_value + '<tr><td><strong>' + itemname + '</strong> (' +
                                        item + ') is not Protected.<br>An intent-filter exists.'
                                        '</td><td><span class="label label-danger">high</span></td>'
                                        '<td> A' + appl_data + ' ' + itemname + ' is found to be '
                                        'shared with other apps on the device therefore leaving it '
                                        'accessible to any other application on the device. The '
                                        'presence of intent-filter indicates that the ' + itemname +
                                        ' is explicitly exported.</td></tr>'
                                    )
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1

        # GRANT-URI-PERMISSIONS
        title = 'Improper Content Provider Permissions'
        desc = (
            'A content provider permission was set to allows access from any other app on the '
            'device. Content providers may contain sensitive information about an app and '
            'therefore should not be shared.'
        )
        for granturi in granturipermissions:
            if granturi.getAttribute("android:pathPrefix") == '/':
                ret_value = (
                    ret_value + '<tr><td>' + title + '<br> [pathPrefix=/] </td>' + '<td>'
                    '<span class="label label-danger">high</span></td><td>' + desc + '</td></tr>'
                )
            elif granturi.getAttribute("android:path") == '/':
                ret_value = (
                    ret_value + '<tr><td>' + title + '<br> [path=/] </td>' + '<td>'
                    '<span class="label label-danger">high</span></td><td>' + desc + '</td></tr>'
                )
            elif granturi.getAttribute("android:pathPattern") == '*':
                ret_value = (
                    ret_value + '<tr><td>' + title + '<br> [path=*]</td>' + '<td>'
                    '<span class="label label-danger">high</span></td><td>' + desc + '</td></tr>'
                )
        # DATA
        for data in datas:
            if data.getAttribute("android:scheme") == "android_secret_code":
                xmlhost = data.getAttribute("android:host")
                desc = (
                    "A secret code was found in the manifest. These codes, when entered into the"
                    " dialer grant access to hidden content that may contain sensitive information."
                )
                ret_value = (
                    ret_value + '<tr><td>Dailer Code: ' + xmlhost + 'Found <br>'
                    '[android:scheme="android_secret_code"]</td><td>'
                    '<span class="label label-danger">high</span></td><td>'+ desc + '</td></tr>'
                )
            elif data.getAttribute("android:port"):
                dataport = data.getAttribute("android:port")
                title = "Data SMS Receiver Set"
                desc = (
                    "A binary SMS recevier is configured to listen on a port. Binary SMS messages "
                    "sent to a device are processed by the application in whichever way the "
                    "developer choses. The data in this SMS should be properly validated by the "
                    "application. Furthermore, the application should assume that the SMS being "
                    "received is from an untrusted source."
                )
                ret_value = (
                    ret_value + '<tr><td> on Port: ' + dataport + 'Found<br>[android:port]</td>'
                    '<td><span class="label label-danger">high</span></td><td>'+ desc +'</td></tr>'
                )

        # INTENTS
        for intent in intents:
            if intent.getAttribute("android:priority").isdigit():
                value = intent.getAttribute("android:priority")
                if int(value) > 100:
                    ret_value = (
                        ret_value + '<tr><td>High Intent Priority ('+ value +')<br>'
                        '[android:priority]</td><td>'
                        '<span class="label label-warning">medium</span></td>'
                        '<td>By setting an intent priority higher than another intent, the app '
                        'effectively overrides other requests.</td></tr>'
                    )
        ##ACTIONS
        for action in actions:
            if action.getAttribute("android:priority").isdigit():
                value = action.getAttribute("android:priority")
                if int(value) > 100:
                    ret_value = (
                        ret_value + '<tr><td>High Action Priority (' + value + ')<br>'
                        '[android:priority] </td><td><span class="label label-warning">medium'
                        '</span></td><td>By setting an action priority higher than another action,'
                        ' the app effectively overrides other requests.</td></tr>'
                    )
        if len(ret_value) < 2:
            ret_value = '<tr><td>None</td><td>None</td><td>None</td><tr>'
        # Prepare return dict
        man_an_dic = {
            'manifest_anal' : ret_value,
            'exported_act' : exported,
            'exported_cnt' : exp_count,
            'permissons' : format_permissions(man_data_dic['perm']),
            'cnt_act' : len(man_data_dic['activities']),
            'cnt_pro' : len(man_data_dic['providers']),
            'cnt_ser' : len(man_data_dic['services']),
            'cnt_bro' : len(man_data_dic['receivers'])
        }
        return man_an_dic
    except:
        PrintException("[ERROR] Performing Manifest Analysis")


def read_manifest(app_dir, tools_dir, typ, binary):
    """Read the manifest file."""
    try:
        dat = ''

        if binary is True:
            print "[INFO] Getting Manifest from Binary"
            print "[INFO] AXML -> XML"
            manifest = os.path.join(app_dir, "AndroidManifest.xml")
            if len(settings.AXMLPRINTER_BINARY) > 0 and isFileExists(settings.AXMLPRINTER_BINARY):
                cp_path = settings.AXMLPRINTER_BINARY
            else:
                cp_path = os.path.join(tools_dir, 'AXMLPrinter2.jar')

            args = [settings.JAVA_PATH + 'java', '-jar', cp_path, manifest]
            dat = subprocess.check_output(args)
        else:
            print "[INFO] Getting Manifest from Source"
            if typ == "eclipse":
                manifest = os.path.join(app_dir, "AndroidManifest.xml")
            elif typ == "studio":

                manifest = os.path.join(
                    app_dir, "app/src/main/AndroidManifest.xml"
                )
            with io.open(
                manifest,
                mode='r',
                encoding="utf8",
                errors="ignore"
            ) as file_pointer:
                dat = file_pointer.read()
        return dat
    except:
        PrintException("[ERROR] Reading Manifest file")
