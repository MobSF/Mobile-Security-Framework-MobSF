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
        cat = []
        icons = []
        dvm_perm = {}
        package = ''
        minsdk = ''
        maxsdk = ''
        targetsdk = ''
        mainact = ''
        androidversioncode = ''
        androidversionname = ''
        applications = mfxml.getElementsByTagName("application")
        permissions = mfxml.getElementsByTagName("uses-permission")
        manifest = mfxml.getElementsByTagName("manifest")
        activities = mfxml.getElementsByTagName("activity")
        services = mfxml.getElementsByTagName("service")
        providers = mfxml.getElementsByTagName("provider")
        receivers = mfxml.getElementsByTagName("receiver")
        libs = mfxml.getElementsByTagName("uses-library")
        sdk = mfxml.getElementsByTagName("uses-sdk")
        categories = mfxml.getElementsByTagName("category")
        for node in sdk:
            minsdk = node.getAttribute("android:minSdkVersion")
            maxsdk = node.getAttribute("android:maxSdkVersion")
            # Esteve 08.08.2016 - begin - If android:targetSdkVersion is not set, the default value is the one of the android:minSdkVersion
            # targetsdk=node.getAttribute("android:targetSdkVersion")
            if node.getAttribute("android:targetSdkVersion"):
                targetsdk = node.getAttribute("android:targetSdkVersion")
            else:
                targetsdk = node.getAttribute("android:minSdkVersion")
            # End
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

        for _lib in libs:
            libary = _lib.getAttribute("android:name")
            lib.append(libary)

        for category in categories:
            cat.append(category.getAttribute("android:name"))

        for application in applications:
            try:
                icon_path = application.getAttribute("android:icon")
                icons.append(icon_path)
            except:
                continue  # No icon attribute?

        for permission in permissions:
            perm.append(permission.getAttribute("android:name"))

        for i in perm:
            prm = i
            pos = i.rfind(".")
            if pos != -1:
                prm = i[pos + 1:]
            try:
                dvm_perm[i] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][prm]
            except KeyError:
                dvm_perm[i] = [
                    "dangerous",
                    "Unknown permission from android reference",
                    "Unknown permission from android reference"
                ]

        man_data_dic = {
            'services': svc,
            'activities': act,
            'receivers': brd,
            'providers': cnp,
            'libraries': lib,
            'categories': cat,
            'perm': dvm_perm,
            'packagename': package,
            'mainactivity': mainact,
            'min_sdk': minsdk,
            'max_sdk': maxsdk,
            'target_sdk': targetsdk,
            'androver': androidversioncode,
            'androvername': androidversionname,
            'icons': icons
        }

        return man_data_dic
    except:
        PrintException("[ERROR] Extracting Manifest Data")


def get_browsable_activities(node):
    """Get Browsable Activities"""
    try:
        browse_dic = {}
        schemes = []
        mime_types = []
        hosts = []
        ports = []
        paths = []
        path_prefixs = []
        path_patterns = []
        catg = node.getElementsByTagName("category")
        for cat in catg:
            if cat.getAttribute("android:name") == "android.intent.category.BROWSABLE":
                datas = node.getElementsByTagName("data")
                for data in datas:
                    scheme = data.getAttribute("android:scheme")
                    if scheme and scheme not in schemes:
                        schemes.append(scheme)
                    mime = data.getAttribute("android:mimeType")
                    if mime and mime not in mime_types:
                        mime_types.append(mime)
                    host = data.getAttribute("android:host")
                    if host and host not in hosts:
                        hosts.append(host)
                    port = data.getAttribute("android:port")
                    if port and port not in ports:
                        ports.append(port)
                    path = data.getAttribute("android:path")
                    if path and path not in paths:
                        paths.append(path)
                    path_prefix = data.getAttribute("android:pathPrefix")
                    if path_prefix and path_prefix not in path_prefixs:
                        path_prefixs.append(path_prefix)
                    path_pattern = data.getAttribute("android:pathPattern")
                    if path_pattern and path_pattern not in path_patterns:
                        path_patterns.append(path_pattern)
        schemes = [scheme + "://" for scheme in schemes]
        browse_dic["schemes"] = schemes
        browse_dic["mime_types"] = mime_types
        browse_dic["hosts"] = hosts
        browse_dic["ports"] = ports
        browse_dic["paths"] = paths
        browse_dic["path_prefixs"] = path_prefixs
        browse_dic["path_patterns"] = path_patterns
        browse_dic["browsable"] = bool(browse_dic["schemes"])
        return browse_dic
    except:
        PrintException("[ERROR] Getting Browsable Activities")


def manifest_analysis(mfxml, man_data_dic):
    """Analyse manifest file."""
    # pylint: disable=C0301
    manifest_desc = {
        'a_debuggable': (
            'Debug Enabled For App <br>[android:debuggable=true]',
            'high',
            'Debugging was enabled on the app which makes it easier for reverse engineers to hook a '
            'debugger to it. This allows dumping a stack trace and accessing debugging helper classes.'
        ),
        'a_allowbackup': (
            'Application Data can be Backed up<br>[android:allowBackup=true]',
            'medium',
            'This flag allows anyone to backup your application data via adb. It allows users who have'
            ' enabled USB debugging to copy application data off of the device.'
        ),
        'a_allowbackup_miss': (
            'Application Data can be Backed up<br>[android:allowBackup] flag is missing.',
            'medium',
            'The flag [android:allowBackup] should be set to false. By default it is set to true and '
            'allows anyone to backup your application data via adb. It allows users who have enabled '
            'USB debugging to copy application data off of the device.'
        ),
        'a_testonly': (
            'Application is in Test Mode <br>[android:testOnly=true]',
            'high',
            ' It may expose functionality or data outside of itself that would cause a security hole.'
        ),
        'a_taskaffinity': (
            'TaskAffinity is set for Activity </br>(%s)',
            'high',
            'If taskAffinity is set, then other application could read the Intents sent to Activities'
            ' belonging to another task. Always use the default setting keeping the affinity as the '
            'package name in order to prevent sensitive information inside sent or received Intents '
            'from being read by another application.'
        ),
        'a_launchmode': (
            'Launch Mode of Activity (%s) is not standard.',
            'high',
            'An Activity should not be having the launch mode attribute set to "singleTask/singleInstance"'
            ' as it becomes root Activity and it is possible for other applications to read the contents'
            ' of the calling Intent. So it is required to use the "standard" launch mode attribute when'
            ' sensitive information is included in an Intent.'
        ),
        'a_prot_sign': (
            '<strong>%s</strong> (%s) is Protected by a permission.</br>%s<br>[android:exported=true]',
            'info',
            'A%s %s is found to be exported, but is protected by permission.'
        ),
        'a_prot_normal': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of '
            'the permission should be checked.</br>%s <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission. However,'
            ' the protection level of the permission is set to normal. This means that a malicious'
            ' application can request and obtain the permission and interact with the component.'
            ' If it was set to signature, only applications signed with the same certificate could'
            ' obtain the permission.'
        ),
        'a_prot_danger': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of '
            'the permission should be checked.</br>%s <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission. However,'
            ' the protection level of the permission is set to dangerous. This means that a'
            ' malicious application can request and obtain the permission and interact with the'
            ' component. If it was set to signature, only applications signed with the same'
            ' certificate could obtain the permission.'
        ),
        'a_prot_sign_sys': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of '
            'the permission should be checked.</br>%s <br>[android:exported=true]',
            'info',
            'A%s %s is found to be exported, but is protected by a permission. However, the'
            ' protection level of the permission is set to signatureOrSystem. It is recommended that'
            ' signature level is used instead. Signature level should suffice for most purposes, and'
            ' does not depend on where the applications are installed on the device.'
        ),
        'a_prot_unknown': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of '
            'the permission should be checked.</br>%s <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission which is not'
            ' defined in the analysed application. As a result, the protection level of the'
            ' permission should be checked where it is defined. If it is set to normal or'
            ' dangerous, a malicious application can request and obtain the permission and interact'
            ' with the component. If it is set to signature, only applications signed with the same'
            ' certificate can obtain the permission.'
        ),
        'a_prot_normal_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level,'
            ' but the protection level of the permission should be checked.</br>%s'
            ' <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device.  It is protected by a permission at the application'
            ' level. However, the protection level of the permission is set to normal. This means that'
            ' a malicious application can request and obtain the permission and interact with the'
            ' component. If it was set to signature, only applications signed with the same certificate'
            ' could obtain the permission.'
        ),
        'a_prot_danger_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level,'
            ' but the protection level of the permission should be checked.</br>%s'
            ' <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission at the'
            ' application level. However, the protection level of the permission is set to'
            ' dangerous. This means that a malicious application can request and obtain the'
            ' permission and interact with the component. If it was set to signature, only'
            ' applications signed with the same certificate could obtain the permission.'
        ),
        'a_prot_sign_appl': (
            '<strong>%s</strong> (%s)  Protected by a permission at the application level.</br>%s'
            '<br>[android:exported=true]',
            'info',
            'A%s %s is found to be exported, but is protected by a permission at the application level.'
        ),
        'a_prot_sign_sys_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level, but'
            ' the protection level of the permission should be checked.</br>%s'
            ' <br>[android:exported=true]',
            'info',
            'A%s %s is found to be exported, but is protected by a permission at the application'
            ' level. However, the protection level of the permission is set to signatureOrSystem.'
            ' It is recommended that signature level is used instead. Signature level should'
            ' suffice for most purposes, and does not depend on where the applications are'
            ' installed on the device.'
        ),
        'a_prot_unknown_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application, but the'
            ' protection level of the permission should be checked.</br>%s'
            ' <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission at the'
            ' application level which is not defined in the analysed application. As a result,'
            ' the protection level of the permission should be checked where it is defined.'
            ' If it is set to normal or dangerous, a malicious application can request and'
            ' obtain the permission and interact with the component. If it is set to signature,'
            ' only applications signed with the same certificate can obtain the permission.'
        ),
        'a_not_protected': (
            '<strong>%s</strong> (%s) is not Protected. <br>[android:exported=true]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device.'
        ),
        'a_not_protected_filter': (
            '<strong>%s</strong> (%s) is not Protected.<br>An intent-filter exists.',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. The presence of intent-filter indicates that the '
            '%s is explicitly exported.'
        ),
        'c_not_protected': (
            '<strong>%s</strong> (%s) is not Protected. <br>[[Content Provider, targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is a Content Provider that targets an API'
            ' level under 17, which makes it exported by default, regardless of the API level of'
            ' the system that the application runs on.'
        ),
        'c_not_protected2': (
            '<strong>%s</strong> (%s) would not be Protected if the application ran on a device where'
            ' the the API level was less than 17. <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider(%s %s) would be exported if the application ran on a device where'
            ' the the API level was less than 17. In that situation, it would be shared with other'
            ' apps on the device therefore leaving it accessible to any other application on the'
            ' device.'
        ),
        'c_prot_normal': (
            '<strong>%s</strong> (%s) is Protected by a permission, but'
            ' the protection level of the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission. However,'
            ' the protection level of the permission is set to normal. This means that a malicious'
            ' application can request and obtain the permission and interact with the component.'
            ' If it was set to signature, only applications signed with the same certificate could'
            ' obtain the permission.'
        ),
        'c_prot_danger': (
            '<strong>%s</strong> (%s) is Protected by a permission, but'
            ' the protection level of the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission. However,'
            ' the protection level of the permission is set to dangerous. This means that a'
            ' malicious application can request and obtain the permission and interact with the'
            ' component. If it was set to signature, only applications signed with the same'
            ' certificate could obtain the permission.'
        ),
        'c_prot_sign': (
            '<strong>%s</strong> (%s) is Protected by a permission.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'info',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by permission.'
        ),
        'c_prot_sign_sys': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of'
            ' the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'info',
            'A%s %s is found to be exported, but is protected by a permission. However, the'
            ' protection level of the permission is set to signatureOrSystem. It is recommended that'
            ' signature level is used instead. Signature level should suffice for most purposes, and'
            ' does not depend on where the applications are installed on the device.'
        ),
        'c_prot_unknown': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of '
            'the permission should be checked.</br>%s <br>[Content Provider, targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission which is not'
            ' defined in the analysed application. As a result, the protection level of the'
            ' permission should be checked where it is defined. If it is set to normal or'
            ' dangerous, a malicious application can request and obtain the permission and interact'
            ' with the component. If it is set to signature, only applications signed with the same'
            ' certificate can obtain the permission.'
        ),
        'c_prot_normal_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level, but'
            ' the protection level of the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission at the'
            ' application level. However, the protection level of the permission is set to normal.'
            ' This means that a malicious application can request and obtain the permission'
            ' and interact with the component. If it was set to signature, only applications'
            ' signed with the same certificate could obtain the permission.'
        ),
        'c_prot_danger_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level, but'
            ' the protection level of the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by a permission at the'
            ' application level. However, the protection level of the permission is set to dangerous.'
            ' This means that a malicious application can request and obtain the permission'
            ' and interact with the component. If it was set to signature, only applications'
            ' signed with the same certificate could obtain the permission.'
        ),
        'c_prot_sign_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'info',
            'A%s %s is found to be shared with other apps on the device therefore leaving it accessible'
            ' to any other application on the device. It is protected by permission at the'
            ' application level.'
        ),
        'c_prot_sign_sys_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level,'
            ' but the protection level of the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion < 17]',
            'info',
            'A%s %s is found to be exported, but is protected by a permission at the application'
            ' level. However, the protection level of the permission is set to signatureOrSystem.'
            ' It is recommended that signature level is used instead. Signature level should'
            ' suffice for most purposes, and does not depend on where the applications are'
            ' installed on the device.'
        ),
        'c_prot_unknown_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at application level, but the'
            ' protection level of the permission should be checked.</br>%s <br>[Content Provider,'
            ' targetSdkVersion < 17]',
            'high',
            'A%s %s is found to be shared with other apps on the device therefore leaving it'
            ' accessible to any other application on the device. It is protected by a'
            ' permission at application level which is not defined in the analysed application.'
            ' As a result, the protection level of the permission should be checked where it'
            ' is defined. If it is set to normal or dangerous, a malicious application can'
            ' request and obtain the permission and interact with the component. If it is'
            ' set to signature, only applications signed with the same certificate can obtain'
            ' the permission.'
        ),
        'c_prot_normal_new': (
            '<strong>%s</strong> (%s) is Protected by a permission, but'
            ' the protection level of the permission should be checked if'
            ' the application runs on a device where the the API level is less than 17</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider (%s) would be exported if the application ran on a'
            ' device where the the API level was less than 17. In that situation, it'
            ' would still be protected by a permission. However, the protection level'
            ' of the permission is set to normal. This means that a malicious application'
            ' could request and obtain the permission and interact with the component. If'
            ' it was set to signature, only applications signed with the same certificate'
            ' could obtain the permission.'
        ),
        'c_prot_danger_new': (
            '<strong>%s</strong> (%s) is Protected by a permission, but'
            ' the protection level of the permission should be checked if'
            ' the application runs on a device where the the API level is less than 17.</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider(%s) would be exported if the application ran on a device'
            ' where the the API level was less than 17. In that situation, it would still'
            ' be protected by a permission. However, the protection level of the permission'
            ' is set to dangerous. This means that a malicious application could request and'
            ' obtain the permission and interact with the component. If it was set to'
            ' signature, only applications signed with the same certificate could obtain'
            ' the permission.'
        ),
        'c_prot_sign_new': (
            '<strong>%s</strong> (%s) is Protected by a permission.</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'info',
            'The Content Provider(%s) would be exported if the application ran on a'
            ' device where the the API level was less than 17. Nevertheless, it is'
            ' protected by a permission.'
        ),
        'c_prot_sign_sys_new': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of'
            ' the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'info',
            'The Content Provider(%s) would be exported if the application ran on a device where'
            ' the API level was less than 17. In that situation, it would still be protected by a'
            ' permission. However, the protection level of the permission is set to'
            ' signatureOrSystem. It is recommended that signature level is used instead.'
            ' Signature level should suffice for most purposes, and does not depend on where'
            ' the applications are installed on the device.'
        ),
        'c_prot_unknown_new': (
            '<strong>%s</strong> (%s) is Protected by a permission, but the protection level of'
            ' the permission should be checked  if the application runs on a device where the the'
            ' API level is less than 17.</br>%s <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider(%s) would be exported if the application ran on a device where'
            ' the the API level was less than 17. In that situation, it would still be protected'
            ' by a permission which is not defined in the analysed application. As a result, the'
            ' protection level of the permission should be checked where it is defined. If it is'
            ' set to normal or dangerous, a malicious application can request and obtain the'
            ' permission and interact with the component. If it is set to signature, only'
            ' applications signed with the same certificate can obtain the permission.'
        ),
        'c_prot_normal_new_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level,'
            ' but the protection level of the permission should be checked if'
            ' the application runs on a device where the the API level is less than 17</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider (%s) would be exported if the application ran on a'
            ' device where the the API level was less than 17. In that situation, it'
            ' would still be protected by a permission. However, the protection level'
            ' of the permission is set to normal. This means that a malicious application'
            ' could request and obtain the permission and interact with the component. If'
            ' it was set to signature, only applications signed with the same certificate'
            ' could obtain the permission.'
        ),
        'c_prot_danger_new_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level,'
            ' but the protection level of the permission should be checked if'
            ' the application runs on a device where the the API level is less than 17.</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider(%s) would be exported if the application ran on a device'
            ' where the the API level was less than 17. In that situation, it would still'
            ' be protected by a permission. However, the protection level of the permission'
            ' is set to dangerous. This means that a malicious application could request and'
            ' obtain the permission and interact with the component. If it was set to'
            ' signature, only applications signed with the same certificate could obtain'
            ' the permission.'
        ),
        'c_prot_sign_new_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application'
            ' level.</br>%s<br>[Content Provider, targetSdkVersion >= 17]',
            'info',
            'The Content Provider(%s) would be exported if the application ran on a'
            ' device where the the API level was less than 17. Nevertheless, it is'
            ' protected by a permission.'
        ),
        'c_prot_sign_sys_new_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application'
            ' level, but the protection level of the permission should be checked.</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'info',
            'The Content Provider(%s) would be exported if the application ran on a device where'
            ' the API level was less than 17. In that situation, it would still be protected by a'
            ' permission. However, the protection level of the permission is set to'
            ' signatureOrSystem. It is recommended that signature level is used instead.'
            ' Signature level should suffice for most purposes, and does not depend on where'
            ' the applications are installed on the device.'
        ),
        'c_prot_unknown_new_appl': (
            '<strong>%s</strong> (%s) is Protected by a permission at the application level,'
            ' but the protection level of the permission should be checked  if the application'
            ' runs on a device where the the API level is less than 17.</br>%s'
            ' <br>[Content Provider, targetSdkVersion >= 17]',
            'high',
            'The Content Provider(%s) would be exported if the application ran on a device where'
            ' the the API level was less than 17. In that situation, it would still be protected'
            ' by a permission which is not defined in the analysed application. As a result, the'
            ' protection level of the permission should be checked where it is defined. If it is'
            ' set to normal or dangerous, a malicious application can request and obtain the'
            ' permission and interact with the component. If it is set to signature, only'
            ' applications signed with the same certificate can obtain the permission.'
        ),
        'a_improper_provider': (
            'Improper Content Provider Permissions<br>[%s]',
            'high',
            'A content provider permission was set to allows access from any other app on the device. '
            'Content providers may contain sensitive information about an app and therefore should not'
            ' be shared.'
        ),
        'a_dailer_code': (
            'Dailer Code: %s Found <br>[android:scheme="android_secret_code"]',
            'high',
            'A secret code was found in the manifest. These codes, when entered into the dialer grant'
            ' access to hidden content that may contain sensitive information.'
        ),
        'a_sms_receiver_port': (
            'Data SMS Receiver Set on Port: %s Found<br>[android:port]',
            'high',
            'A binary SMS recevier is configured to listen on a port. Binary SMS messages sent to a '
            'device are processed by the application in whichever way the developer choses. The data'
            ' in this SMS should be properly validated by the application. Furthermore, the application'
            ' should assume that the SMS being received is from an untrusted source."'
        ),
        'a_high_intent_priority': (
            'High Intent Priority (%s)<br>[android:priority]',
            'medium',
            'By setting an intent priority higher than another intent, the app effectively overrides'
            ' other requests.'
        ),
        'a_high_action_priority': (
            'High Action Priority (%s)<br>[android:priority] ',
            'medium',
            'By setting an action priority higher than another action, the app effectively overrides'
            ' other requests.'
        ),
    }
    try:
        print "[INFO] Manifest Analysis Started"
        exp_count = dict.fromkeys(["act", "ser", "bro", "cnt"], 0)
        applications = mfxml.getElementsByTagName("application")
        datas = mfxml.getElementsByTagName("data")
        intents = mfxml.getElementsByTagName("intent-filter")
        actions = mfxml.getElementsByTagName("action")
        granturipermissions = mfxml.getElementsByTagName(
            "grant-uri-permission")
        permissions = mfxml.getElementsByTagName("permission")
        ret_value = []
        ret_list = []
        exported = []
        browsable_activities = {}
        permission_dict = {}
        icon_hidden = True
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
            # Esteve 23.07.2016 - begin - identify permission at the
            # application level
            if application.getAttribute("android:permission"):
                perm_appl_level_exists = True
                perm_appl_level = application.getAttribute(
                    "android:permission")
            else:
                perm_appl_level_exists = False
            # End
            if application.getAttribute("android:debuggable") == "true":
                ret_list.append(("a_debuggable", tuple(), tuple(),))
            if application.getAttribute("android:allowBackup") == "true":
                ret_list.append(("a_allowbackup", tuple(), tuple(),))
            elif application.getAttribute("android:allowBackup") == "false":
                pass
            else:
                ret_list.append(("a_allowbackup_miss", tuple(), tuple(),))
            if application.getAttribute("android:testOnly") == "true":
                ret_list.append(("a_testonly", tuple(), tuple(),))
            for node in application.childNodes:
                an_or_a = ''
                if node.nodeName == 'activity':
                    itemname = 'Activity'
                    cnt_id = "act"
                    an_or_a = 'n'
                    browse_dic = get_browsable_activities(node)
                    if browse_dic["browsable"]:
                        browsable_activities[node.getAttribute(
                            "android:name")] = browse_dic
                elif node.nodeName == 'activity-alias':
                    itemname = 'Activity-Alias'
                    cnt_id = "act"
                    an_or_a = 'n'
                    browse_dic = get_browsable_activities(node)
                    if browse_dic["browsable"]:
                        browsable_activities[node.getAttribute(
                            "android:name")] = browse_dic
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

                # Task Affinity
                if (
                        itemname in ['Activity', 'Activity-Alias'] and
                        node.getAttribute("android:taskAffinity")
                ):
                    item = node.getAttribute("android:name")
                    ret_list.append(("a_taskaffinity", (item,), tuple(),))

                # LaunchMode
                if (
                        itemname in ['Activity', 'Activity-Alias'] and
                        (
                            node.getAttribute("android:launchMode") == 'singleInstance' or
                            node.getAttribute(
                                "android:launchMode") == 'singleTask'
                        )
                ):
                    item = node.getAttribute("android:name")
                    ret_list.append(("a_launchmode", (item,), tuple(),))
                # Exported Check
                item = ''
                is_inf = False
                is_perm_exist = False
                # Esteve 23.07.2016 - begin - initialise variables to identify
                # the existence of a permission at the component level that
                # matches a permission at the manifest level
                prot_level_exist = False
                protlevel = ''
                # End
                if itemname != 'NIL':
                    if node.getAttribute("android:exported") == 'true':
                        perm = ''
                        item = node.getAttribute("android:name")
                        if node.getAttribute("android:permission"):
                            # permission exists
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
                                        permission_dict[
                                            node.getAttribute("android:permission")]
                                    )
                                    # Esteve 23.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                    # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                    # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                    # included in the EXPORTED data structure for further treatment; components in this situation are also
                                    # counted as exported.
                                    prot_level_exist = True
                                    protlevel = permission_dict[
                                        node.getAttribute("android:permission")]
                                if prot_level_exist:
                                    if protlevel == 'normal':
                                        ret_list.append(
                                            ("a_prot_normal", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'dangerous':
                                        ret_list.append(
                                            ("a_prot_danger", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    elif protlevel == 'signature':
                                        ret_list.append(
                                            ("a_prot_sign", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                    elif protlevel == 'signatureOrSystem':
                                        ret_list.append(
                                            ("a_prot_sign_sys", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                else:
                                    ret_list.append(
                                        ("a_prot_unknown", (itemname, item, perm), (an_or_a, itemname,),))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 23.07.2016 - end
                            else:
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                # application level. As they are exported, they
                                # are not protected.
                                if perm_appl_level_exists is False:
                                    ret_list.append(
                                        ("a_not_protected", (itemname, item), (an_or_a, itemname,),))
                                    if itemname in ['Activity', 'Activity-Alias']:
                                        exported.append(item)
                                    exp_count[cnt_id] = exp_count[cnt_id] + 1
                                # Esteve 24.07.2016 - end
                                # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                #  level. Two options are possible:
                                #        1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                #           we did just above for permissions specified at the component level.
                                #        2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                # defined in the analysed application.
                                else:
                                    perm = '<strong>Permission: </strong>' + perm_appl_level
                                    prot = ""
                                    if perm_appl_level in permission_dict:
                                        prot = "</br><strong>protectionLevel: </strong>" + \
                                            permission_dict[perm_appl_level]
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            perm_appl_level]
                                    if prot_level_exist:
                                        if protlevel == 'normal':
                                            ret_list.append(
                                                ("a_prot_normal_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'dangerous':
                                            ret_list.append(
                                                ("a_prot_danger_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        elif protlevel == 'signature':
                                            ret_list.append(
                                                ("a_prot_sign_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                        elif protlevel == 'signatureOrSystem':
                                            ret_list.append(
                                                ("a_prot_sign_sys_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                    else:
                                        ret_list.append(
                                            ("a_prot_unknown_appl", (itemname, item, perm), (an_or_a, itemname,),))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                # Esteve 24.07.2016 - end

                    elif node.getAttribute("android:exported") != 'false':
                        # Check for Implicitly Exported
                        # Logic to support intent-filter
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == "intent-filter":
                                is_inf = True
                        if is_inf:
                            item = node.getAttribute("android:name")
                            if node.getAttribute("android:permission"):
                                # permission exists
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
                                            permission_dict[
                                                node.getAttribute("android:permission")]
                                        )
                                        # Esteve 24.07.2016 - begin - take into account protection level of the permission when claiming that a component is protected by it;
                                        # - the permission might not be defined in the application being analysed, if so, the protection level is not known;
                                        # - activities (or activity-alias) that are exported and have an unknown or normal or dangerous protection level are
                                        #  included in the EXPORTED data structure for further treatment; components in this situation are also
                                        #  counted as exported.
                                        prot_level_exist = True
                                        protlevel = permission_dict[
                                            node.getAttribute("android:permission")]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ("a_prot_normal", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ("a_prot_danger", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ("a_prot_sign", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ("a_prot_sign_sys", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                        else:
                                            ret_list.append(
                                                ("a_prot_unknown", (itemname, item, perm), (an_or_a, itemname,),))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        # Esteve 24.07.2016 - end
                                else:
                                    # Esteve 24.07.2016 - begin - At this point, we are dealing with components that do not have a permission neither at the component level nor at the
                                    # application level. As they are exported,
                                    # they are not protected.
                                    if perm_appl_level_exists is False:
                                        ret_list.append(
                                            ("a_not_protected_filter", (itemname, item,), (an_or_a, itemname, itemname,),))
                                        if itemname in ['Activity', 'Activity-Alias']:
                                            exported.append(item)
                                        exp_count[cnt_id] = exp_count[
                                            cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                    # Esteve 24.07.2016 - begin - At this point, we are dealing with components that have a permission at the application level, but not at the component
                                    # level. Two options are possible:
                                    # 1) The permission is defined at the manifest level, which allows us to differentiate the level of protection as
                                    #  we did just above for permissions specified at the component level.
                                    # 2) The permission is not defined at the manifest level, which means the protection level is unknown, as it is not
                                    #  defined in the analysed application.
                                    else:
                                        perm = '<strong>Permission: </strong>' + perm_appl_level
                                        prot = ""
                                        if perm_appl_level in permission_dict:
                                            prot = "</br><strong>protectionLevel: </strong>" + \
                                                permission_dict[
                                                    perm_appl_level]
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                perm_appl_level]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ("a_prot_normal_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ("a_prot_danger_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                if itemname in ['Activity', 'Activity-Alias']:
                                                    exported.append(item)
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ("a_prot_sign_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ("a_prot_sign_sys_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                        else:
                                            ret_list.append(
                                                ("a_prot_unknown_appl", (itemname, item, perm), (an_or_a, itemname,),))
                                            if itemname in ['Activity', 'Activity-Alias']:
                                                exported.append(item)
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    # Esteve 24.07.2016 - end
                                    # Esteve 29.07.2016 - begin The component is not explicitly exported (android:exported is not "true"). It is not implicitly exported either (it does not
                                    # make use of an intent filter). Despite that, it could still be exported by default, if it is a content provider and the android:targetSdkVersion
                                    # is older than 17 (Jelly Bean, Android versionn 4.2). This is true regardless of the system's API level.
                                    # Finally, it must also be taken into account that, if the minSdkVersion is greater or equal than 17, this check is unnecessary, because the
                                    # app will not be run on a system where the
                                    # system's API level is below 17.
                        else:
                            if man_data_dic['min_sdk'] and man_data_dic['target_sdk'] and int(man_data_dic['min_sdk']) < 17:
                                if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) < 17:
                                    perm = ''
                                    item = node.getAttribute("android:name")
                                    if node.getAttribute("android:permission"):
                                        # permission exists
                                        perm = '<strong>Permission: </strong>' + \
                                            node.getAttribute(
                                                "android:permission")
                                        is_perm_exist = True
                                    if is_perm_exist:
                                        prot = ""
                                        if node.getAttribute("android:permission") in permission_dict:
                                            prot = "</br><strong>protectionLevel: </strong>" + \
                                                permission_dict[
                                                    node.getAttribute("android:permission")]
                                            prot_level_exist = True
                                            protlevel = permission_dict[
                                                node.getAttribute("android:permission")]
                                        if prot_level_exist:
                                            if protlevel == 'normal':
                                                ret_list.append(
                                                    ("c_prot_normal", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'dangerous':
                                                ret_list.append(
                                                    ("c_prot_danger", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            elif protlevel == 'signature':
                                                ret_list.append(
                                                    ("c_prot_sign", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            elif protlevel == 'signatureOrSystem':
                                                ret_list.append(
                                                    ("c_prot_sign_sys", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                        else:
                                            ret_list.append(
                                                ("c_prot_unknown", (itemname, item, perm), (an_or_a, itemname,),))
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                    else:
                                        if perm_appl_level_exists is False:
                                            ret_list.append(
                                                ("c_not_protected", (itemname, item), (an_or_a, itemname,),))
                                            exp_count[cnt_id] = exp_count[
                                                cnt_id] + 1
                                        else:
                                            perm = '<strong>Permission: </strong>' + perm_appl_level
                                            prot = ""
                                            if perm_appl_level in permission_dict:
                                                prot = "</br><strong>protectionLevel: </strong>" + \
                                                    permission_dict[
                                                        perm_appl_level]
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    perm_appl_level]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    ret_list.append(
                                                        ("c_prot_normal_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                elif protlevel == 'dangerous':
                                                    ret_list.append(
                                                        ("c_prot_danger_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                elif protlevel == 'signature':
                                                    ret_list.append(
                                                        ("c_prot_sign_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                elif protlevel == 'signatureOrSystem':
                                                    ret_list.append(
                                                        ("c_prot_sign_sys_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            else:
                                                ret_list.append(
                                                    ("c_prot_unknown_appl", (itemname, item, perm), (an_or_a, itemname,),))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                    # Esteve 29.07.2016 - end
                                    # Esteve 08.08.2016 - begin - If the content provider does not target an API version lower than 17, it could still be exported by default, depending
                                    # on the API version of the platform. If it was below 17, the content
                                    # provider would be exported by default.
                                else:
                                    if itemname == 'Content Provider' and int(man_data_dic['target_sdk']) >= 17:
                                        perm = ''
                                        item = node.getAttribute(
                                            "android:name")
                                        if node.getAttribute("android:permission"):
                                            # permission exists
                                            perm = '<strong>Permission: </strong>' + \
                                                node.getAttribute(
                                                    "android:permission")
                                            is_perm_exist = True
                                        if is_perm_exist:
                                            prot = ""
                                            if node.getAttribute("android:permission") in permission_dict:
                                                prot = "</br><strong>protectionLevel: </strong>" + \
                                                    permission_dict[
                                                        node.getAttribute("android:permission")]
                                                prot_level_exist = True
                                                protlevel = permission_dict[
                                                    node.getAttribute("android:permission")]
                                            if prot_level_exist:
                                                if protlevel == 'normal':
                                                    ret_list.append(
                                                        ("c_prot_normal_new", (itemname, item, perm + prot,), (itemname,),))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                if protlevel == 'dangerous':
                                                    ret_list.append(
                                                        ("c_prot_danger_new", (itemname, item, perm + prot,), (itemname,),))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                                if protlevel == 'signature':
                                                    ret_list.append(
                                                        ("c_prot_sign_new", (itemname, item, perm + prot,), (itemname,),))
                                                if protlevel == 'signatureOrSystem':
                                                    ret_list.append(
                                                        ("c_prot_sign_sys_new", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                            else:
                                                ret_list.append(
                                                    ("c_prot_unknown_new", (itemname, item, perm), (itemname,),))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                        else:
                                            if perm_appl_level_exists is False:
                                                ret_list.append(
                                                    ("c_not_protected2", (itemname, item), (an_or_a, itemname,),))
                                                exp_count[cnt_id] = exp_count[
                                                    cnt_id] + 1
                                            else:
                                                perm = '<strong>Permission: </strong>' + perm_appl_level
                                                prot = ""
                                                if perm_appl_level in permission_dict:
                                                    prot = "</br><strong>protectionLevel: </strong>" + \
                                                        permission_dict[
                                                            perm_appl_level]
                                                    prot_level_exist = True
                                                    protlevel = permission_dict[
                                                        perm_appl_level]
                                                if prot_level_exist:
                                                    if protlevel == 'normal':
                                                        ret_list.append(
                                                            ("c_prot_normal_new_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                        exp_count[cnt_id] = exp_count[
                                                            cnt_id] + 1
                                                    elif protlevel == 'dangerous':
                                                        ret_list.append(
                                                            ("c_prot_danger_new_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                        exp_count[cnt_id] = exp_count[
                                                            cnt_id] + 1
                                                    elif protlevel == 'signature':
                                                        ret_list.append(
                                                            ("c_prot_sign_new_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                    elif protlevel == 'signatureOrSystem':
                                                        ret_list.append(
                                                            ("c_prot_sign_sys_new_appl", (itemname, item, perm + prot,), (an_or_a, itemname,),))
                                                else:
                                                    ret_list.append(
                                                        ("c_prot_unknown_new_appl", (itemname, item, perm), (an_or_a, itemname,),))
                                                    exp_count[cnt_id] = exp_count[
                                                        cnt_id] + 1
                                    # Esteve 08.08.2016 - end

        # GRANT-URI-PERMISSIONS
        for granturi in granturipermissions:
            if granturi.getAttribute("android:pathPrefix") == '/':
                ret_list.append(
                    ("a_improper_provider", ('pathPrefix=/',), tuple(),))
            elif granturi.getAttribute("android:path") == '/':
                ret_list.append(("a_improper_provider", ('path=/',), tuple(),))
            elif granturi.getAttribute("android:pathPattern") == '*':
                ret_list.append(("a_improper_provider", ('path=*',), tuple(),))
        # DATA
        for data in datas:
            if data.getAttribute("android:scheme") == "android_secret_code":
                xmlhost = data.getAttribute("android:host")
                ret_list.append(("a_dailer_code", (xmlhost,), tuple(),))

            elif data.getAttribute("android:port"):
                dataport = data.getAttribute("android:port")
                ret_list.append(("a_sms_receiver_port", (dataport,), tuple(),))
        # INTENTS
        for intent in intents:
            if intent.getAttribute("android:priority").isdigit():
                value = intent.getAttribute("android:priority")
                if int(value) > 100:
                    ret_list.append(
                        ("a_high_intent_priority", (value,), tuple(),))
        # ACTIONS
        for action in actions:
            if action.getAttribute("android:priority").isdigit():
                value = action.getAttribute("android:priority")
                if int(value) > 100:
                    ret_list.append(
                        ("a_high_action_priority", (value,), tuple(),))
        for a_key, t_name, t_desc in ret_list:
            a_template = manifest_desc.get(a_key)
            if a_template:
                a_title = a_template[0] % t_name
                a_desc = a_template[2] % t_desc
                ret_value.append({"title": a_title,
                                  "stat": a_template[1],
                                  "desc": a_desc})

        for category in man_data_dic['categories']:
            if category == "android.intent.category.LAUNCHER":
                icon_hidden = False
                break

        # Prepare return dict
        man_an_dic = {
            'manifest_anal': ret_value,
            'exported_act': exported,
            'exported_cnt': exp_count,
            'browsable_activities': browsable_activities,
            'permissons': man_data_dic['perm'],
            'cnt_act': len(man_data_dic['activities']),
            'cnt_pro': len(man_data_dic['providers']),
            'cnt_ser': len(man_data_dic['services']),
            'cnt_bro': len(man_data_dic['receivers']),
            'icon_hidden': icon_hidden
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
