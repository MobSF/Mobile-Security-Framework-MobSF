# -*- coding: utf_8 -*-
"""Android manifest analysis utils."""
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from xml.dom import minidom
from xml.parsers.expat import ExpatError

from bs4 import BeautifulSoup

from django.conf import settings

from mobsf.MobSF.utils import (
    append_scan_status,
    find_java_binary,
    is_file_exists,
)

# pylint: disable=E0401
from .kb.dvm_permissions import DVM_PERMISSIONS

logger = logging.getLogger(__name__)


ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'


def get_manifest_file(app_dir, app_path, tools_dir, typ):
    """Read the manifest file."""
    try:
        manifest = ''
        if typ == 'aar':
            logger.info('Getting AndroidManifest.xml from AAR')
            manifest = os.path.join(app_dir, ANDROID_MANIFEST_FILE)
        elif typ == 'apk':
            logger.info('Getting AndroidManifest.xml from APK')
            manifest = get_manifest_apk(app_path, app_dir, tools_dir)
        else:
            logger.info('Getting AndroidManifest.xml from Source Code')
            if typ == 'eclipse':
                manifest = os.path.join(app_dir, ANDROID_MANIFEST_FILE)
            elif typ == 'studio':
                manifest = os.path.join(
                    app_dir,
                    f'app/src/main/{ANDROID_MANIFEST_FILE}')
        return manifest
    except Exception:
        logger.exception('Getting AndroidManifest.xml file')


def get_manifest_apk(app_path, app_dir, tools_dir):
    """Get readable AndroidManifest.xml.

    Should be called before get_icon_apk() function
    """
    try:
        manifest = None
        if (len(settings.APKTOOL_BINARY) > 0
                and is_file_exists(settings.APKTOOL_BINARY)):
            apktool_path = settings.APKTOOL_BINARY
        else:
            apktool_path = os.path.join(tools_dir, 'apktool_2.9.3.jar')
        output_dir = os.path.join(app_dir, 'apktool_out')
        args = [find_java_binary(),
                '-jar',
                '-Djdk.util.zip.disableZip64ExtraFieldValidation=true',
                apktool_path,
                '--match-original',
                '--frame-path',
                tempfile.gettempdir(),
                '-f', '-s', 'd',
                app_path,
                '-o',
                output_dir]
        manifest = os.path.join(output_dir, ANDROID_MANIFEST_FILE)
        if is_file_exists(manifest):
            # APKTool already created readable XML
            return manifest
        logger.info('Converting AXML to XML')
        subprocess.check_output(args)  # User input is MD5 and validated
    except Exception:
        logger.exception('Getting Manifest file')
    return manifest


def get_xml_namespace(xml_str):
    """Get namespace."""
    m = re.search(r'manifest (.{1,250}?):', xml_str)
    if m:
        return m.group(1)
    logger.warning('XML namespace not found')
    return None


def get_fallback():
    logger.warning('Using Fake XML to continue the Analysis')
    return minidom.parseString(
        (r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android='
         r'"http://schemas.android.com/apk/res/android" '
         r'android:versionCode="Failed"  '
         r'android:versionName="Failed" package="Failed"  '
         r'platformBuildVersionCode="Failed" '
         r'platformBuildVersionName="Failed XML Parsing" ></manifest>'))


def bs4_xml_parser(xml_str):
    """Attempt to parse XML with bs4."""
    logger.info('Parsing AndroidManifest.xml with bs4')
    try:
        soup = BeautifulSoup(xml_str, 'xml')
        return soup.prettify().encode('utf-8', 'ignore')
    except Exception:
        logger.exception('Parsing XML with bs4')
    return None


def get_manifest(checksum, app_path, app_dir, tools_dir, typ):
    """Get the manifest file."""
    try:
        ns = 'android'
        manifest_file = get_manifest_file(
            app_dir,
            app_path,
            tools_dir,
            typ)
        mfile = Path(manifest_file)
        if not mfile.exists():
            logger.warning('apktool failed to extract '
                           'AndroidManifest.xml')
            return manifest_file, ns, get_fallback()
        msg = 'Parsing AndroidManifest.xml'
        logger.info(msg)
        append_scan_status(checksum, msg)
        xml_str = mfile.read_text('utf-8', 'ignore')
        ns = get_xml_namespace(xml_str)
        if ns and ns == 'xmlns':
            ns = 'android'
        if ns and ns != 'android':
            logger.warning('Non standard XML namespace: %s', ns)
        try:
            return manifest_file, ns, minidom.parseString(xml_str)
        except ExpatError:
            logger.warning('Parsing AndroidManifest.xml failed')
            return manifest_file, ns, minidom.parseString(
                bs4_xml_parser(xml_str))
    except Exception as exp:
        msg = 'Parsing AndroidManifest.xml failed'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
    return manifest_file, ns, get_fallback()


def manifest_data(checksum, mfxml, ns):
    """Extract manifest data."""
    try:
        msg = 'Extracting Manifest Data'
        logger.info(msg)
        append_scan_status(checksum, msg)
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
        applications = mfxml.getElementsByTagName('application')
        permissions = mfxml.getElementsByTagName('uses-permission')
        permsdk23 = mfxml.getElementsByTagName('uses-permission-sdk-23')
        if permsdk23:
            permissions.extend(permsdk23)
        manifest = mfxml.getElementsByTagName('manifest')
        activities = mfxml.getElementsByTagName('activity')
        services = mfxml.getElementsByTagName('service')
        providers = mfxml.getElementsByTagName('provider')
        receivers = mfxml.getElementsByTagName('receiver')
        libs = mfxml.getElementsByTagName('uses-library')
        sdk = mfxml.getElementsByTagName('uses-sdk')
        categories = mfxml.getElementsByTagName('category')
        for node in sdk:
            minsdk = node.getAttribute(f'{ns}:minSdkVersion')
            maxsdk = node.getAttribute(f'{ns}:maxSdkVersion')
            # Esteve 08.08.2016 - begin - If android:targetSdkVersion
            # is not set, the default value is the one of the
            # minSdkVersiontargetsdk
            # = node.getAttribute (f'{ns}:targetSdkVersion')
            if node.getAttribute(f'{ns}:targetSdkVersion'):
                targetsdk = node.getAttribute(f'{ns}:targetSdkVersion')
            else:
                targetsdk = node.getAttribute(f'{ns}:minSdkVersion')
            # End
        for node in manifest:
            package = node.getAttribute('package')
            androidversioncode = node.getAttribute(f'{ns}:versionCode')
            androidversionname = node.getAttribute(f'{ns}:versionName')
        alt_main = ''
        for activity in activities:
            act_2 = activity.getAttribute(f'{ns}:name')
            act.append(act_2)
            if not mainact:
                # ^ Some manifest has more than one MAIN, take only
                # the first occurrence.
                for sitem in activity.getElementsByTagName('action'):
                    val = sitem.getAttribute(f'{ns}:name')
                    if val == 'android.intent.action.MAIN':
                        mainact = activity.getAttribute(f'{ns}:name')
                # Manifest has no MAIN, look for launch activity.
                for sitem in activity.getElementsByTagName('category'):
                    val = sitem.getAttribute(f'{ns}:name')
                    if val == 'android.intent.category.LAUNCHER':
                        alt_main = activity.getAttribute(f'{ns}:name')
        if not mainact and alt_main:
            mainact = alt_main

        for service in services:
            service_name = service.getAttribute(f'{ns}:name')
            svc.append(service_name)

        for provider in providers:
            provider_name = provider.getAttribute(f'{ns}:name')
            cnp.append(provider_name)

        for receiver in receivers:
            rec = receiver.getAttribute(f'{ns}:name')
            brd.append(rec)

        for _lib in libs:
            library = _lib.getAttribute(f'{ns}:name')
            lib.append(library)

        for category in categories:
            cat.append(category.getAttribute(f'{ns}:name'))

        for application in applications:
            try:
                icon_path = application.getAttribute(f'{ns}:icon')
                icons.append(icon_path)
            except Exception:
                continue  # No icon attribute?

        android_permission_tags = ('com.google.', 'android.', 'com.google.')
        for permission in permissions:
            perm.append(permission.getAttribute(f'{ns}:name'))
        for full_perm in perm:
            # For general android permissions
            prm = full_perm
            pos = full_perm.rfind('.')
            if pos != -1:
                prm = full_perm[pos + 1:]
            if not full_perm.startswith(android_permission_tags):
                prm = full_perm
            try:
                dvm_perm[full_perm] = DVM_PERMISSIONS[
                    'MANIFEST_PERMISSION'][prm]
            except KeyError:
                # Handle Special Perms
                if DVM_PERMISSIONS['SPECIAL_PERMISSIONS'].get(full_perm):
                    dvm_perm[full_perm] = DVM_PERMISSIONS[
                        'SPECIAL_PERMISSIONS'][full_perm]
                else:
                    dvm_perm[full_perm] = [
                        'unknown',
                        'Unknown permission',
                        'Unknown permission from android reference',
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
            'icons': icons,
        }

        return man_data_dic
    except Exception as exp:
        msg = 'Extracting Manifest Data'
        logger.exception(msg)
        append_scan_status(checksum, msg, repr(exp))
