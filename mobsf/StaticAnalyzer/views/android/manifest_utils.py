# -*- coding: utf_8 -*-
"""Android manifest analysis utils."""
import logging
import re
from pathlib import Path

from defusedxml.minidom import parseString

from bs4 import BeautifulSoup

from mobsf.MobSF.utils import (
    append_scan_status,
)
from mobsf.StaticAnalyzer.views.android.converter import (
    run_apktool,
)

# pylint: disable=E0401
from .kb.dvm_permissions import DVM_PERMISSIONS

logger = logging.getLogger(__name__)


ANDROID_4_2_LEVEL = 17
ANDROID_5_0_LEVEL = 21
ANDROID_8_0_LEVEL = 26
ANDROID_MANIFEST_FILE = 'AndroidManifest.xml'


def get_manifest_file(app_dic):
    """Get AndroidManifest.xml file path.

    Used by get_parsed_manifest() and manifest_view.run()
    """
    manifest = None
    try:
        app_path = Path(app_dic['app_path'])
        app_dir = Path(app_dic['app_dir'])
        tools_dir = Path(app_dic['tools_dir'])
        typ = app_dic['zipped']
        checksum = app_dic['md5']
        androguard_xml = app_dic.get('androguard_manifest_xml')

        if typ == 'aar':
            logger.info('Getting AndroidManifest.xml from AAR')
            manifest = app_dir / ANDROID_MANIFEST_FILE
        elif typ == 'apk':
            logger.info('Getting AndroidManifest.xml from APK')
            manifest = app_dir / 'apktool_out' / ANDROID_MANIFEST_FILE
            if manifest.exists():
                return manifest

            # Run apktool to extract AndroidManifest.xml
            manifest.parent.mkdir(parents=True, exist_ok=True)
            run_apktool(app_path, app_dir, tools_dir)

            if not manifest.exists() and androguard_xml:
                logger.warning(
                    'apktool failed to extract AndroidManifest.xml,'
                    ' fallback to androguard')
                manifest.write_bytes(androguard_xml)
            elif not androguard_xml:
                msg = ('Failed to extract AndroidManifest.xml'
                       ' from APK with apktool and androguard')
                logger.error(msg)
                append_scan_status(checksum, msg, 'apktool and androguard failed')
        elif typ == 'eclipse':
            logger.info('Getting AndroidManifest.xml'
                        ' from Eclipse project source code')
            manifest = app_dir / ANDROID_MANIFEST_FILE
        elif typ == 'studio':
            logger.info('Getting AndroidManifest.xml'
                        ' from Android Studio project source code')
            manifest = app_dir / 'app' / 'src' / \
                'main' / ANDROID_MANIFEST_FILE
        else:
            logger.error('Unknown project type')
    except Exception:
        logger.exception('Getting AndroidManifest.xml file')
    return manifest


def get_xml_namespace(xml_str):
    """Get namespace."""
    match = re.search(r'manifest (.{1,250}?):', xml_str)
    if not match:
        logger.warning('XML namespace not found')
        return None

    namespace = match.group(1)

    # Handle standard and non-standard namespaces
    if namespace == 'xmlns':
        namespace = 'android'
    elif namespace != 'android':
        logger.warning('Non-standard XML namespace: %s', namespace)

    return namespace


def get_fallback():
    return parseString(
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


def get_parsed_manifest(app_dic):
    """Get the parsed manifest XML, file path and namespace."""
    checksum = app_dic['md5']
    parsed_xml = None
    manifest_file = None
    app_dic['manifest_file'] = None
    app_dic['manifest_namespace'] = 'android'
    app_dic['manifest_parsed_xml'] = get_fallback()
    try:
        manifest_file = get_manifest_file(app_dic)
        if not (manifest_file and manifest_file.exists()):
            logger.warning('APK AndroidManifest.xml file not found')
            app_dic['manifest_file'] = manifest_file
            return

        app_dic['manifest_file'] = manifest_file
        msg = 'Parsing AndroidManifest.xml'
        logger.info(msg)
        append_scan_status(checksum, msg)

        # Parse manifest XML
        xml_str = manifest_file.read_text('utf-8', 'ignore')
        app_dic['manifest_namespace'] = get_xml_namespace(xml_str)
        # apktool generated AndroidManifest.xml for APK
        parsed_xml = parseString(xml_str)
        app_dic['manifest_parsed_xml'] = parsed_xml
        return
    except Exception:
        try:
            logger.warning('Failed parsing AndroidManifest.xml, fallback to androguard')
            parsed_xml = parseString(app_dic['androguard_manifest_xml'])
            # Overwrite the file with androguard generated XML
            manifest_file.write_bytes(app_dic['androguard_manifest_xml'])
            app_dic['manifest_parsed_xml'] = parsed_xml
            return
        except Exception:
            logger.warning('Failed parsing androguard AndroidManifest.xml'
                           ', fallback to bs4')
        try:
            parsed_xml = parseString(bs4_xml_parser(xml_str))
            app_dic['manifest_parsed_xml'] = parsed_xml
            return
        except Exception as exp:
            msg = 'Parsing AndroidManifest.xml using all methods'
            logger.exception(msg)
            append_scan_status(checksum, msg, repr(exp))


def extract_manifest_data(app_dic):
    """Extract manifest data.

    Data from apk_features (aapt2) is also available as a fallback.
    """
    checksum = app_dic['md5']
    try:
        mfxml = app_dic['manifest_parsed_xml']
        ns = app_dic['manifest_namespace']
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
            if app_dic.get('apk_features', {}).get('target_sdk_version'):
                targetsdk = app_dic['apk_features']['target_sdk_version']
            elif node.getAttribute(f'{ns}:targetSdkVersion'):
                targetsdk = node.getAttribute(f'{ns}:targetSdkVersion')
            else:
                targetsdk = node.getAttribute(f'{ns}:minSdkVersion')
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
        if not perm and app_dic.get('apk_features', {}).get('permissions'):
            perm = app_dic['apk_features']['permissions']
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
        pkg_backup = app_dic.get('apk_features', {}).get('package')
        mainact_backup = app_dic.get('apk_features', {}).get('launchable_activity')
        minsdk_backup = app_dic.get('apk_features', {}).get('min_sdk_version')
        if not package and pkg_backup:
            package = pkg_backup
        if not mainact and mainact_backup:
            mainact = mainact_backup
        if not minsdk and minsdk_backup:
            minsdk = minsdk_backup
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
