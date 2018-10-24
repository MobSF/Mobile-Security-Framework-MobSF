# -*- coding: utf_8 -*-
"""Module for iOS App Plist Analysis."""

import os
import plistlib
from MobSF.utils import (
    PrintException,
    isFileExists
)
from biplist import (
    readPlist,
    writePlistToString
)


def convert_bin_xml(bin_xml_file):
    """Convert Binary XML to Readable XML"""
    plist_obj = readPlist(bin_xml_file)
    data = writePlistToString(plist_obj)
    return data


def __check_permissions(p_list):
    '''Check the permissions the app requests.'''
    # List taken from
    # https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html
    print("[INFO] Checking Permissions")
    permissions = []
    if "NSAppleMusicUsageDescription" in p_list:
        permissions.append(
            (
                "NSAppleMusicUsageDescription",
                "Access Apple Media Library.",
                p_list["NSAppleMusicUsageDescription"]
            )
        )
    if "NSBluetoothPeripheralUsageDescription" in p_list:
        permissions.append(
            (
                "NSBluetoothPeripheralUsageDescription",
                "Access Bluetooth Interface.",
                p_list["NSBluetoothPeripheralUsageDescription"]
            )
        )
    if "NSCalendarsUsageDescription" in p_list:
        permissions.append(
            (
                "NSCalendarsUsageDescription",
                "Access Calendars.",
                p_list["NSCalendarsUsageDescription"]
            )
        )
    if "NSCameraUsageDescription" in p_list:
        permissions.append(
            (
                "NSCameraUsageDescription",
                "Access the Camera.",
                p_list["NSCameraUsageDescription"]
            )
        )
    if "NSContactsUsageDescription" in p_list:
        permissions.append(
            (
                "NSContactsUsageDescription",
                "Access Contacts.",
                p_list["NSContactsUsageDescription"]
            )
        )
    if "NSHealthShareUsageDescription" in p_list:
        permissions.append(
            (
                "NSHealthShareUsageDescription",
                "Read Health Data.",
                p_list["NSHealthShareUsageDescription"]
            )
        )
    if "NSHealthUpdateUsageDescription" in p_list:
        permissions.append(
            (
                "NSHealthUpdateUsageDescription",
                "Write Health Data.",
                p_list["NSHealthUpdateUsageDescription"]
            )
        )
    if "NSHomeKitUsageDescription" in p_list:
        permissions.append(
            (
                "NSHomeKitUsageDescription",
                "Access HomeKit configuration data.",
                p_list["NSHomeKitUsageDescription"]
            )
        )
    if "NSLocationAlwaysUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationAlwaysUsageDescription",
                "Access location information at all times.",
                p_list["NSLocationAlwaysUsageDescription"]
            )
        )
    if "NSLocationUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationUsageDescription",
                "Access location information at all times (< iOS 8).",
                p_list["NSLocationUsageDescription"]
            )
        )
    if "NSLocationWhenInUseUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationWhenInUseUsageDescription",
                "Access location information when app is in the foreground.",
                p_list["NSLocationWhenInUseUsageDescription"]
            )
        )
    if "NSMicrophoneUsageDescription" in p_list:
        permissions.append(
            (
                "NSMicrophoneUsageDescription",
                "Access microphone.",
                p_list["NSMicrophoneUsageDescription"]
            )
        )
    if "NSMotionUsageDescription" in p_list:
        permissions.append(
            (
                "NSMotionUsageDescription",
                "Access the device’s accelerometer.",
                p_list["NSMotionUsageDescription"]
            )
        )
    if "NSPhotoLibraryUsageDescription" in p_list:
        permissions.append(
            (
                "NSPhotoLibraryUsageDescription",
                "Access the user’s photo library.",
                p_list["NSPhotoLibraryUsageDescription"]
            )
        )
    if "NSRemindersUsageDescription" in p_list:
        permissions.append(
            (
                "NSRemindersUsageDescription",
                "Access the user’s reminders.",
                p_list["NSRemindersUsageDescription"]
            )
        )
    if "NSVideoSubscriberAccountUsageDescription" in p_list:
        permissions.append(
            (
                "NSVideoSubscriberAccountUsageDescription",
                "Access the user’s TV provider account.",
                p_list["NSVideoSubscriberAccountUsageDescription"]
            )
        )

    return permissions


def __check_insecure_connections(p_list):
    '''Check info.plist for insecure connection configurations.'''
    print("[INFO] Checking for Insecure Connections")

    insecure_connections = []
    if 'NSAppTransportSecurity' in p_list:
        ns_app_trans_dic = p_list['NSAppTransportSecurity']
        if 'NSExceptionDomains' in ns_app_trans_dic:
            for key in ns_app_trans_dic['NSExceptionDomains']:
                insecure_connections.append(key)
        if 'NSAllowsArbitraryLoads' in ns_app_trans_dic:
            if ns_app_trans_dic['NSAllowsArbitraryLoads'] is True:
                insecure_connections.append(p_list['NSAppTransportSecurity'])
    return insecure_connections


def plist_analysis(src, is_source):
    """Plist Analysis"""
    try:
        print("[INFO] iOS Info.plist Analysis Started")
        plist_info = {
            "bin_name": "",
            "bin": "",
            "id": "",
            "version": "",
            "build": "",
            "sdk": "",
            "pltfm": "",
            "min": "",
            "plist_xml": "",
            "permissions": [],
            "inseccon": [],
            "bundle_name": "",
            "build_version_name": "",
            "bundle_url_types": [],
            "bundle_supported_platforms": [],
            "bundle_localizations": []
        }
        if is_source:
            print("[INFO] Finding Info.plist in iOS Source")
            for ifile in os.listdir(src):
                if ifile.endswith(".xcodeproj"):
                    app_name = ifile.replace(".xcodeproj", "")
                    break
            app_plist_file = "Info.plist"
            for dirpath, dirnames, files in os.walk(src):
                for name in files:
                    if "__MACOSX" not in dirpath and name == app_plist_file:
                        plist_file = os.path.join(dirpath, name)
                        break
        else:
            print("[INFO] Finding Info.plist in iOS Binary")
            dirs = os.listdir(src)
            dot_app_dir = ""
            for dir_ in dirs:
                if dir_.endswith(".app"):
                    dot_app_dir = dir_
                    break
            bin_dir = os.path.join(src, dot_app_dir) # Full Dir/Payload/x.app
            plist_file = os.path.join(bin_dir, "Info.plist")
        if not isFileExists(plist_file):
            print("[WARNING] Cannot find Info.plist file. Skipping Plist Analysis.")
        else:
            #Generic Plist Analysis
            plist_obj = plistlib.readPlist(plist_file)
            plist_info["plist_xml"] = plistlib.writePlistToBytes(plist_obj).decode("utf-8", "ignore")
            if "CFBundleDisplayName" in plist_obj:
                plist_info["bin_name"] = plist_obj["CFBundleDisplayName"]
            else:
                if not is_source:
                    #For iOS IPA
                    plist_info["bin_name"] = dot_app_dir.replace(".app", "")
            if "CFBundleExecutable" in plist_obj:
                plist_info["bin"] = plist_obj["CFBundleExecutable"]
            if "CFBundleIdentifier" in plist_obj:
                plist_info["id"] = plist_obj["CFBundleIdentifier"]

            # build
            if "CFBundleVersion" in plist_obj:
                plist_info["build"] = plist_obj["CFBundleVersion"]
            if "DTSDKName" in plist_obj:
                plist_info["sdk"] = plist_obj["DTSDKName"]
            if "DTPlatformVersion" in plist_obj:
                plist_info["pltfm"] = plist_obj["DTPlatformVersion"]
            if "MinimumOSVersion" in plist_obj:
                plist_info["min"] = plist_obj["MinimumOSVersion"]

            plist_info["bundle_name"] = plist_obj.get("CFBundleName", "")
            plist_info["bundle_version_name"] = plist_obj.get("CFBundleShortVersionString", "")
            plist_info["bundle_url_types"] = plist_obj.get("CFBundleURLTypes", [])
            plist_info["bundle_supported_platforms"] = plist_obj.get("CFBundleSupportedPlatforms", [])
            plist_info["bundle_localizations"] = plist_obj.get("CFBundleLocalizations", [])

            # Check possible app-permissions
            plist_info["permissions"] = __check_permissions(plist_obj)
            plist_info["inseccon"] = __check_insecure_connections(plist_obj)
        return plist_info
    except:
        PrintException("[ERROR] - Reading from Info.plist")
