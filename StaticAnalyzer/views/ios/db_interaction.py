# -*- coding: utf_8 -*-
"""Module holding the functions for the db."""
from MobSF.utils import (
    PrintException,
    python_list,
    python_dict
)
from StaticAnalyzer.models import (
    StaticAnalyzerIPA,
    StaticAnalyzerIOSZIP
)

# IPA DB


def get_context_from_analysis_ipa(app_dict, info_dict, bin_dict, files, sfiles):
    """Get the context for IPA from analysis results"""
    try:
        context = {
            'title': 'Static Analysis',
            'name': app_dict["app_name"],
            'size': app_dict["size"],
            'md5': app_dict["md5_hash"],
            'sha1': app_dict["sha1"],
            'sha256': app_dict["sha256"],
            'plist': info_dict["plist_xml"],
            'bin_name': info_dict["bin_name"],
            'id': info_dict["id"],
            'ver': info_dict["ver"],
            'sdk': info_dict["sdk"],
            'pltfm': info_dict["pltfm"],
            'min': info_dict["min"],
            'bin_anal': bin_dict["bin_res"],
            'libs': bin_dict["libs"],
            'files': files,
            'file_analysis': sfiles,
            'strings': bin_dict["strings"],
            'permissions': info_dict["permissions"],
            'insecure_connections': info_dict["inseccon"]
        }
        return context
    except:
        PrintException("[ERROR] Rendering to Template")


def get_context_from_db_entry_ipa(db_entry):
    """Return the context for IPA from DB"""
    try:
        print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
        context = {
            'title': db_entry[0].TITLE,
            'name': db_entry[0].APPNAMEX,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'plist': db_entry[0].INFOPLIST,
            'bin_name': db_entry[0].BINNAME,
            'id': db_entry[0].IDF,
            'ver': db_entry[0].VERSION,
            'sdk': db_entry[0].SDK,
            'pltfm': db_entry[0].PLTFM,
            'min': db_entry[0].MINX,
            'bin_anal': db_entry[0].BIN_ANAL,
            'libs': db_entry[0].LIBS,
            'files': python_list(db_entry[0].FILES),
            'file_analysis': db_entry[0].SFILESX,
            'strings': python_list(db_entry[0].STRINGS),
            'permissions': python_list(db_entry[0].PERMISSIONS),
            'insecure_connections': python_list(db_entry[0].INSECCON)
        }
        return context
    except:
        PrintException("[ERROR] Fetching from DB")


def update_db_entry_ipa(app_dict, info_dict, bin_dict, files, sfiles):
    """Update an IPA DB entry"""
    try:
        # pylint: disable=E1101
        StaticAnalyzerIPA.objects.filter(MD5=app_dict["md5_hash"]).update(
            TITLE='Static Analysis',
            APPNAMEX=app_dict["app_name"],
            SIZE=app_dict["size"],
            MD5=app_dict["md5_hash"],
            SHA1=app_dict["sha1"],
            SHA256=app_dict["sha256"],
            INFOPLIST=info_dict["plist_xml"],
            BINNAME=info_dict["bin_name"],
            IDF=info_dict["id"],
            VERSION=info_dict["ver"],
            SDK=info_dict["sdk"],
            PLTFM=info_dict["pltfm"],
            MINX=info_dict["min"],
            BIN_ANAL=bin_dict["bin_res"],
            LIBS=bin_dict["libs"],
            FILES=files,
            SFILESX=sfiles,
            STRINGS=bin_dict["strings"],
            PERMISSIONS=info_dict["permissions"],
            INSECCON=info_dict["inseccon"]
        )

    except:
        PrintException("[ERROR] Updating DB")


def create_db_entry_ipa(app_dict, info_dict, bin_dict, files, sfiles):
    """Save an IOS IPA DB entry"""
    try:
        static_db = StaticAnalyzerIPA(
            TITLE='Static Analysis',
            APPNAMEX=app_dict["app_name"],
            SIZE=app_dict["size"],
            MD5=app_dict["md5_hash"],
            SHA1=app_dict["sha1"],
            SHA256=app_dict["sha256"],
            INFOPLIST=info_dict["plist_xml"],
            BINNAME=info_dict["bin_name"],
            IDF=info_dict["id"],
            VERSION=info_dict["ver"],
            SDK=info_dict["sdk"],
            PLTFM=info_dict["pltfm"],
            MINX=info_dict["min"],
            BIN_ANAL=bin_dict["bin_res"],
            LIBS=bin_dict["libs"],
            FILES=files,
            SFILESX=sfiles,
            STRINGS=bin_dict["strings"],
            PERMISSIONS=info_dict["permissions"],
            INSECCON=info_dict["inseccon"]
        )
        static_db.save()
    except:
        PrintException("[ERROR] Saving to DB")

# IOS ZIP DB ENTRY


def get_context_from_analysis_ios(app_dict, info_dict,code_dict, files, sfiles):
    """Get the context for IOS ZIP from analysis results"""
    try:
        context = {
            'title': 'Static Analysis',
            'name': app_dict["app_name"],
            'size': app_dict["size"],
            'md5': app_dict["md5_hash"],
            'sha1': app_dict["sha1"],
            'sha256': app_dict["sha256"],
            'plist': info_dict["plist_xml"],
            'bin_name': info_dict["bin_name"],
            'id': info_dict["id"],
            'ver': info_dict["ver"],
            'sdk': info_dict["sdk"],
            'pltfm': info_dict["pltfm"],
            'min': info_dict["min"],
            'files': files,
            'file_analysis': sfiles,
            'api': code_dict["api"],
            'insecure': code_dict["code_anal"],
            'urls': code_dict["urlnfile"],
            'domains': code_dict["domains"],
            'emails': code_dict["emailnfile"],
            'permissions': info_dict["permissions"],
            'insecure_connections': info_dict["inseccon"]
        }
        return context
    except:
        PrintException("[ERROR] Rendering to Template")


def get_context_from_db_entry_ios(db_entry):
    """Return the context for IOS ZIP from DB"""
    try:
        print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
        context = {
            'title': db_entry[0].TITLE,
            'name': db_entry[0].APPNAMEX,
            'size': db_entry[0].SIZE,
            'md5': db_entry[0].MD5,
            'sha1': db_entry[0].SHA1,
            'sha256': db_entry[0].SHA256,
            'plist': db_entry[0].INFOPLIST,
            'bin_name': db_entry[0].BINNAME,
            'id': db_entry[0].IDF,
            'ver': db_entry[0].VERSION,
            'sdk': db_entry[0].SDK,
            'pltfm': db_entry[0].PLTFM,
            'min': db_entry[0].MINX,
            'files': python_list(db_entry[0].FILES),
            'file_analysis': db_entry[0].SFILESX,
            'api': python_dict(db_entry[0].API),
            'insecure': python_dict(db_entry[0].CODEANAL),
            'urls': python_list(db_entry[0].URLnFile),
            'domains': python_dict(db_entry[0].DOMAINS),
            'emails': python_list(db_entry[0].EmailnFile),
            'permissions': python_list(db_entry[0].PERMISSIONS),
            'insecure_connections': python_list(db_entry[0].INSECCON)
        }
        return context
    except:
        PrintException("[ERROR] Fetching from DB")


def update_db_entry_ios(app_dict, info_dict, code_dict, files, sfiles):
    """Update an IOS ZIP DB entry"""
    try:
        # pylint: disable=E1101
        StaticAnalyzerIOSZIP.objects.filter(MD5=app_dict["md5_hash"]).update(
            TITLE='Static Analysis',
            APPNAMEX=app_dict["app_name"],
            SIZE=app_dict["size"],
            MD5=app_dict["md5_hash"],
            SHA1=app_dict["sha1"],
            SHA256=app_dict["sha256"],
            INFOPLIST=info_dict["plist_xml"],
            BINNAME=info_dict["bin_name"],
            IDF=info_dict["id"],
            VERSION=info_dict["ver"],
            SDK=info_dict["sdk"],
            PLTFM=info_dict["pltfm"],
            MINX=info_dict["min"],
            FILES=files,
            SFILESX=sfiles,
            API=code_dict["api"],
            CODEANAL=code_dict["code_anal"],
            URLnFile=code_dict["urlnfile"],
            DOMAINS=code_dict["domains"],
            EmailnFile=code_dict["emailnfile"],
            PERMISSIONS=info_dict["permissions"],
            INSECCON=info_dict["inseccon"])

    except:
        PrintException("[ERROR] Updating DB")


def create_db_entry_ios(app_dict, info_dict, code_dict, files, sfiles):
    """Save an IOS ZIP DB entry"""
    try:
        # pylint: disable=E1101
        static_db = StaticAnalyzerIOSZIP(
            TITLE='Static Analysis',
            APPNAMEX=app_dict["app_name"],
            SIZE=app_dict["size"],
            MD5=app_dict["md5_hash"],
            SHA1=app_dict["sha1"],
            SHA256=app_dict["sha256"],
            INFOPLIST=info_dict["plist_xml"],
            BINNAME=info_dict["bin_name"],
            IDF=info_dict["id"],
            VERSION=info_dict["ver"],
            SDK=info_dict["sdk"],
            PLTFM=info_dict["pltfm"],
            MINX=info_dict["min"],
            FILES=files,
            SFILESX=sfiles,
            API=code_dict["api"],
            CODEANAL=code_dict["code_anal"],
            URLnFile=code_dict["urlnfile"],
            DOMAINS=code_dict["domains"],
            EmailnFile=code_dict["emailnfile"],
            PERMISSIONS=info_dict["permissions"],
            INSECCON=info_dict["inseccon"])
        static_db.save()
    except:
        PrintException("[ERROR] Updating DB")
