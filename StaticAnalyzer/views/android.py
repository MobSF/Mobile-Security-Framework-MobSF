# -*- coding: utf_8 -*-
"""
Android Static Code Analysis
"""

import io
import re
import os
import zipfile
import subprocess
import ntpath
import shutil
import platform

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape
from django.template.defaulttags import register

from xml.dom import minidom

from StaticAnalyzer.models import StaticAnalyzerAndroid
from MobSF.utils import (
    PrintException,
    python_list,
    python_dict,
    isDirExists,
    isFileExists
)
from MalwareAnalyzer.views import MalwareCheck
from StaticAnalyzer.views.shared_func import (
    FileSize,
    HashGen,
    Unzip
)

# pylint: disable=E0401
from .dvm_permissions import DVM_PERMISSIONS

try:
    import StringIO
    StringIO = StringIO.StringIO
except ImportError:
    from io import StringIO


@register.filter
def key(d, key_name):
    return d.get(key_name)


def Java(request):
    try:
        m = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        typ = request.GET['type']
        if m:
            md5 = request.GET['md5']
            if typ == 'eclipse':
                src = os.path.join(settings.UPLD_DIR, md5 + '/src/')
            elif typ == 'studio':
                src = os.path.join(settings.UPLD_DIR, md5 + '/app/src/main/java/')
            elif typ == 'apk':
                src = os.path.join(settings.UPLD_DIR, md5 + '/java_source/')
            else:
                return HttpResponseRedirect('/error/')
            html = ''
            for dir_name, files in os.walk(src):
                for jfile in files:
                    if jfile.endswith(".java"):
                        file_path = os.path.join(src, dir_name, jfile)
                        if "+" in jfile:
                            fp2 = os.path.join(src, dir_name, jfile.replace("+", "x"))
                            shutil.move(file_path, fp2)
                            file_path = fp2
                        fileparam = file_path.replace(src, '')
                        if any(cls in fileparam for cls in settings.SKIP_CLASSES) == False:
                            html += (
                                "<tr><td><a href='../ViewSource/?file=" + escape(fileparam) +
                                "&md5=" + md5 +
                                "&type=" + typ + "'>" +
                                escape(fileparam) + "</a></td></tr>"
                            )
        context = {
            'title': 'Java Source',
            'files': html,
            'md5': md5,
            'type': typ,
        }

        template = "java.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Getting Java Files")
        return HttpResponseRedirect('/error/')


def Smali(request):
    try:
        m = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        if m:
            md5 = request.GET['md5']
            SRC = os.path.join(settings.UPLD_DIR, md5+'/smali_source/')
            html = ''
            for dir_name, files in os.walk(SRC):
                for jfile in files:
                    if jfile.endswith(".smali"):
                        file_path = os.path.join(SRC, dir_name, jfile)
                        if "+" in jfile:
                            fp2 = os.path.join(SRC, dir_name, jfile.replace("+", "x"))
                            shutil.move(file_path, fp2)
                            file_path = fp2
                        fileparam = file_path.replace(SRC, '')
                        html += (
                            "<tr><td><a href='../ViewSource/?file=" + escape(fileparam) +
                            "&md5=" + md5 + "'>" +
                            escape(fileparam) + "</a></td></tr>"
                        )
        context = {
            'title': 'Smali Source',
            'files': html,
            'md5': md5,
        }

        template = "smali.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Getting Smali Files")
        return HttpResponseRedirect('/error/')


def Find(request):
    try:
        m = re.match('^[0-9a-f]{32}$', request.POST['md5'])
        if m:
            MD5 = request.POST['md5']
            q = request.POST['q']
            code = request.POST['code']
            matches = []
            if code == 'java':
                src = os.path.join(settings.UPLD_DIR, MD5+'/java_source/')
                ext = '.java'
            elif code == 'smali':
                src = os.path.join(settings.UPLD_DIR, MD5+'/smali_source/')
                ext = '.smali'
            else:
                return HttpResponseRedirect('/error/')
            for dir_name, files in os.walk(src):
                for jfile in files:
                    if jfile.endswith(ext):
                        file_path = os.path.join(src, dir_name, jfile)
                        if "+" in jfile:
                            fp2 = os.path.join(src, dir_name, jfile.replace("+", "x"))
                            shutil.move(file_path, fp2)
                            file_path = fp2
                        fileparam = file_path.replace(src, '')
                        with io.open(file_path, mode='r', encoding="utf8", errors="ignore") as f:
                            dat = f.read()
                        if q in dat:
                            matches.append(
                                "<a href='../ViewSource/?file=" + escape(fileparam) +
                                "&md5=" + MD5 +
                                "&type=apk'>" + escape(fileparam) + "</a>"
                            )
        flz = len(matches)
        context = {
            'title': 'Search Results',
            'matches': matches,
            'term': q,
            'found' : str(flz)
        }
        template = "search.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Searching Failed")
        return HttpResponseRedirect('/error/')


def ViewSource(request):
    try:
        fil = ''
        m = re.match('^[0-9a-f]{32}$', request.GET['md5'])
        if m and (request.GET['file'].endswith('.java') or request.GET['file'].endswith('.smali')):
            fil = request.GET['file']
            MD5 = request.GET['md5']
            if ("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil):
                return HttpResponseRedirect('/error/')
            else:
                if fil.endswith('.java'):
                    typ = request.GET['type']
                    if typ == 'eclipse':
                        SRC = os.path.join(settings.UPLD_DIR, MD5+'/src/')
                    elif typ == 'studio':
                        SRC = os.path.join(settings.UPLD_DIR, MD5+'/app/src/main/java/')
                    elif typ == 'apk':
                        SRC = os.path.join(settings.UPLD_DIR, MD5+'/java_source/')
                    else:
                        return HttpResponseRedirect('/error/')
                elif fil.endswith('.smali'):
                    SRC = os.path.join(settings.UPLD_DIR, MD5+'/smali_source/')
                sfile = os.path.join(SRC, fil)
                dat = ''
                with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as f:
                    dat = f.read()
        else:
            return HttpResponseRedirect('/error/')
        context = {'title': escape(ntpath.basename(fil)),
                   'file': escape(ntpath.basename(fil)),
                   'dat': dat}
        template = "view_source.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Viewing Source")
        return HttpResponseRedirect('/error/')


def ManifestView(request):
    try:
        DIR = settings.BASE_DIR  # BASE DIR
        MD5 = request.GET['md5']  # MD5
        TYP = request.GET['type']  # APK or SOURCE
        BIN = request.GET['bin']
        m = re.match('^[0-9a-f]{32}$', MD5)
        if m and (TYP in ['eclipse', 'studio', 'apk']) and (BIN in ['1', '0']):
            APP_DIR = os.path.join(
                settings.UPLD_DIR, MD5 + '/')  # APP DIRECTORY
            TOOLS_DIR = os.path.join(DIR, 'StaticAnalyzer/tools/')  # TOOLS DIR
            if BIN == '1':
                x = True
            elif BIN == '0':
                x = False
            MANI = ReadManifest(APP_DIR, TOOLS_DIR, TYP, x)
            context = {
                'title': 'AndroidManifest.xml',
                'file': 'AndroidManifest.xml',
                'dat': MANI
            }
            template = "view_mani.html"
            return render(request, template, context)
    except:
        PrintException("[ERROR] Viewing AndroidManifest.xml")
        return HttpResponseRedirect('/error/')


def _get_context_from_db_entry(DB):
    """Return the context dict for an apk-DB entry."""

    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."

    context = {
        'title' : DB[0].TITLE,
        'name' : DB[0].APP_NAME,
        'size' : DB[0].SIZE,
        'md5': DB[0].MD5,
        'sha1' : DB[0].SHA1,
        'sha256' : DB[0].SHA256,
        'packagename' : DB[0].PACKAGENAME,
        'mainactivity' : DB[0].MAINACTIVITY,
        'targetsdk' : DB[0].TARGET_SDK,
        'maxsdk' : DB[0].MAX_SDK,
        'minsdk' : DB[0].MIN_SDK,
        'androvername' : DB[0].ANDROVERNAME,
        'androver': DB[0].ANDROVER,
        'manifest': DB[0].MANIFEST_ANAL,
        'permissions' : DB[0].PERMISSIONS,
        'files' : python_list(DB[0].FILES),
        'certz' : DB[0].CERTZ,
        'activities' : python_list(DB[0].ACTIVITIES),
        'receivers' : python_list(DB[0].RECEIVERS),
        'providers' : python_list(DB[0].PROVIDERS),
        'services' : python_list(DB[0].SERVICES),
        'libraries' : python_list(DB[0].LIBRARIES),
        'act_count' : DB[0].CNT_ACT,
        'prov_count' : DB[0].CNT_PRO,
        'serv_count' : DB[0].CNT_SER,
        'bro_count' : DB[0].CNT_BRO,
        'certinfo': DB[0].CERT_INFO,
        'issued': DB[0].ISSUED,
        'native' : DB[0].NATIVE,
        'dynamic' : DB[0].DYNAMIC,
        'reflection' : DB[0].REFLECT,
        'crypto': DB[0].CRYPTO,
        'obfus': DB[0].OBFUS,
        'api': DB[0].API,
        'dang': DB[0].DANG,
        'urls': DB[0].URLS,
        'domains': python_dict(DB[0].DOMAINS),
        'emails': DB[0].EMAILS,
        'strings': python_list(DB[0].STRINGS),
        'zipped' : DB[0].ZIPPED,
        'mani': DB[0].MANI,
        'e_act': DB[0].E_ACT,
        'e_ser': DB[0].E_SER,
        'e_bro': DB[0].E_BRO,
        'e_cnt': DB[0].E_CNT,
    }
    return context

def _get_context_from_an(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic):
    context = {
        'title' : 'Static Analysis',
        'name' : app_dic['app_name'],
        'size' : app_dic['size'],
        'md5': app_dic['md5'],
        'sha1' : app_dic['sha1'],
        'sha256' : app_dic['sha256'],
        'packagename' : man_data_dic['packagename'],
        'mainactivity' : man_data_dic['mainactivity'],
        'targetsdk' : man_data_dic['target_sdk'],
        'maxsdk' : man_data_dic['max_sdk'],
        'minsdk' : man_data_dic['min_sdk'],
        'androvername' : man_data_dic['androvername'],
        'androver': man_data_dic['androver'],
        'manifest': man_an_dic['manifest_anal'],
        'permissions' : man_an_dic['permissons'],
        'files' : app_dic['files'],
        'certz' : app_dic['certz'],
        'activities' : man_data_dic['activities'],
        'receivers' : man_data_dic['receivers'],
        'providers' : man_data_dic['providers'],
        'services' : man_data_dic['services'],
        'libraries' : man_data_dic['libraries'],
        'act_count' : man_an_dic['cnt_act'],
        'prov_count' : man_an_dic['cnt_pro'],
        'serv_count' : man_an_dic['cnt_ser'],
        'bro_count' : man_an_dic['cnt_bro'],
        'certinfo': cert_dic['cert_info'],
        'issued':cert_dic['issued'],
        'native' : code_an_dic['native'],
        'dynamic' : code_an_dic['dynamic'],
        'reflection' : code_an_dic['reflect'],
        'crypto': code_an_dic['crypto'],
        'obfus': code_an_dic['obfus'],
        'api': code_an_dic['api'],
        'dang': code_an_dic['dang'],
        'urls': code_an_dic['urls'],
        'domains': code_an_dic['domains'],
        'emails': code_an_dic['emails'],
        'strings': app_dic['strings'],
        'zipped' : app_dic['zipped'],
        'mani': app_dic['mani'],
        'e_act': man_an_dic['exported_cnt']["act"],
        'e_ser': man_an_dic['exported_cnt']["ser"],
        'e_bro': man_an_dic['exported_cnt']["bro"],
        'e_cnt': man_an_dic['exported_cnt']["cnt"],
    }
    return context

def _update_db_entry(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic):
    StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5']).update(
        TITLE='Static Analysis',
        APP_NAME=app_dic['app_name'],
        SIZE=app_dic['size'],
        MD5=app_dic['md5'],
        SHA1=app_dic['sha1'],
        SHA256=app_dic['sha256'],
        PACKAGENAME=man_data_dic['packagename'],
        MAINACTIVITY=man_data_dic['mainactivity'],
        TARGET_SDK=man_data_dic['target_sdk'],
        MAX_SDK=man_data_dic['max_sdk'],
        MIN_SDK=man_data_dic['min_sdk'],
        ANDROVERNAME=man_data_dic['androvername'],
        ANDROVER=man_data_dic['androver'],
        MANIFEST_ANAL=man_an_dic['manifest_anal'],
        PERMISSIONS=man_an_dic['permissons'],
        FILES=app_dic['files'],
        CERTZ=app_dic['certz'],
        ACTIVITIES=man_data_dic['activities'],
        RECEIVERS=man_data_dic['receivers'],
        PROVIDERS=man_data_dic['providers'],
        SERVICES=man_data_dic['services'],
        LIBRARIES=man_data_dic['libraries'],
        CNT_ACT=man_an_dic['cnt_act'],
        CNT_PRO=man_an_dic['cnt_pro'],
        CNT_SER=man_an_dic['cnt_ser'],
        CNT_BRO=man_an_dic['cnt_bro'],
        CERT_INFO=cert_dic['cert_info'],
        ISSUED=cert_dic['issued'],
        NATIVE=code_an_dic['native'],
        DYNAMIC=code_an_dic['dynamic'],
        REFLECT=code_an_dic['reflect'],
        CRYPTO=code_an_dic['crypto'],
        OBFUS=code_an_dic['obfus'],
        API=code_an_dic['api'],
        DANG=code_an_dic['dang'],
        URLS=code_an_dic['urls'],
        DOMAINS=code_an_dic['domains'],
        EMAILS=code_an_dic['emails'],
        STRINGS=app_dic['strings'],
        ZIPPED=app_dic['zipped'],
        MANI=app_dic['mani'],
        EXPORTED_ACT=man_an_dic['exported_act'],
        E_ACT=man_an_dic['exported_cnt']["act"],
        E_SER=man_an_dic['exported_cnt']["ser"],
        E_BRO=man_an_dic['exported_cnt']["bro"],
        E_CNT=man_an_dic['exported_cnt']["cnt"]
    )

def _create_db_entry(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic):
    STATIC_DB = StaticAnalyzerAndroid(
        TITLE='Static Analysis',
        APP_NAME=app_dic['app_name'],
        SIZE=app_dic['size'],
        MD5=app_dic['md5'],
        SHA1=app_dic['sha1'],
        SHA256=app_dic['sha256'],
        PACKAGENAME=man_data_dic['packagename'],
        MAINACTIVITY=man_data_dic['mainactivity'],
        TARGET_SDK=man_data_dic['target_sdk'],
        MAX_SDK=man_data_dic['max_sdk'],
        MIN_SDK=man_data_dic['min_sdk'],
        ANDROVERNAME=man_data_dic['androvername'],
        ANDROVER=man_data_dic['androver'],
        MANIFEST_ANAL=man_an_dic['manifest_anal'],
        PERMISSIONS=man_an_dic['permissons'],
        FILES=app_dic['files'],
        CERTZ=app_dic['certz'],
        ACTIVITIES=man_data_dic['activities'],
        RECEIVERS=man_data_dic['receivers'],
        PROVIDERS=man_data_dic['providers'],
        SERVICES=man_data_dic['services'],
        LIBRARIES=man_data_dic['libraries'],
        CNT_ACT=man_an_dic['cnt_act'],
        CNT_PRO=man_an_dic['cnt_pro'],
        CNT_SER=man_an_dic['cnt_ser'],
        CNT_BRO=man_an_dic['cnt_bro'],
        CERT_INFO=cert_dic['cert_info'],
        ISSUED=cert_dic['issued'],
        NATIVE=code_an_dic['native'],
        DYNAMIC=code_an_dic['dynamic'],
        REFLECT=code_an_dic['reflect'],
        CRYPTO=code_an_dic['crypto'],
        OBFUS=code_an_dic['obfus'],
        API=code_an_dic['api'],
        DANG=code_an_dic['dang'],
        URLS=code_an_dic['urls'],
        DOMAINS=code_an_dic['domains'],
        EMAILS=code_an_dic['emails'],
        STRINGS=app_dic['strings'],
        ZIPPED=app_dic['zipped'],
        MANI=app_dic['mani'],
        EXPORTED_ACT=man_an_dic['exported_act'],
        E_ACT=man_an_dic['exported_cnt']["act"],
        E_SER=man_an_dic['exported_cnt']["ser"],
        E_BRO=man_an_dic['exported_cnt']["bro"],
        E_CNT=man_an_dic['exported_cnt']["cnt"]
    )
    STATIC_DB.save()

def _get_context_from_db_entry_zip(DB):
    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."

    context = {
        'title' : DB[0].TITLE,
        'name' : DB[0].APP_NAME,
        'size' : DB[0].SIZE,
        'md5': DB[0].MD5,
        'sha1' : DB[0].SHA1,
        'sha256' : DB[0].SHA256,
        'packagename' : DB[0].PACKAGENAME,
        'mainactivity' : DB[0].MAINACTIVITY,
        'targetsdk' : DB[0].TARGET_SDK,
        'maxsdk' : DB[0].MAX_SDK,
        'minsdk' : DB[0].MIN_SDK,
        'androvername' : DB[0].ANDROVERNAME,
        'androver': DB[0].ANDROVER,
        'manifest': DB[0].MANIFEST_ANAL,
        'permissions' : DB[0].PERMISSIONS,
        'files' : python_list(DB[0].FILES),
        'certz' : DB[0].CERTZ,
        'activities' : python_list(DB[0].ACTIVITIES),
        'receivers' : python_list(DB[0].RECEIVERS),
        'providers' : python_list(DB[0].PROVIDERS),
        'services' : python_list(DB[0].SERVICES),
        'libraries' : python_list(DB[0].LIBRARIES),
        'act_count' : DB[0].CNT_ACT,
        'prov_count' : DB[0].CNT_PRO,
        'serv_count' : DB[0].CNT_SER,
        'bro_count' : DB[0].CNT_BRO,
        'native' : DB[0].NATIVE,
        'dynamic' : DB[0].DYNAMIC,
        'reflection' : DB[0].REFLECT,
        'crypto': DB[0].CRYPTO,
        'obfus': DB[0].OBFUS,
        'api': DB[0].API,
        'dang': DB[0].DANG,
        'urls': DB[0].URLS,
        'domains': python_dict(DB[0].DOMAINS),
        'emails': DB[0].EMAILS,
        'mani': DB[0].MANI,
        'e_act': DB[0].E_ACT,
        'e_ser': DB[0].E_SER,
        'e_bro': DB[0].E_BRO,
        'e_cnt': DB[0].E_CNT,
    }
    return context

def _get_context_from_an_zip(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic):
    context = {
        'title' : 'Static Analysis',
        'name' : app_dic['app_name'],
        'size' : app_dic['size'],
        'md5': app_dic['md5'],
        'sha1' : app_dic['sha1'],
        'sha256' : app_dic['sha256'],
        'packagename' : man_data_dic['packagename'],
        'mainactivity' : man_data_dic['mainactivity'],
        'targetsdk' : man_data_dic['target_sdk'],
        'maxsdk' : man_data_dic['max_sdk'],
        'minsdk' : man_data_dic['min_sdk'],
        'androvername' : man_data_dic['androvername'],
        'androver': man_data_dic['androver'],
        'manifest': man_an_dic['manifest_anal'],
        'permissions' : man_an_dic['permissons'],
        'files' : app_dic['files'],
        'certz' : app_dic['certz'],
        'activities' : man_data_dic['activities'],
        'receivers' : man_data_dic['receivers'],
        'providers' : man_data_dic['providers'],
        'services' : man_data_dic['services'],
        'libraries' : man_data_dic['libraries'],
        'act_count' : man_an_dic['cnt_act'],
        'prov_count' : man_an_dic['cnt_pro'],
        'serv_count' : man_an_dic['cnt_ser'],
        'bro_count' : man_an_dic['cnt_bro'],
        'native' : code_an_dic['native'],
        'dynamic' : code_an_dic['dynamic'],
        'reflection' : code_an_dic['reflect'],
        'crypto': code_an_dic['crypto'],
        'obfus': code_an_dic['obfus'],
        'api': code_an_dic['api'],
        'dang': code_an_dic['dang'],
        'urls': code_an_dic['urls'],
        'domains': code_an_dic['domains'],
        'emails': code_an_dic['emails'],
        'mani': app_dic['mani'],
        'e_act': man_an_dic['exported_cnt']["act"],
        'e_ser': man_an_dic['exported_cnt']["ser"],
        'e_bro': man_an_dic['exported_cnt']["bro"],
        'e_cnt': man_an_dic['exported_cnt']["cnt"],
    }
    return context

def _update_db_entry_zip(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic):
    StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5']).update(
        TITLE='Static Analysis',
        APP_NAME=app_dic['app_name'],
        SIZE=app_dic['size'],
        MD5=app_dic['md5'],
        SHA1=app_dic['sha1'],
        SHA256=app_dic['sha256'],
        PACKAGENAME=man_data_dic['packagename'],
        MAINACTIVITY=man_data_dic['mainactivity'],
        TARGET_SDK=man_data_dic['target_sdk'],
        MAX_SDK=man_data_dic['max_sdk'],
        MIN_SDK=man_data_dic['min_sdk'],
        ANDROVERNAME=man_data_dic['androvername'],
        ANDROVER=man_data_dic['androver'],
        MANIFEST_ANAL=man_an_dic['manifest_anal'],
        PERMISSIONS=man_an_dic['permissons'],
        FILES=app_dic['files'],
        CERTZ=app_dic['certz'],
        ACTIVITIES=man_data_dic['activities'],
        RECEIVERS=man_data_dic['receivers'],
        PROVIDERS=man_data_dic['providers'],
        SERVICES=man_data_dic['services'],
        LIBRARIES=man_data_dic['libraries'],
        CNT_ACT=man_an_dic['cnt_act'],
        CNT_PRO=man_an_dic['cnt_pro'],
        CNT_SER=man_an_dic['cnt_ser'],
        CNT_BRO=man_an_dic['cnt_bro'],
        CERT_INFO="",
        ISSUED="",
        NATIVE=code_an_dic['native'],
        DYNAMIC=code_an_dic['dynamic'],
        REFLECT=code_an_dic['reflect'],
        CRYPTO=code_an_dic['crypto'],
        OBFUS=code_an_dic['obfus'],
        API=code_an_dic['api'],
        DANG=code_an_dic['dang'],
        URLS=code_an_dic['urls'],
        DOMAINS=code_an_dic['domains'],
        EMAILS=code_an_dic['emails'],
        STRINGS="",
        ZIPPED="",
        MANI=app_dic['mani'],
        EXPORTED_ACT=man_an_dic['exported_act'],
        E_ACT=man_an_dic['exported_cnt']["act"],
        E_SER=man_an_dic['exported_cnt']["ser"],
        E_BRO=man_an_dic['exported_cnt']["bro"],
        E_CNT=man_an_dic['exported_cnt']["cnt"]
    )

def _create_db_entry_zip(app_dic, man_data_dic, man_an_dic, code_an_dic, cert_dic):
    STATIC_DB = StaticAnalyzerAndroid(
        TITLE='Static Analysis',
        APP_NAME=app_dic['app_name'],
        SIZE=app_dic['size'],
        MD5=app_dic['md5'],
        SHA1=app_dic['sha1'],
        SHA256=app_dic['sha256'],
        PACKAGENAME=man_data_dic['packagename'],
        MAINACTIVITY=man_data_dic['mainactivity'],
        TARGET_SDK=man_data_dic['target_sdk'],
        MAX_SDK=man_data_dic['max_sdk'],
        MIN_SDK=man_data_dic['min_sdk'],
        ANDROVERNAME=man_data_dic['androvername'],
        ANDROVER=man_data_dic['androver'],
        MANIFEST_ANAL=man_an_dic['manifest_anal'],
        PERMISSIONS=man_an_dic['permissons'],
        FILES=app_dic['files'],
        CERTZ=app_dic['certz'],
        ACTIVITIES=man_data_dic['activities'],
        RECEIVERS=man_data_dic['receivers'],
        PROVIDERS=man_data_dic['providers'],
        SERVICES=man_data_dic['services'],
        LIBRARIES=man_data_dic['libraries'],
        CNT_ACT=man_an_dic['cnt_act'],
        CNT_PRO=man_an_dic['cnt_pro'],
        CNT_SER=man_an_dic['cnt_ser'],
        CNT_BRO=man_an_dic['cnt_bro'],
        CERT_INFO="",
        ISSUED="",
        NATIVE=code_an_dic['native'],
        DYNAMIC=code_an_dic['dynamic'],
        REFLECT=code_an_dic['reflect'],
        CRYPTO=code_an_dic['crypto'],
        OBFUS=code_an_dic['obfus'],
        API=code_an_dic['api'],
        DANG=code_an_dic['dang'],
        URLS=code_an_dic['urls'],
        DOMAINS=code_an_dic['domains'],
        EMAILS=code_an_dic['emails'],
        STRINGS="",
        ZIPPED="",
        MANI=app_dic['mani'],
        EXPORTED_ACT=man_an_dic['exported_act'],
        E_ACT=man_an_dic['exported_cnt']["act"],
        E_SER=man_an_dic['exported_cnt']["ser"],
        E_BRO=man_an_dic['exported_cnt']["bro"],
        E_CNT=man_an_dic['exported_cnt']["cnt"]
    )
    STATIC_DB.save()


def StaticAnalyzer(request):
    try:
        #Input validation
        app_dic = {}

        typ = request.GET['type']
        # output = request.GET['format'] # Later for json output
        m = re.match('^[0-9a-f]{32}$', request.GET['checksum'])
        if (
                (
                    m
                ) and (
                    request.GET['name'].lower().endswith('.apk') or
                    request.GET['name'].lower().endswith('.zip')
                ) and (
                    typ in ['zip', 'apk']
                )
        ):
            app_dic['dir'] = settings.BASE_DIR  #BASE DIR
            app_dic['app_name'] = request.GET['name'] #APP ORGINAL NAME
            app_dic['md5'] = request.GET['checksum']  #MD5
            app_dic['app_dir'] = os.path.join(settings.UPLD_DIR, app_dic['md5']+'/') #APP DIRECTORY
            app_dic['tools_dir'] = os.path.join(app_dic['dir'], 'StaticAnalyzer/tools/')  #TOOLS DIR
            # DWD_DIR = settings.DWD_DIR # not needed? Var is never used.
            print "[INFO] Starting Analysis on : "+app_dic['app_name']
            rescan = str(request.GET.get('rescan', 0))
            if typ == 'apk':
                #Check if in DB
                db = StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5'])
                if db.exists() and rescan == '0':
                    context = _get_context_from_db_entry(db)
                else:
                    app_dic['app_file'] = app_dic['md5'] + '.apk'  #NEW FILENAME
                    app_dic['app_path'] = app_dic['app_dir'] + app_dic['app_file']  #APP PATH

                    # ANALYSIS BEGINS
                    app_dic['size'] = str(FileSize(app_dic['app_path'])) + 'MB'  #FILE SIZE
                    app_dic['sha1'], app_dic['sha256'] = HashGen(app_dic['app_path'])

                    app_dic['files'] = Unzip(app_dic['app_path'], app_dic['app_dir'])
                    app_dic['certz'] = GetHardcodedCertKeystore(app_dic['files'])

                    print "[INFO] APK Extracted"

                    # Manifest XML
                    app_dic['persed_xml'] = GetManifest(
                        app_dic['app_dir'],
                        app_dic['tools_dir'],
                        '',
                        True
                    )

                    # Set Manifest link
                    app_dic['mani'] = '../ManifestView/?md5='+app_dic['md5']+'&type=apk&bin=1'
                    man_data_dic = ManifestData(app_dic['persed_xml'], app_dic['app_dir'])

                    man_an_dic = ManifestAnalysis(
                        app_dic['persed_xml'],
                        man_data_dic
                    )

                    cert_dic = CertInfo(app_dic['app_dir'], app_dic['tools_dir'])
                    Dex2Jar(app_dic['app_path'], app_dic['app_dir'], app_dic['tools_dir'])
                    Dex2Smali(app_dic['app_dir'], app_dic['tools_dir'])
                    Jar2Java(app_dic['app_dir'], app_dic['tools_dir'])

                    code_an_dic = CodeAnalysis(
                        app_dic['app_dir'],
                        app_dic['md5'],
                        man_an_dic['permissons'],
                        "apk"
                    )

                    print "\n[INFO] Generating Java and Smali Downloads"
                    GenDownloads(app_dic['app_dir'], app_dic['md5'])

                    # Get the strings
                    app_dic['strings'] = Strings(
                        app_dic['app_file'],
                        app_dic['app_dir'],
                        app_dic['tools_dir']
                    )
                    app_dic['zipped'] = '&type=apk'

                    print "\n[INFO] Connecting to Database"
                    try:
                        #SAVE TO DB
                        if rescan == '1':
                            print "\n[INFO] Updating Database..."
                            _update_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic
                            )
                        elif rescan == '0':
                            print "\n[INFO] Saving to Database"
                            _create_db_entry(
                                app_dic,
                                man_data_dic,
                                man_an_dic,
                                code_an_dic,
                                cert_dic
                            )
                    except:
                        PrintException("[ERROR] Saving to Database Failed")
                    context = _get_context_from_an(
                        app_dic,
                        man_data_dic,
                        man_an_dic,
                        code_an_dic,
                        cert_dic
                    )
                template = "static_analysis.html"
                return render(request, template, context)
            elif typ == 'zip':
                #Check if in DB
                db = StaticAnalyzerAndroid.objects.filter(MD5=app_dic['md5'])
                if db.exists() and rescan == '0':
                    _get_context_from_db_entry_zip(db)
                else:
                    app_dic['app_file'] = app_dic['md5'] + '.zip'        #NEW FILENAME
                    app_dic['app_path'] = app_dic['app_dir']+ app_dic['app_file']    #APP PATH
                    print "[INFO] Extracting ZIP"
                    app_dic['files'] = Unzip(app_dic['app_path'], app_dic['app_dir'])
                    #Check if Valid Directory Structure and get ZIP Type
                    pro_type, Valid = ValidAndroidZip(app_dic['app_dir'])
                    if Valid and pro_type == 'ios':
                        print "[INFO] Redirecting to iOS Source Code Analyzer"
                        return HttpResponseRedirect(
                            '/StaticAnalyzer_iOS/?name=' + app_dic['app_name'] +
                            '&type=ios&checksum=' + app_dic['md5']
                        )
                    app_dic['certz'] = GetHardcodedCertKeystore(app_dic['files'])
                    print "[INFO] ZIP Type - " + pro_type
                    if Valid and (pro_type in ['eclipse', 'studio']):
                        #ANALYSIS BEGINS
                        app_dic['size'] = str(FileSize(app_dic['app_path'])) + 'MB'   #FILE SIZE
                        app_dic['sha1'], app_dic['sha256'] = HashGen(app_dic['app_path'])

                        # Manifest XML
                        app_dic['persed_xml'] = GetManifest(
                            app_dic['app_dir'],
                            app_dic['tools_dir'],
                            pro_type,
                            False
                        )

                        # Set manifest view link
                        app_dic['mani'] = (
                            '../ManifestView/?md5='+app_dic['md5']+'&type='+pro_type+'&bin=0'
                        )

                        man_data_dic = ManifestData(app_dic['persed_xml'], app_dic['app_dir'])

                        man_an_dic = ManifestAnalysis(
                            app_dic['persed_xml'],
                            man_data_dic
                        )

                        code_an_dic = CodeAnalysis(
                            app_dic['app_dir'],
                            app_dic['md5'],
                            man_an_dic['permissons'],
                            pro_type
                        )
                        print "\n[INFO] Connecting to Database"
                        try:
                            #SAVE TO DB
                            if rescan == '1':
                                print "\n[INFO] Updating Database..."
                                _update_db_entry_zip(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic
                                )
                            elif rescan == '0':
                                print "\n[INFO] Saving to Database"
                                _create_db_entry_zip(
                                    app_dic,
                                    man_data_dic,
                                    man_an_dic,
                                    code_an_dic,
                                    cert_dic
                                )
                        except:
                            PrintException("[ERROR] Saving to Database Failed")
                        context = _get_context_from_an_zip(
                            app_dic,
                            man_data_dic,
                            man_an_dic,
                            code_an_dic,
                            cert_dic
                        )
                    else:
                        return HttpResponseRedirect('/ZIP_FORMAT/')
                template = "static_analysis_android_zip.html"
                return render(request, template, context)
            else:
                print "\n[ERROR] Only APK,IPA and Zipped Android/iOS Source code supported now!"
        else:
            return HttpResponseRedirect('/error/')

    except Exception as e:
        PrintException("[ERROR] Static Analyzer")
        context = {
            'title': 'Error',
            'exp': e.message,
            'doc': e.__doc__
        }
        template = "error.html"
        return render(request, template, context)


def GetHardcodedCertKeystore(files):
    try:
        print "[INFO] Getting Hardcoded Certificates/Keystores"
        dat = ''
        certz = ''
        ks = ''
        for f in files:
            ext = f.split('.')[-1]
            if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                certz += escape(f) + "</br>"
            if re.search("jks|bks", ext):
                ks += escape(f) + "</br>"
        if len(certz) > 1:
            dat += (
                "<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>" +
                certz +
                "</td><tr>"
            )
        if len(ks) > 1:
            dat += "<tr><td>Hardcoded Keystore Found.</td><td>"+ks+"</td><tr>"
        return dat
    except:
        PrintException("[ERROR] Getting Hardcoded Certificates/Keystores")


def ReadManifest(APP_DIR, TOOLS_DIR, TYP, BIN):
    try:
        dat = ''

        if BIN == True:
            print "[INFO] Getting Manifest from Binary"
            print "[INFO] AXML -> XML"
            manifest = os.path.join(APP_DIR, "AndroidManifest.xml")
            if len(settings.AXMLPRINTER_BINARY) > 0 and isFileExists(settings.AXMLPRINTER_BINARY):
                CP_PATH = settings.AXMLPRINTER_BINARY
            else:
                CP_PATH = os.path.join(TOOLS_DIR, 'AXMLPrinter2.jar')

            args = [settings.JAVA_PATH + 'java', '-jar', CP_PATH, manifest]
            dat = subprocess.check_output(args)
        else:
            print "[INFO] Getting Manifest from Source"
            if TYP == "eclipse":
                manifest = os.path.join(APP_DIR, "AndroidManifest.xml")
            elif TYP == "studio":

                manifest = os.path.join(
                    APP_DIR, "app/src/main/AndroidManifest.xml"
                )
            with io.open(manifest, mode='r', encoding="utf8", errors="ignore") as f:
                dat = f.read()
        return dat
    except:
        PrintException("[ERROR] Reading Manifest file")


def GetManifest(APP_DIR, TOOLS_DIR, TYP, BIN):
    try:
        dat = ''
        mfest = ''
        dat = ReadManifest(APP_DIR, TOOLS_DIR, TYP, BIN).replace("\n", "")
        try:
            print "[INFO] Parsing AndroidManifest.xml"
            mfest = minidom.parseString(dat)
        except:
            PrintException("[ERROR] Pasrsing AndroidManifest.xml")
            mfest = minidom.parseString(
                (
                    r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android='
                    r'"http://schemas.android.com/apk/res/android" android:versionCode="Failed"  '
                    r'android:versionName="Failed" package="Failed"  '
                    r'platformBuildVersionCode="Failed" '
                    r'platformBuildVersionName="Failed XML Parsing" ></manifest>'
                )
            )
            print "[WARNING] Using Fake XML to continue the Analysis"
        return mfest
    except:
        PrintException("[ERROR] Parsing Manifest file")


def ValidAndroidZip(APP_DIR):
    try:
        print "[INFO] Checking for ZIP Validity and Mode"
        # Eclipse
        man = os.path.isfile(os.path.join(APP_DIR, "AndroidManifest.xml"))
        src = os.path.exists(os.path.join(APP_DIR, "src/"))
        if man and src:
            return 'eclipse', True
        # Studio
        man = os.path.isfile(
            os.path.join(
                APP_DIR, "app/src/main/AndroidManifest.xml"
            )
        )
        src = os.path.exists(os.path.join(APP_DIR, "app/src/main/java/"))
        if man and src:
            return 'studio', True
        # iOS Source
        xcode = [f for f in os.listdir(APP_DIR) if f.endswith(".xcodeproj")]
        if xcode:
            return 'ios', True
        return '', False
    except:
        PrintException("[ERROR] Determining Upload type")


def GenDownloads(APP_DIR, MD5):
    try:
        print "[INFO] Generating Downloads"
        # For Java
        DIR = os.path.join(APP_DIR, 'java_source/')
        DWD = os.path.join(settings.DWD_DIR, MD5 + '-java.zip')
        zipf = zipfile.ZipFile(DWD, 'w')
        zipdir(DIR, zipf)
        zipf.close()
        # For Smali
        DIR = os.path.join(APP_DIR, 'smali_source/')
        DWD = os.path.join(settings.DWD_DIR, MD5 + '-smali.zip')
        zipf = zipfile.ZipFile(DWD, 'w')
        zipdir(DIR, zipf)
        zipf.close()
    except:
        PrintException("[ERROR] Generating Downloads")


def zipdir(path, zip):
    try:
        print "[INFO] Zipping"
        for root, dirs, files in os.walk(path):
            for file in files:
                zip.write(os.path.join(root, file))
    except:
        PrintException("[ERROR] Zipping")


def FormatPermissions(PERMISSIONS):
    try:
        print "[INFO] Formatting Permissions"
        DESC = ''
        for ech in PERMISSIONS:
            DESC = DESC + '<tr><td>' + ech + '</td>'
            for l in PERMISSIONS[ech]:
                DESC = DESC + '<td>' + l + '</td>'
            DESC = DESC+ '</tr>'
        DESC = DESC.replace(
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
        return DESC
    except:
        PrintException("[ERROR] Formatting Permissions")


def CertInfo(APP_DIR, TOOLS_DIR):
    try:
        print "[INFO] Reading Code Signing Certificate"
        cert = os.path.join(APP_DIR, 'META-INF/')
        CP_PATH = TOOLS_DIR + 'CertPrint.jar'
        files = [f for f in os.listdir(cert) if os.path.isfile(os.path.join(cert, f))]
        certfile = None
        if "CERT.RSA" in files:
            certfile = os.path.join(cert, "CERT.RSA")
        else:
            for f in files:
                if f.lower().endswith(".rsa"):
                    certfile = os.path.join(cert, f)
                elif f.lower().endswith(".dsa"):
                    certfile = os.path.join(cert, f)
        if certfile:
            args = [settings.JAVA_PATH + 'java', '-jar', CP_PATH, certfile]
            dat = ''
            issued = 'good'
            dat = escape(subprocess.check_output(args)).replace('\n', '</br>')
        else:
            dat = 'No Code Signing Certificate Found!'
            issued = 'missing'
        if re.findall("Issuer: CN=Android Debug|Subject: CN=Android Debug", dat):
            issued = 'bad'

        cert_dic = {
            'cert_info' : dat,
            'issued' : issued
        }
        return cert_dic
    except:
        PrintException("[ERROR] Reading Code Signing Certificate")


def WinFixJava(TOOLS_DIR):
    try:
        print "[INFO] Running JAVA path fix in Windows"
        DMY = os.path.join(TOOLS_DIR, 'd2j2/d2j_invoke.tmp')
        ORG = os.path.join(TOOLS_DIR, 'd2j2/d2j_invoke.bat')
        dat = ''
        with open(DMY, 'r') as f:
            dat = f.read().replace("[xxx]", settings.JAVA_PATH + "java")
        with open(ORG, 'w') as f:
            f.write(dat)
    except:
        PrintException("[ERROR] Running JAVA path fix in Windows")


def WinFixPython3(TOOLS_DIR):
    try:
        print "[INFO] Running Python 3 path fix in Windows"
        PYTHON3_PATH = ""
        if len(settings.PYTHON3_PATH) > 2:
            PYTHON3_PATH = settings.PYTHON3_PATH
        else:
            pathenv = os.environ["path"]
            if pathenv:
                paths = pathenv.split(";")
                for path in paths:
                    if "python3" in path.lower():
                        PYTHON3_PATH = path
        PYTHON3 = "\"" + os.path.join(PYTHON3_PATH, "python") + "\""
        DMY = os.path.join(TOOLS_DIR, 'enjarify/enjarify.tmp')
        ORG = os.path.join(TOOLS_DIR, 'enjarify/enjarify.bat')
        dat = ''
        with open(DMY, 'r') as f:
            dat = f.read().replace("[xxx]", PYTHON3)
        with open(ORG, 'w') as f:
            f.write(dat)
    except:
        PrintException("[ERROR] Running Python 3 path fix in Windows")


def Dex2Jar(APP_PATH, APP_DIR, TOOLS_DIR):
    try:
        print "[INFO] DEX -> JAR"
        args = []
        working_dir = False
        if settings.JAR_CONVERTER == "d2j":
            print "[INFO] Using JAR converter - dex2jar"
            if platform.system() == "Windows":
                WinFixJava(TOOLS_DIR)
                D2J = os.path.join(TOOLS_DIR, 'd2j2/d2j-dex2jar.bat')
            else:
                INV = os.path.join(TOOLS_DIR, 'd2j2/d2j_invoke.sh')
                D2J = os.path.join(TOOLS_DIR, 'd2j2/d2j-dex2jar.sh')
                subprocess.call(["chmod", "777", D2J])
                subprocess.call(["chmod", "777", INV])
            if len(settings.DEX2JAR_BINARY) > 0 and isFileExists(settings.DEX2JAR_BINARY):
                D2J = settings.DEX2JAR_BINARY
            args = [
                D2J,
                APP_DIR + 'classes.dex',
                '-f',
                '-o',
                APP_DIR + 'classes.jar'
            ]
        elif settings.JAR_CONVERTER == "enjarify":
            print "[INFO] Using JAR converter - Google enjarify"
            if len(settings.ENJARIFY_DIRECTORY) > 0 and isDirExists(settings.ENJARIFY_DIRECTORY):
                WD = settings.ENJARIFY_DIRECTORY
            else:
                WD = os.path.join(TOOLS_DIR, 'enjarify/')
            if platform.system() == "Windows":
                WinFixPython3(TOOLS_DIR)
                EJ = os.path.join(WD, 'enjarify.bat')
                args = [EJ, APP_PATH, "-f", "-o", APP_DIR + 'classes.jar']
            else:
                working_dir = True
                if len(settings.PYTHON3_PATH) > 2:
                    PYTHON3 = os.path.join(settings.PYTHON3_PATH, "python3")
                else:
                    PYTHON3 = "python3"
                args = [
                    PYTHON3,
                    "-O",
                    "-m",
                    "enjarify.main",
                    APP_PATH,
                    "-f",
                    "-o",
                    APP_DIR +'classes.jar'
                ]
        if working_dir:
            subprocess.call(args, cwd=WD)
        else:
            subprocess.call(args)
    except:
        PrintException("[ERROR] Converting Dex to JAR")


def Dex2Smali(APP_DIR, TOOLS_DIR):
    try:
        print "[INFO] DEX -> SMALI"
        DEX_PATH = APP_DIR + 'classes.dex'
        if len(settings.BACKSMALI_BINARY) > 0 and isFileExists(settings.BACKSMALI_BINARY):
            BS_PATH = settings.BACKSMALI_BINARY
        else:
            BS_PATH = os.path.join(TOOLS_DIR, 'baksmali.jar')
        OUTPUT = os.path.join(APP_DIR, 'smali_source/')
        args = [
            settings.JAVA_PATH + 'java',
            '-jar', BS_PATH, DEX_PATH, '-o', OUTPUT
        ]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting DEX to SMALI")


def Jar2Java(APP_DIR, TOOLS_DIR):
    try:
        print "[INFO] JAR -> JAVA"
        JAR_PATH = APP_DIR + 'classes.jar'
        OUTPUT = os.path.join(APP_DIR, 'java_source/')
        if settings.DECOMPILER == 'jd-core':
            if (
                    len(settings.JD_CORE_DECOMPILER_BINARY) > 0 and
                    isFileExists(settings.JD_CORE_DECOMPILER_BINARY)
            ):
                JD_PATH = settings.JD_CORE_DECOMPILER_BINARY
            else:
                JD_PATH = os.path.join(TOOLS_DIR, 'jd-core.jar')
            args = [settings.JAVA_PATH+'java', '-jar', JD_PATH, JAR_PATH, OUTPUT]
        elif settings.DECOMPILER == 'cfr':
            if (
                    len(settings.CFR_DECOMPILER_BINARY) > 0 and
                    isFileExists(settings.CFR_DECOMPILER_BINARY)
            ):
                JD_PATH = settings.CFR_DECOMPILER_BINARY
            else:
                JD_PATH = os.path.join(TOOLS_DIR, 'cfr_0_115.jar')
            args = [settings.JAVA_PATH+'java', '-jar', JD_PATH, JAR_PATH, '--outputdir', OUTPUT]
        elif settings.DECOMPILER == "procyon":
            if (
                    len(settings.PROCYON_DECOMPILER_BINARY) > 0 and
                    isFileExists(settings.PROCYON_DECOMPILER_BINARY)
            ):
                PD_PATH = settings.PROCYON_DECOMPILER_BINARY
            else:
                PD_PATH = os.path.join(TOOLS_DIR, 'procyon-decompiler-0.5.30.jar')
            args = [settings.JAVA_PATH+'java', '-jar', PD_PATH, JAR_PATH, '-o', OUTPUT]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting JAR to JAVA")


def Strings(APP_FILE, APP_DIR, TOOLS_DIR):
    try:
        print "[INFO] Extracting Strings from APK"
        strings = TOOLS_DIR+'strings_from_apk.jar'
        args = [
            settings.JAVA_PATH + 'java',
            '-jar', strings, APP_DIR+APP_FILE, APP_DIR
        ]
        subprocess.call(args)
        dat = ''
        try:
            with io.open(APP_DIR+'strings.json', mode='r', encoding="utf8", errors="ignore") as f:
                dat = f.read()
        except:
            pass
        dat = dat[1:-1].split(",")
        return dat
    except:
        PrintException("[ERROR] Extracting Strings from APK")


def ManifestData(mfxml, app_dir):
    try:
        print "[INFO] Extracting Manifest Data"
        SVC = []
        ACT = []
        BRD = []
        CNP = []
        LIB = []
        PERM = []
        DP = {}
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
            act = activity.getAttribute("android:name")
            ACT.append(act)
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
            sn = service.getAttribute("android:name")
            SVC.append(sn)

        for provider in providers:
            pn = provider.getAttribute("android:name")
            CNP.append(pn)

        for receiver in receivers:
            re = receiver.getAttribute("android:name")
            BRD.append(re)

        for lib in libs:
            l = lib.getAttribute("android:name")
            LIB.append(l)

        for permission in permissions:
            perm = permission.getAttribute("android:name")
            PERM.append(perm)

        for i in PERM:
            prm = i
            pos = i.rfind(".")
            if pos != -1:
                prm = i[pos+1:]
            try:
                DP[i] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][prm]
            except KeyError:
                DP[i] = [
                    "dangerous",
                    "Unknown permission from android reference",
                    "Unknown permission from android reference"
                ]

        man_data_dic = {
            'services' : SVC,
            'activities' : ACT,
            'receivers' : BRD,
            'providers' : CNP,
            'libraries' : LIB,
            'perm' : DP,
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

def ManifestAnalysis(mfxml, man_data_dic):
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
        RET = ''
        EXPORTED = []
        PERMISSION_DICT = dict()
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

                PERMISSION_DICT[permission.getAttribute(
                    "android:name")] = protectionlevel
            elif permission.getAttribute("android:name"):
                PERMISSION_DICT[permission.getAttribute(
                    "android:name")] = "normal"

        # APPLICATIONS
        for application in applications:

            if application.getAttribute("android:debuggable") == "true":
                RET = (
                    RET + (
                        '<tr><td>Debug Enabled For App <br>[android:debuggable=true]</td><td>'
                        '<span class="label label-danger">high</span></td><td>Debugging was enabled'
                        ' on the app which makes it easier for reverse engineers to hook a debugger'
                        ' to it. This allows dumping a stack trace and accessing debugging helper '
                        'classes.</td></tr>'
                    )
                )
            if application.getAttribute("android:allowBackup") == "true":
                RET = (
                    RET+ (
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
                RET = (
                    RET+ (
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
                RET = (
                    RET+ (
                        '<tr><td>Application is in Test Mode <br>[android:testOnly=true]</td><td>'
                        '<span class="label label-danger">high</span></td><td> It may expose '
                        'functionality or data outside of itself that would cause a security hole.'
                        '</td></tr>'
                    )
                )

            for node in application.childNodes:
                ad = ''
                if node.nodeName == 'activity':
                    itmname = 'Activity'
                    cnt_id = "act"
                    ad = 'n'
                elif node.nodeName == 'activity-alias':
                    itmname = 'Activity-Alias'
                    cnt_id = "act"
                    ad = 'n'
                elif node.nodeName == 'provider':
                    itmname = 'Content Provider'
                    cnt_id = "cnt"
                elif node.nodeName == 'receiver':
                    itmname = 'Broadcast Receiver'
                    cnt_id = "bro"
                elif node.nodeName == 'service':
                    itmname = 'Service'
                    cnt_id = "ser"
                else:
                    itmname = 'NIL'
                item = ''

                #Task Affinity
                if (
                        itmname  in ['Activity', 'Activity-Alias'] and
                        node.getAttribute("android:taskAffinity")
                ):
                    item = node.getAttribute("android:name")
                    # pylint: disable=C0301
                    RET = RET+ '<tr><td>TaskAffinity is set for Activity </br>('+item + ')</td><td><span class="label label-danger">high</span></td><td>If taskAffinity is set, then other application could read the Intents sent to Activities belonging to another task. Always use the default setting keeping the affinity as the package name in order to prevent sensitive information inside sent or received Intents from being read by another application.</td></tr>'

                #LaunchMode
                if (
                        itmname in ['Activity', 'Activity-Alias'] and
                        (
                            node.getAttribute("android:launchMode") == 'singleInstance' or
                            node.getAttribute("android:launchMode") == 'singleTask'
                        )
                ):
                    item = node.getAttribute("android:name")
                    # pylint: disable=C0301
                    RET = RET+ '<tr><td>Launch Mode of Activity ('+item + ') is not standard.</td><td><span class="label label-danger">high</span></td><td>An Activity should not be having the launch mode attribute set to "singleTask/singleInstance" as it becomes root Activity and it is possible for other applications to read the contents of the calling Intent. So it is required to use the "standard" launch mode attribute when sensitive information is included in an Intent.</td></tr>'
                #Exported Check
                item = ''
                isInf = False
                isPermExist = False
                if 'NIL' != itmname:
                    if node.getAttribute("android:exported") == 'true':
                        perm = ''
                        item = node.getAttribute("android:name")
                        if node.getAttribute("android:permission"):
                            #permission exists
                            perm = (
                                '<strong>Permission: </strong>' +
                                node.getAttribute("android:permission")
                            )
                            isPermExist = True
                        if item != man_data_dic['mainactivity']:
                            if isPermExist:
                                prot = ""
                                if node.getAttribute("android:permission") in PERMISSION_DICT:
                                    prot = (
                                        "</br><strong>protectionLevel: </strong>" +
                                        PERMISSION_DICT[node.getAttribute("android:permission")]
                                    )
                                RET = (
                                    RET + '<tr><td><strong>' + itmname + '</strong> (' +
                                    item + ') is Protected by a permission.</br>' +
                                    perm + prot + ' <br>[android:exported=true]</td>' +
                                    '<td><span class="label label-info">info</span></td><td> A' +
                                    ad + ' ' + itmname +
                                    ' is found to be exported, but is protected by permission.' +
                                    '</td></tr>'
                                )
                            else:
                                if (itmname in ['Activity', 'Activity-Alias']):
                                    EXPORTED.append(item)
                                RET = (
                                    RET + '<tr><td><strong>' + itmname + '</strong> (' +
                                    item + ') is not Protected. <br>[android:exported=true]</td>' +
                                    '<td><span class="label label-danger">high</span></td><td> A' +
                                    ad + ' ' + itmname + ' is found to be shared with other apps' +
                                    ' on the device therefore leaving it accessible to any other' +
                                    ' application on the device.</td></tr>'
                                )
                                exp_count[cnt_id] = exp_count[cnt_id] + 1
                    elif node.getAttribute("android:exported") != 'false':
                        #Check for Implicitly Exported
                        #Logic to support intent-filter
                        intentfilters = node.childNodes
                        for i in intentfilters:
                            inf = i.nodeName
                            if inf == "intent-filter":
                                isInf = True
                        if isInf:
                            item = node.getAttribute("android:name")
                            if node.getAttribute("android:permission"):
                                #permission exists
                                perm = (
                                    '<strong>Permission: </strong>' +
                                    node.getAttribute("android:permission")
                                )
                                isPermExist = True
                            if item != man_data_dic['mainactivity']:
                                if isPermExist:
                                    prot = ""
                                    if node.getAttribute("android:permission") in PERMISSION_DICT:
                                        prot = (
                                            "</br><strong>protectionLevel: </strong>" +
                                            PERMISSION_DICT[node.getAttribute("android:permission")]
                                        )
                                    RET = (
                                        RET +'<tr><td><strong>'+itmname+'</strong> (' + item +
                                        ') is Protected by a permission.</br>' + perm + prot +
                                        ' <br>[android:exported=true]</td>' +
                                        '<td><span class="label label-info">info</span></td>' +
                                        '<td> A' + ad + ' ' + itmname + ' is found to be ' +
                                        'exported, but is protected by permission.</td></tr>'
                                    )
                                else:
                                    if (itmname in ['Activity', 'Activity-Alias']):
                                        EXPORTED.append(item)
                                    RET = (
                                        RET + '<tr><td><strong>' + itmname + '</strong> (' + item +
                                        ') is not Protected.<br>An intent-filter exists.</td>'
                                        '<td><span class="label label-danger">high</span></td>'
                                        '<td> A' + ad + ' ' + itmname + ' is found to be shared '
                                        'with other apps on the device therefore leaving it '
                                        'accessible to any other application on the device. The '
                                        'presence of intent-filter indicates that the ' + itmname +
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
                RET = (
                    RET + '<tr><td>' + title + '<br> [pathPrefix=/] </td>' + '<td>'
                    '<span class="label label-danger">high</span></td><td>' + desc + '</td></tr>'
                )
            elif granturi.getAttribute("android:path") == '/':
                RET = (
                    RET + '<tr><td>' + title + '<br> [path=/] </td>' + '<td>'
                    '<span class="label label-danger">high</span></td><td>' + desc + '</td></tr>'
                )
            elif granturi.getAttribute("android:pathPattern") == '*':
                RET = (
                    RET + '<tr><td>' + title + '<br> [path=*]</td>' + '<td>'
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
                RET = (
                    RET + '<tr><td>Dailer Code: ' + xmlhost + 'Found <br>'
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
                RET = (
                    RET + '<tr><td> on Port: ' + dataport + 'Found<br>[android:port]</td>'
                    '<td><span class="label label-danger">high</span></td><td>'+ desc +'</td></tr>'
                )

        # INTENTS

        for intent in intents:
            if intent.getAttribute("android:priority").isdigit():
                value = intent.getAttribute("android:priority")
                if int(value) > 100:
                    RET = (
                        RET + '<tr><td>High Intent Priority ('+ value +')<br>'
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
                    RET = (
                        RET + '<tr><td>High Action Priority (' + value + ')<br>[android:priority]'
                        '</td><td><span class="label label-warning">medium</span></td><td>By '
                        'setting an action priority higher than another action, the app effectively'
                        ' overrides other requests.</td></tr>'
                    )
        if len(RET) < 2:
            RET = '<tr><td>None</td><td>None</td><td>None</td><tr>'

        # Prepare return dict
        man_an_dic = {
            'manifest_anal' : RET,
            'exported_act' : EXPORTED,
            'exported_cnt' : exp_count,
            'permissons' : FormatPermissions(man_data_dic['perm']),
            'cnt_act' : len(man_data_dic['activities']),
            'cnt_pro' : len(man_data_dic['providers']),
            'cnt_ser' : len(man_data_dic['services']),
            'cnt_bro' : len(man_data_dic['receivers'])
        }
        return man_an_dic
    except:
        PrintException("[ERROR] Performing Manifest Analysis")

def CodeAnalysis(APP_DIR, MD5, PERMS, TYP):
    try:
        print "[INFO] Static Android Code Analysis Started"
        c = {
            key: [] for key in (
                'inf_act',
                'inf_ser',
                'inf_bro',
                'log',
                'fileio',
                'rand',
                'd_hcode',
                'd_app_tamper',
                'dex_cert',
                'dex_tamper',
                'd_rootcheck',
                'd_root',
                'd_ssl_pin',
                'dex_root',
                'dex_debug_key',
                'dex_debug',
                'dex_debug_con',
                'dex_emulator',
                'd_prevent_screenshot',
                'd_webviewdisablessl',
                'd_webviewdebug',
                'd_sensitive',
                'd_ssl',
                'd_sqlite',
                'd_con_world_readable',
                'd_con_world_writable',
                'd_con_private',
                'd_extstorage',
                'd_tmpfile',
                'd_jsenabled',
                'gps',
                'crypto',
                'exec',
                'server_socket',
                'socket',
                'datagramp',
                'datagrams',
                'ipc',
                'msg',
                'webview_addjs',
                'webview',
                'webviewget',
                'webviewpost',
                'httpcon',
                'urlcon',
                'jurl',
                'httpsurl',
                'nurl',
                'httpclient',
                'notify',
                'cellinfo',
                'cellloc',
                'subid',
                'devid',
                'softver',
                'simserial',
                'simop',
                'opname',
                'contentq',
                'refmethod',
                'obf',
                'gs',
                'bencode',
                'bdecode',
                'dex',
                'mdigest',
                'sqlc_password',
                'd_sql_cipher',
                'd_con_world_rw',
                'ecb',
                'rsa_no_pad',
                'weak_iv'
            )
        }
        crypto = False
        obfus = False
        reflect = False
        dynamic = False
        native = False
        EmailnFile = ''
        URLnFile = ''
        ALLURLSLST = list()
        DOMAINS = dict()
        if TYP == "apk":
            JS = os.path.join(APP_DIR, 'java_source/')
        elif TYP == "studio":
            JS = os.path.join(APP_DIR, 'app/src/main/java/')
        elif TYP == "eclipse":
            JS = os.path.join(APP_DIR, 'src/')
        print "[INFO] Code Analysis Started on - " + JS
        for dirName, subDir, files in os.walk(JS):
            for jfile in files:
                jfile_path = os.path.join(JS, dirName, jfile)
                if "+" in jfile:
                    p2 = os.path.join(JS, dirName, jfile.replace("+", "x"))
                    shutil.move(jfile_path, p2)
                    jfile_path = p2
                repath = dirName.replace(JS, '')
                if (
                        jfile.endswith('.java') and
                        any(cls in repath for cls in settings.SKIP_CLASSES) == False
                ):
                    dat = ''
                    with io.open(jfile_path, mode='r', encoding="utf8", errors="ignore") as f:
                        dat = f.read()
                    #Initialize
                    URLS = []
                    EMAILS = []

                    #Code Analysis
                    #print "[INFO] Doing Code Analysis on - " + jfile_path
                    #==========================Android Security Code Review ========================
                    if (
                            re.findall(r'MODE_WORLD_READABLE|Context\.MODE_WORLD_READABLE', dat) or
                            re.findall(r'openFileOutput\(\s*".+"\s*,\s*1\s*\)', dat)
                    ):
                        c['d_con_world_readable'].append(jfile_path.replace(JS, ''))
                    if (
                            re.findall(r'MODE_WORLD_WRITABLE|Context\.MODE_WORLD_WRITABLE', dat) or
                            re.findall(r'openFileOutput\(\s*".+"\s*,\s*2\s*\)', dat)
                    ):
                        c['d_con_world_writable'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'openFileOutput\(\s*".+"\s*,\s*3\s*\)', dat):
                        c['d_con_world_rw'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'MODE_PRIVATE|Context\.MODE_PRIVATE', dat):
                        c['d_con_private'].append(jfile_path.replace(JS, ''))
                    if (
                            'WRITE_EXTERNAL_STORAGE' in PERMS and
                            (
                                '.getExternalStorage' in dat or
                                '.getExternalFilesDir(' in dat
                            )
                    ):
                        c['d_extstorage'].append(jfile_path.replace(JS, ''))
                    if 'WRITE_EXTERNAL_STORAGE' in PERMS and '.createTempFile(' in dat:
                        c['d_tmpfile'].append(jfile_path.replace(JS, ''))
                    if (
                            'setJavaScriptEnabled(true)' in dat and
                            '.addJavascriptInterface(' in dat
                    ):
                        c['d_jsenabled'].append(jfile_path.replace(JS, ''))
                    if (
                            '.setWebContentsDebuggingEnabled(true)' in dat and
                            'WebView' in dat
                    ):
                        c['d_webviewdebug'].append(jfile_path.replace(JS, ''))
                    if 'onReceivedSslError(WebView' in dat and '.proceed();' in dat:
                        c['d_webviewdisablessl'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'rawQuery(' in dat or
                                'execSQL(' in dat
                            ) and 'android.database.sqlite' in dat
                    ):
                        c['d_sqlite'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                ('javax.net.ssl') in dat
                            ) and (
                                ('TrustAllSSLSocket-Factory') in dat or
                                ('AllTrustSSLSocketFactory') in dat or
                                ('NonValidatingSSLSocketFactory') in dat or
                                ('ALLOW_ALL_HOSTNAME_VERIFIER') in dat or
                                ('.setDefaultHostnameVerifier(') in dat or
                                ('NullHostnameVerifier(') in dat
                            )
                    ):
                        c['d_ssl'].append(jfile_path.replace(JS, ''))
                    if (
                            'password = "' in dat.lower() or
                            'secret = "' in dat.lower() or
                            'username = "' in dat.lower() or
                            'key = "' in dat.lower()
                    ):
                        c['d_sensitive'].append(jfile_path.replace(JS, ''))
                    if (
                            'import dexguard.util' in dat and
                            'DebugDetector.isDebuggable' in dat
                    ):
                        c['dex_debug'].append(jfile_path.replace(JS, ''))
                    if (
                            'import dexguard.util' in dat and
                            'DebugDetector.isDebuggerConnected' in dat
                    ):
                        c['dex_debug_con'].append(jfile_path.replace(JS, ''))
                    if (
                            ('import dexguard.util') in dat and
                            ('EmulatorDetector.isRunningInEmulator') in dat
                    ):
                        c['dex_emulator'].append(jfile_path.replace(JS, ''))
                    if (
                            ('import dexguard.util') in dat and
                            ('DebugDetector.isSignedWithDebugKey') in dat
                    ):
                        c['dex_debug_key'].append(jfile_path.replace(JS, ''))
                    if 'import dexguard.util' in dat and 'RootDetector.isDeviceRooted' in dat:
                        c['dex_root'].append(jfile_path.replace(JS, ''))
                    if 'import dexguard.util' in dat and 'TamperDetector.checkApk' in dat:
                        c['dex_tamper'].append(jfile_path.replace(JS, ''))
                    if (
                            'import dexguard.util' in dat and
                            'CertificateChecker.checkCertificate' in dat
                    ):
                        c['dex_cert'].append(jfile_path.replace(JS, ''))
                    if (
                            'org.thoughtcrime.ssl.pinning' in dat and (
                                'PinningHelper.getPinnedHttpsURLConnection' in dat or
                                'PinningHelper.getPinnedHttpClient' in dat or
                                'PinningSSLSocketFactory(' in dat
                            )
                    ):
                        c['d_ssl_pin'].append(jfile_path.replace(JS, ''))
                    if ('PackageManager.GET_SIGNATURES' in dat) and ('getPackageName(' in dat):
                        c['d_app_tamper'].append(jfile_path.replace(JS, ''))
                    if (
                            'com.noshufou.android.su' in dat or
                            'com.thirdparty.superuser' in dat or
                            'eu.chainfire.supersu' in dat or
                            'com.koushikdutta.superuser' in dat or
                            'eu.chainfire.' in dat
                    ):
                        c['d_root'].append(jfile_path.replace(JS, ''))
                    if (
                            ('.contains("test-keys")') in dat or
                            ('/system/app/Superuser.apk') in dat or
                            ('isDeviceRooted()') in dat or
                            ('/system/bin/failsafe/su') in dat or
                            ('/system/sd/xbin/su') in dat or
                            ('"/system/xbin/which", "su"') in dat or
                            ('RootTools.isAccessGiven()') in dat
                    ):
                        c['d_rootcheck'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'java\.util\.Random', dat):
                        c['rand'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'Log\.(v|d|i|w|e|f|s)|System\.out\.print', dat):
                        c['log'].append(jfile_path.replace(JS, ''))
                    if ".hashCode()" in dat:
                        c['d_hcode'].append(jfile_path.replace(JS, ''))
                    if "getWindow().setFlags(" in dat and ".FLAG_SECURE" in dat:
                        c['d_prevent_screenshot'].append(jfile_path.replace(JS, ''))
                    if "SQLiteOpenHelper.getWritableDatabase(" in dat:
                        c['sqlc_password'].append(jfile_path.replace(JS, ''))
                    if "SQLiteDatabase.loadLibs(" in dat and "net.sqlcipher." in dat:
                        c['d_sql_cipher'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'Cipher\.getInstance\(\s*"\s*AES\/ECB', dat):
                        c['ecb'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'cipher\.getinstance\(\s*"rsa/.+/nopadding', dat.lower()):
                        c['rsa_no_pad'].append(jfile_path.replace(JS, ''))
                    if (
                            "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" in dat or
                            "0x01,0x02,0x03,0x04,0x05,0x06,0x07" in dat
                    ):
                        c['weak_iv'].append(jfile_path.replace(JS, ''))

                    #Inorder to Add rule to Code Analysis, add identifier to c, add rule here and
                    # define identifier description and severity the bottom of this function.
                    #=========================Android API Analysis =========================
                    #API Check

                    if re.findall(r"System.loadLibrary\(|System.load\(", dat):
                        native = True
                    if (
                            re.findall(
                                (
                                    r'dalvik.system.DexClassLoader|java.security.ClassLoader|'
                                    r'java.net.URLClassLoader|java.security.SecureClassLoader'
                                ),
                                dat
                            )
                    ):
                        dynamic = True
                    if (
                            re.findall(
                                'java.lang.reflect.Method|java.lang.reflect.Field|Class.forName',
                                dat
                            )
                    ):
                        reflect = True
                    if re.findall('javax.crypto|kalium.crypto|bouncycastle.crypto', dat):
                        crypto = True
                        c['crypto'].append(jfile_path.replace(JS, ''))
                    if 'utils.AESObfuscator' in dat and 'getObfuscator' in dat:
                        c['obf'].append(jfile_path.replace(JS, ''))
                        obfus = True

                    if 'getRuntime().exec(' in dat and 'getRuntime(' in dat:
                        c['exec'].append(jfile_path.replace(JS, ''))
                    if 'ServerSocket' in dat and 'net.ServerSocket' in dat:
                        c['server_socket'].append(jfile_path.replace(JS, ''))
                    if 'Socket' in dat and 'net.Socket' in dat:
                        c['socket'].append(jfile_path.replace(JS, ''))
                    if 'DatagramPacket' in dat and 'net.DatagramPacket' in dat:
                        c['datagramp'].append(jfile_path.replace(JS, ''))
                    if 'DatagramSocket' in dat and 'net.DatagramSocket' in dat:
                        c['datagrams'].append(jfile_path.replace(JS, ''))
                    if re.findall('IRemoteService|IRemoteService.Stub|IBinder|Intent', dat):
                        c['ipc'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'sendMultipartTextMessage' in dat or
                                'sendTextMessage' in dat or
                                'vnd.android-dir/mms-sms' in dat
                            ) and (
                                'telephony.SmsManager' in dat
                            )
                    ):
                        c['msg'].append(jfile_path.replace(JS, ''))
                    if (
                            'addJavascriptInterface' in dat and
                            'WebView' in dat and
                            'android.webkit' in dat
                    ):
                        c['webview_addjs'].append(jfile_path.replace(JS, ''))
                    if 'WebView' in dat and 'loadData' in dat and 'android.webkit' in dat:
                        c['webviewget'].append(jfile_path.replace(JS, ''))
                    if 'WebView' in dat and 'postUrl' in dat and 'android.webkit' in dat:
                        c['webviewpost'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'HttpURLConnection' in dat or
                                'org.apache.http' in dat
                            ) and (
                                'openConnection' in dat or
                                'connect' in dat or
                                'HttpRequest' in dat
                            )
                    ):
                        c['httpcon'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'net.URLConnection' in dat
                            ) and (
                                'connect' in dat or
                                'openConnection' in dat or
                                'openStream' in dat
                            )
                    ):
                        c['urlcon'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'net.JarURLConnection' in dat
                            ) and (
                                'JarURLConnection' in dat or
                                'jar:' in dat
                            )
                    ):
                        c['jurl'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'javax.net.ssl.HttpsURLConnection' in dat
                            ) and (
                                'HttpsURLConnection' in dat or
                                'connect' in dat
                            )
                    ):
                        c['httpsurl'].append(jfile_path.replace(JS, ''))
                    if (('net.URL') and ('openConnection' or 'openStream')) in dat:
                        c['nurl'].append(jfile_path.replace(JS, ''))
                    if (
                            re.findall(
                                (
                                    'http.client.HttpClient|net.http.AndroidHttpClient|'
                                    'http.impl.client.AbstractHttpClient'
                                ),
                                dat
                            )
                    ):
                        c['httpclient'].append(jfile_path.replace(JS, ''))
                    if 'app.NotificationManager' in dat and 'notify' in dat:
                        c['notify'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getAllCellInfo' in dat:
                        c['cellinfo'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getCellLocation' in dat:
                        c['cellloc'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSubscriberId' in dat:
                        c['subid'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getDeviceId' in dat:
                        c['devid'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getDeviceSoftwareVersion' in dat:
                        c['softver'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSimSerialNumber' in dat:
                        c['simserial'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSimOperator' in dat:
                        c['simop'].append(jfile_path.replace(JS, ''))
                    if 'telephony.TelephonyManager' in dat and 'getSimOperatorName' in dat:
                        c['opname'].append(jfile_path.replace(JS, ''))
                    if 'content.ContentResolver' in dat and 'query' in dat:
                        c['contentq'].append(jfile_path.replace(JS, ''))
                    if 'java.lang.reflect.Method' in dat and 'invoke' in dat:
                        c['refmethod'].append(jfile_path.replace(JS, ''))
                    if 'getSystemService' in dat:
                        c['gs'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'android.util.Base64' in dat
                            ) and (
                                '.encodeToString' in dat or
                                '.encode' in dat
                            )
                    ):
                        c['bencode'].append(jfile_path.replace(JS, ''))
                    if 'android.util.Base64' in dat and '.decode' in dat:
                        c['bdecode'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'dalvik.system.PathClassLoader' in dat or
                                'dalvik.system.DexFile' in dat or
                                'dalvik.system.DexPathList' in dat or
                                'dalvik.system.DexClassLoader' in dat
                            ) and (
                                'loadDex' in dat or
                                'loadClass' in dat or
                                'DexClassLoader' in dat or
                                'loadDexFile' in dat
                            )
                    ):
                        c['dex'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'java.security.MessageDigest' in dat
                            ) and (
                                'MessageDigestSpi' in dat or
                                'MessageDigest' in dat
                            )
                        ):
                        c['mdigest'].append(jfile_path.replace(JS, ''))
                    if (
                            (
                                'android.location' in dat
                            )and (
                                ('getLastKnownLocation(') in dat or
                                'requestLocationUpdates(' in dat or
                                ('getLatitude(') in dat or
                                'getLongitude(' in dat
                            )
                    ):
                        c['gps'].append(jfile_path.replace(JS, ''))
                    if re.findall(
                            (
                                'OpenFileOutput|getSharedPreferences|SharedPreferences.Editor|'
                                'getCacheDir|getExternalStorageState|openOrCreateDatabase'
                            ),
                            dat
                    ):
                        c['fileio'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'startActivity\(|startActivityForResult\(', dat):
                        c['inf_act'].append(jfile_path.replace(JS, ''))
                    if re.findall(r'startService\(|bindService\(', dat):
                        c['inf_ser'].append(jfile_path.replace(JS, ''))
                    if re.findall(
                            r'sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(', dat
                    ):
                        c['inf_bro'].append(jfile_path.replace(JS, ''))

                    fl = jfile_path.replace(JS, '')
                    base_fl = ntpath.basename(fl)

                    #URLs My Custom regex
                    p = re.compile(
                        (
                            ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])'
                            ur'[\w().=/;,#:@?&~*+!$%\'{}-]+)'
                        ),
                        re.UNICODE
                    )

                    urllist = re.findall(p, dat.lower())
                    ALLURLSLST.extend(urllist)
                    uflag = 0
                    for url in urllist:
                        if url not in URLS:
                            URLS.append(url)
                            uflag = 1
                    if uflag == 1:
                        URLnFile += (
                            "<tr><td>" + "<br>".join(URLS) +
                            "</td><td><a href='../ViewSource/?file=" + escape(fl) +
                            "&md5=" + MD5 + "&type=" + TYP + "'>" + escape(base_fl) +
                            "</a></td></tr>"
                        )

                    # Email Etraction Regex
                    regex = re.compile(r'[\w.-]+@[\w-]+\.[\w.]+')
                    eflag = 0
                    for email in regex.findall(dat.lower()):
                        if (email not in EMAILS) and (not email.startswith('//')):
                            EMAILS.append(email)
                            eflag = 1
                    if eflag == 1:
                        EmailnFile += (
                            "<tr><td>" + "<br>".join(EMAILS) +
                            "</td><td><a href='../ViewSource/?file=" + escape(fl) +
                            "&md5=" + MD5 + "&type=" + TYP +"'>" + escape(base_fl) +
                            "</a></td></tr>"
                        )

        # Domain Extraction and Malware Check
        print "[INFO] Performing Malware Check on extracted Domains"
        DOMAINS = MalwareCheck(ALLURLSLST)
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        #API Description
        dc = {
            'gps':'GPS Location',
            'crypto':'Crypto ',
            'exec': 'Execute System Command ',
            'server_socket':'TCP Server Socket ',
            'socket': 'TCP Socket ',
            'datagramp': 'UDP Datagram Packet ',
            'datagrams': 'UDP Datagram Socket ',
            'ipc': 'Inter Process Communication ',
            'msg': 'Send SMS ',
            'webview_addjs':'WebView JavaScript Interface ',
            'webview': 'WebView Load HTML/JavaScript ',
            'webviewget': 'WebView GET Request ',
            'webviewpost': 'WebView POST Request ',
            'httpcon': 'HTTP Connection ',
            'urlcon':'URL Connection to file/http/https/ftp/jar ',
            'jurl':'JAR URL Connection ',
            'httpsurl':'HTTPS Connection ',
            'nurl':'URL Connection supports file,http,https,ftp and jar ',
            'httpclient':'HTTP Requests, Connections and Sessions ',
            'notify': 'Android Notifications ',
            'cellinfo':'Get Cell Information ',
            'cellloc':'Get Cell Location ',
            'subid':'Get Subscriber ID ',
            'devid':'Get Device ID, IMEI,MEID/ESN etc. ',
            'softver':'Get Software Version, IMEI/SV etc. ',
            'simserial': 'Get SIM Serial Number ',
            'simop': 'Get SIM Provider Details ',
            'opname':'Get SIM Operator Name ',
            'contentq':'Query Database of SMS, Contacts etc. ',
            'refmethod':'Java Reflection Method Invocation ',
            'obf': 'Obfuscation ',
            'gs':'Get System Service ',
            'bencode':'Base64 Encode ',
            'bdecode':'Base64 Decode ',
            'dex':'Load and Manipulate Dex Files ',
            'mdigest': 'Message Digest ',
            'fileio': 'Local File I/O Operations',
            'inf_act': 'Starting Activity',
            'inf_ser': 'Starting Service',
            'inf_bro': 'Sending Broadcast'
            }
        html = ''
        for ky in dc:
            if c[ky]:
                link = ''
                hd = "<tr><td>"+dc[ky]+"</td><td>"
                for l in c[ky]:
                    link += (
                        "<a href='../ViewSource/?file=" + escape(l) + "&md5=" + MD5 + "&type=" +
                        TYP + "'>" + escape(ntpath.basename(l)) + "</a> "
                    )
                html += hd+link+"</td></tr>"

        #Security Code Review Description
        dg = {
            'd_sensitive' :
                (
                    'Files may contain hardcoded sensitive informations like '
                    'usernames, passwords, keys etc.'
                ),
            'd_ssl':
                (
                    'Insecure Implementation of SSL. Trusting all the certificates or accepting '
                    'self signed certificates is a critical Security Hole. This application is '
                    'vulnerable to MITM attacks'
                ),
            'd_sqlite':
                (
                    'App uses SQLite Database and execute raw SQL query. Untrusted user input in '
                    'raw SQL queries can cause SQL Injection. Also sensitive information should be '
                    'encrypted and written to the database.'
                ),
            'd_con_world_readable':
                (
                    'The file is World Readable. Any App can read from the file'
                ),
            'd_con_world_writable':
                (
                    'The file is World Writable. Any App can write to the file'
                ),
            'd_con_world_rw':
                (
                    'The file is World Readable and Writable. Any App can read/write to the file'
                ),
            'd_con_private':
                (
                    'App can write to App Directory. Sensitive Information should be encrypted.'
                ),
            'd_extstorage':
                (
                    'App can read/write to External Storage. Any App can read data written to '
                    'External Storage.'
                ),
            'd_tmpfile':
                (
                    'App creates temp file. Sensitive information should never be written into a '
                    'temp file.'
                ),
            'd_jsenabled':
                (
                    'Insecure WebView Implementation. Execution of user controlled code in WebView '
                    'is a critical Security Hole.'
                ),
            'd_webviewdisablessl':
                (
                    'Insecure WebView Implementation. WebView ignores SSL Certificate errors and '
                    'accept any SSL Certificate. This application is vulnerable to MITM attacks'
                ),
            'd_webviewdebug':
                (
                    'Remote WebView debugging is enabled.'
                ),
            'dex_debug':
                (
                    'DexGuard Debug Detection code to detect wheather an App is debuggable or not '
                    'is identified.'
                ),
            'dex_debug_con':
                (
                    'DexGuard Debugger Detection code is identified.'
                ),
            'dex_debug_key':
                (
                    'DecGuard code to detect wheather the App is signed with a debug key or not '
                    'is identified.'
                ),
            'dex_emulator':
                (
                    'DexGuard Emulator Detection code is identified.'
                ),
            'dex_root':
                (
                    'DexGuard Root Detection code is identified.'
                ),
            'dex_tamper' :
                (
                    'DexGuard App Tamper Detection code is identified.'
                ),
            'dex_cert' :
                (
                    'DexGuard Signer Certificate Tamper Detection code is identified.'
                ),
            'd_ssl_pin':
                (
                    ' This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to '
                    'prevent MITM attacks in secure communication channel.'
                ),
            'd_root' :
                (
                    'This App may request root (Super User) privileges.'
                ),
            'd_rootcheck' :
                (
                    'This App may have root detection capabilities.'
                ),
            'd_hcode' :
                (
                    'This App uses Java Hash Code. It\'s a weak hash function and should never be '
                    'used in Secure Crypto Implementation.'
                ),
            'rand' :
                (
                    'The App uses an insecure Random Number Generator.'
                ),
            'log' :
                (
                    'The App logs information. Sensitive information should never be logged.'
                ),
            'd_app_tamper' :
                (
                    'The App may use package signature for tamper detection.'
                ),
            'd_prevent_screenshot' :
                (
                    'This App has capabilities to prevent against Screenshots from Recent Task '
                    'History/ Now On Tap etc.'
                ),
            'd_sql_cipher' :
                (
                    'This App uses SQL Cipher. SQLCipher provides 256-bit AES encryption to sqlite '
                    'database files.'
                ),
            'sqlc_password' :
                (
                    'This App uses SQL Cipher. But the secret may be hardcoded.'
                ),
            'ecb' :
                (
                    'The App uses ECB mode in Cryptographic encryption algorithm. ECB mode is '
                    'known to be weak as it results in the same ciphertext for identical blocks '
                    'of plaintext.'
                ),
            'rsa_no_pad' :
                (
                    'This App uses RSA Crypto without OAEP padding. The purpose of the padding '
                    'scheme is to prevent a number of attacks on RSA that only work when the '
                    'encryption is performed without padding.'
                ),
            'weak_iv' :
                (
                    'The App may use weak IVs like "0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00" or '
                    '"0x01,0x02,0x03,0x04,0x05,0x06,0x07". Not using a random IV makes the '
                    'resulting ciphertext much more predictable and susceptible to a dictionary '
                    'attack.'
                ),
        }

        dang = ''
        spn_dang = '<span class="label label-danger">high</span>'
        spn_info = '<span class="label label-info">info</span>'
        spn_sec = '<span class="label label-success">secure</span>'
        spn_warn = '<span class="label label-warning">warning</span>'

        for k in dg:
            if c[k]:
                link = ''
                if re.findall('d_con_private|log', k):
                    hd = '<tr><td>'+dg[k]+'</td><td>'+spn_info+'</td><td>'
                elif re.findall(
                    (
                        'd_sql_cipher|d_prevent_screenshot|d_app_tamper|d_rootcheck|dex_cert|'
                        'dex_tamper|dex_debug|dex_debug_con|dex_debug_key|dex_emulator|dex_root'
                        '|d_ssl_pin'
                    ),
                    k
                ):
                    hd = '<tr><td>'+dg[k]+'</td><td>'+spn_sec+'</td><td>'
                elif re.findall('d_jsenabled', k):
                    hd = '<tr><td>'+dg[k]+'</td><td>'+spn_warn+'</td><td>'
                else:
                    hd = '<tr><td>'+dg[k]+'</td><td>'+spn_dang+'</td><td>'

                for ll in c[k]:
                    link += (
                        "<a href='../ViewSource/?file=" + escape(ll) + "&md5=" + MD5 + "&type=" +
                        TYP + "'>" + escape(ntpath.basename(ll)) + "</a> "
                    )

                dang += hd+link+"</td></tr>"

        code_an_dic = {
            'api' : html,
            'dang' : dang,
            'urls' : URLnFile,
            'domains' : DOMAINS,
            'emails': EmailnFile,
            'crypto' : crypto,
            'obfus' : obfus,
            'reflect' : reflect,
            'dynamic' : dynamic,
            'native' : native
        }

        return code_an_dic
    except:
        PrintException("[ERROR] Performing Code Analysis")
