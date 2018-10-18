# -*- coding: utf_8 -*-
"""View Source of a file."""

import io
import ntpath
import re
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect, HttpResponseBadRequest, JsonResponse
from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException,
    isFileExists
)
from StaticAnalyzer import views

# directory
SRC_DIRECTORY = '/src/'
JAVA_DIRECTORY = '/app/src/main/java/'
JAVA_SOURCE_DIRECTORY = '/java_source/'
SMALI_SOURCE_DIRECTORY = '/smali_source/'


class ViewSourceIos(object):
    """View iOS Files"""
    def __init__(self, request):
        self.request = request

    @classmethod
    def as_view(cls, request):
        """
        With url.py
        """
        return cls(request).to_html()

    def api(self):
        """
        For REST API
        """
        request = self.request
        fil = request.GET['file']
        typ = request.GET['type']
        md5_hash = request.GET['md5']
        mode = request.GET['mode']
        md5_match = re.match('^[0-9a-f]{32}$', md5_hash)
        ext = fil.split('.')[-1]
        ext_type = re.search("plist|db|sqlitedb|sqlite|txt|m", ext)
        if not md5_match or not ext_type or not re.findall('xml|db|txt|m', typ) or not re.findall('ios|ipa', mode):
            return HttpResponseBadRequest()
    
        if mode == 'ipa':
            src = os.path.join(settings.UPLD_DIR,
                            md5_hash + '/Payload/')
        elif mode == 'ios':
            src = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        sfile = os.path.join(src, fil)
        dat = ''
        file_format = 'txt'
        if typ == 'm':
            file_format = 'cpp'
            with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as flip:
                dat = flip.read()
        elif typ == 'xml':
            file_format = 'xml'
            with io.open(sfile, mode='r', encoding="utf8", errors="ignore") as flip:
                dat = flip.read()
        elif typ == 'db':
            file_format = 'asciidoc'
            dat = views.ios.static_analyzer.read_sqlite(sfile)
        elif typ == 'txt' and fil == "classdump.txt":
            file_format = 'cpp'
            app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
            cls_dump_file = os.path.join(app_dir, "classdump.txt")
            if isFileExists(cls_dump_file):
                with io.open(cls_dump_file, mode='r', encoding="utf8", errors="ignore") as flip:
                    dat = flip.read()
            else:
                dat = "Class Dump not Found"
        context = {'title': escape(ntpath.basename(fil)),
                'file': escape(ntpath.basename(fil)),
                'type': file_format,
                'dat': dat}
        return JsonResponse(context)


    def to_html(self):
        """
        For template
        TODO need 
        """
        return views.ios.static_analyzer.view_file(self.request)




class ViewSourceAndroid(object):
    """
    """
    def __init__(self, request):
        self.request = request

    @staticmethod
    def as_view(request):
        """View the source of a file."""
        view_source = ViewSourceAndroid(request)
        return view_source.to_html()


    def get_package_type(self, md5, package_type):
        if package_type == 'eclipse':
            src = os.path.join(settings.UPLD_DIR, md5 + SRC_DIRECTORY)
        elif package_type == 'studio':
            src = os.path.join(settings.UPLD_DIR, md5 + JAVA_DIRECTORY)
        elif package_type == 'apk':
            src = os.path.join(settings.UPLD_DIR, md5 + JAVA_SOURCE_DIRECTORY)
        else:
            src = ''
        return src

    def to_html(self):
        request = self.request
        try:
            fil = ''
            match = re.match('^[0-9a-f]{32}$', request.GET['md5'])
            if match and (
                    request.GET['file'].endswith('.java') or
                    request.GET['file'].endswith('.smali')
            ):
                fil = request.GET['file']
                md5 = request.GET['md5']
                if ("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil):
                    return HttpResponseRedirect('/error/')
                else:
                    if fil.endswith('.java'):
                        typ = request.GET['type']
                        if typ == 'eclipse':
                            src = os.path.join(settings.UPLD_DIR, md5+'/src/')
                        elif typ == 'studio':
                            src = os.path.join(settings.UPLD_DIR, md5+'/app/src/main/java/')
                        elif typ == 'apk':
                            src = os.path.join(settings.UPLD_DIR, md5+'/java_source/')
                        else:
                            return HttpResponseRedirect('/error/')
                    elif fil.endswith('.smali'):
                        src = os.path.join(settings.UPLD_DIR, md5+'/smali_source/')
                    sfile = os.path.join(src, fil)
                    dat = ''
                    with io.open(
                        sfile,
                        mode='r',
                        encoding="utf8",
                        errors="ignore"
                    ) as file_pointer:
                        dat = file_pointer.read()
            else:
                return HttpResponseRedirect('/error/')
            context = {
                'title': escape(ntpath.basename(fil)),
                'file': escape(ntpath.basename(fil)),
                'dat': dat
            }
            template = "static_analysis/view_source.html"
            return render(request, template, context)
        except:
            PrintException("[ERROR] Viewing Source")
            return HttpResponseRedirect('/error/')

    def api(self):
        """
        for rest api
        """
        request =self.request
        file_name = request.GET['file']
        md5 = request.GET['md5']
        package_type = request.GET['type']

        match = re.match('^[0-9a-f]{32}$', md5)
        is_endswith_java = file_name.endswith('.java')
        is_endswith_smali = file_name.endswith('.smali')

        is_not_match = not match or not (is_endswith_java or is_endswith_smali)
        if is_not_match:
            return HttpResponseBadRequest()

        if ("../" in file_name) or ("%2e%2e" in file_name) or (".." in file_name) or ("%252e" in file_name):
            return HttpResponseBadRequest()
        if is_endswith_java:
            src = self.get_package_type(md5, package_type)
        elif is_endswith_smali:
            src = os.path.join(settings.UPLD_DIR, md5 + SMALI_SOURCE_DIRECTORY)
            
        sfile = os.path.join(src, file_name)
        dat = ''
        with io.open(
            sfile,
            mode='r',
            encoding="utf8",
            errors="ignore"
        ) as file_pointer:
            dat = file_pointer.read()

        context = {
            'title': escape(ntpath.basename(file_name)),
            'file': escape(ntpath.basename(file_name)),
            'dat': dat
        }
        return JsonResponse(context)
