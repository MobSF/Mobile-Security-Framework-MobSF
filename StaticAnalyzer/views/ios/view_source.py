# -*- coding: utf_8 -*-
"""
iOS View Source
"""
import re
import os
import io
import ntpath
import sqlite3

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.utils.html import escape
from django.conf import settings

import biplist

from MobSF.forms import (
    FormUtil
)

from StaticAnalyzer.forms import (
    ViewSourceIOSApiForm,
    ViewSourceIOSForm
)

from MobSF.utils import (
    print_n_send_error_response,
    PrintException,
    isFileExists
)

def set_ext_api(file_path):
    """
    Smart Function to set Extenstion
    """
    ext = file_path.split('.')[-1]
    if ext == "plist":
        return "xml"
    elif ext in ["sqlitedb", "db", "sqlite"]:
        return "db"
    elif ext == "m":
        return "m"
    else:
        return "txt"


def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]


def view_info_plist(md5):
    """
    """
    src = os.path.join(settings.UPLD_DIR,
                               md5 + '/Payload/')

    info_plist_path = ''
    dat = ''
    for root, dirs, files in walklevel(src, 1):
        for file in files:
            if file == "Info.plist":
                info_plist_path = os.path.join(root, "Info.plist")

    print(info_plist_path)
    if len(info_plist_path) == 0:
        context = {
            'title': 'Info.plist',
            'file': 'Info.plist',
            'dat': dat
        }
        return context

    dat = biplist.readPlist(info_plist_path)
    context = {
        'title': 'Info.plist',
        'file': 'Info.plist',
        'dat': dat
    }
    return context 


def run(request, api=False):
    """View iOS Files"""
    try:
        print("[INFO] View iOS Source File")
        file_format = "cpp"
        if api:
            fil = request.POST['file']
            md5_hash = request.POST['hash']
            mode = request.POST['type']
            viewsource_form = ViewSourceIOSApiForm(request.POST)
        else:
            fil = request.GET['file']
            md5_hash = request.GET['md5']
            mode = request.GET['type']
            viewsource_form = ViewSourceIOSForm(request.GET)
        typ = set_ext_api(fil)
        if not viewsource_form.is_valid():
            err = FormUtil.errors_message(viewsource_form)
            if api:
                return err
            context = {
                'title': 'Error',
                'exp': 'Error Description',
                'doc': err
            }
            template = "general/error.html"
            return render(request, template, context, status=400)
        if mode == 'ipa':
            src = os.path.join(settings.UPLD_DIR,
                               md5_hash + '/Payload/')
        elif mode == 'ios':
            src = os.path.join(settings.UPLD_DIR, md5_hash + '/')
        sfile = os.path.join(src, fil)
        dat = ''
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
            dat = read_sqlite(sfile)
        elif typ == 'txt' and fil == "classdump.txt":
            file_format = 'cpp'
            app_dir = os.path.join(settings.UPLD_DIR, md5_hash + '/')
            cls_dump_file = os.path.join(app_dir, "classdump.txt")
            if isFileExists(cls_dump_file):
                with io.open(cls_dump_file,
                             mode='r',
                             encoding="utf8",
                             errors="ignore"
                             ) as flip:
                    dat = flip.read()
            else:
                dat = "Class Dump result not Found"
        else:
            if api:
                return {"error": "Invalid Parameters"}
            return HttpResponseRedirect('/error/')
        context = {'title': escape(ntpath.basename(fil)),
                   'file': escape(ntpath.basename(fil)),
                   'type': file_format,
                   'dat': dat}
        template = "general/view.html"
        if api:
            return context
        return render(request, template, context)
    except Exception as exp:
        msg = str(exp)
        exp = exp.__doc__
        if api:
            return print_n_send_error_response(request, msg, True, exp)
        else:
            return print_n_send_error_response(request, msg, False, exp)


def read_sqlite(sqlite_file):
    """Read SQlite File"""
    try:
        print("[INFO] Dumping SQLITE Database")
        data = ''
        con = sqlite3.connect(sqlite_file)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cur.fetchall()
        for table in tables:
            data += "\nTABLE: " + str(table[0]).decode('utf8', 'ignore') + \
                " \n=====================================================\n"
            cur.execute("PRAGMA table_info('%s')" % table)
            rows = cur.fetchall()
            head = ''
            for row in rows:
                head += str(row[1]).decode('utf8', 'ignore') + " | "
            data += head + " \n========================================" +\
                "=============================\n"
            cur.execute("SELECT * FROM '%s'" % table)
            rows = cur.fetchall()
            for row in rows:
                dat = ''
                for item in row:
                    dat += str(item).decode('utf8', 'ignore') + " | "
                data += dat + "\n"
        return data
    except:
        PrintException("[ERROR] Dumping SQLITE Database")