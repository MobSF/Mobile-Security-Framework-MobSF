# -*- coding: utf_8 -*-
"""Module for manifest_view."""

import logging
import os
import re
from pathlib import Path
from xml.dom.minidom import parseString


from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import print_n_send_error_response


logger = logging.getLogger(__name__)

dirdir = ''


def run(request):
    """View the manifest."""
    try:
        md5 = request.GET['md5']  # MD5
        typ = request.GET['type']  # APK or SOURCE
        binary = request.GET['bin']
        match = re.match('^[0-9a-f]{32}$', md5)
        if (match
            and (typ in ['eclipse', 'studio', 'apk'])
                and (binary in ['1', '0'])):
            app_dir = os.path.join(
                settings.UPLD_DIR, md5 + '/')  # APP DIRECTORY
            mfile = Path(app_dir + 'deeplink.txt')
            global dirdir
            dirdir = app_dir
            deeplink()
            if mfile.exists():
                deepfile = mfile.read_text(
                    'utf-8', 'ignore')
            else:
                deepfile = ''
            context = {
                'title': 'Deeplinks',
                'file': 'Deeplinks',
                'data': deepfile,
                'type': 'html',
                'sqlite': {},
                'version': settings.MOBSF_VER,
            }
            template = 'general/view.html'
            return render(
                request, template, context)
    except Exception:
        logger.exception(
            'Viewing AndroidManifest.xml')
        return print_n_send_error_response(request,
                                           'Error Viewing AndroidManifest.xml')


def strdomvalue(name):
    strdata = ''
    with open(dirdir + 'apktool_out/res/values/strings.xml', 'r') as f:
        strdata = f.read()
    strdom = parseString(strdata)
    strings = (
        strdom.getElementsByTagName('string'))
    for lol in strings:
        for node in (lol.childNodes):
            if node.nodeType == node.TEXT_NODE:
                if('@string/' + str(lol.attributes['name'].value) == name):
                    return (node.data)


def deeplink():
    data = ''
    with open(dirdir + 'apktool_out/AndroidManifest.xml', 'r') as f:
        data = f.read()
    b = []
    c = []
    d = []
    pf = 'android:pathPrefix'
    sc = 'android:scheme'
    ht = 'android:host'
    pp = 'android:pathPattern'
    ap = 'android:path'
    f = open(dirdir + 'deeplink.txt', 'w')
    f.write('All Deeplinks Listed Below!')
    dom = parseString(data)
    activities = (dom.getElementsByTagName('activity')
                  + dom.getElementsByTagName('activity-alias'))

    for activity in activities:
        intentfiltertag = activity.getElementsByTagName(
            'intent-filter')
        if len(intentfiltertag) > 0:
            f.write('\n------------------------------------'
                    + activity.attributes['android:name'].value
                    + '----------------------------------------------\n')
            for intent in intentfiltertag:
                datatag = intent.getElementsByTagName(
                    'data')
                if len(datatag) > 0:
                    for data in datatag:
                        if (data.attributes.length == 3
                                and data.hasAttribute(pf)):
                            if '@string' in (
                                    str(data.attributes[sc].value)):
                                one = strdomvalue(
                                    str(data.attributes[sc].value))
                            else:
                                one = str(
                                    data.attributes[sc].value)
                            if '@string' in (
                                    str(data.attributes[ht].value)):
                                two = strdomvalue(
                                    str(data.attributes[ht].value))
                            else:
                                two = str(
                                    data.attributes[ht].value)
                            if '@string' in (
                                    str(data.attributes[pf].value)):
                                three = strdomvalue(
                                    str(data.attributes[pf].value))
                            else:
                                three = str(
                                    data.attributes[pf].value)
                            result = one + '://' + two + three + '\n'
                            f.write(result)

                        if (data.attributes.length == 3
                                and data.hasAttribute(pp)):
                            if '@string' in (
                                    str(data.attributes[sc].value)):
                                one = strdomvalue(
                                    str(data.attributes[sc].value))
                            else:
                                one = str(
                                    data.attributes[sc].value)
                            if '@string' in (
                                    str(data.attributes[ht].value)):
                                two = strdomvalue(
                                    str(data.attributes[ht].value))
                            else:
                                two = str(
                                    data.attributes[ht].value)
                            if '@string' in (
                                    str(data.attributes[pp].value)):
                                three = strdomvalue(
                                    str(data.attributes[pp].value))
                            else:
                                three = str(
                                    data.attributes[pp].value)
                            result = one + '://' + two + three + '\n'
                            f.write(result)

                        if (data.attributes.length == 3
                                and data.hasAttribute(ap)):
                            if '@string' in (
                                    str(data.attributes[sc].value)):
                                one = strdomvalue(
                                    str(data.attributes[sc].value))
                            else:
                                one = str(
                                    data.attributes[sc].value)
                            if '@string' in (
                                    str(data.attributes[ht].value)):
                                two = strdomvalue(
                                    str(data.attributes[ht].value))
                            else:
                                two = str(
                                    data.attributes[ht].value)
                            if '@string' in (
                                    str(data.attributes[ap].value)):
                                three = strdomvalue(
                                    str(data.attributes[ap].value))
                            else:
                                three = str(
                                    data.attributes[ap].value)
                            result = one + '://' + two + three + '\n'
                            f.write(result)

                        if (data.attributes.length == 2
                            and (data.hasAttribute(ht)
                                 and data.hasAttribute(sc))):
                            if '@string' in (
                                    str(data.attributes[sc].value)):
                                one = strdomvalue(
                                    str(data.attributes[sc].value))
                            else:
                                one = str(
                                    data.attributes[sc].value)
                            if '@string' in (
                                    str(data.attributes[ht].value)):
                                two = strdomvalue(
                                    str(data.attributes[ht].value))
                            else:
                                two = str(
                                    data.attributes[ht].value)
                            result = one + '://' + two + '\n'
                            f.write(result)

                        if (data.attributes.length == 1):
                            if data.hasAttribute(
                                    ht):
                                b.append(
                                    str(data.attributes[ht].value))
                            if data.hasAttribute(
                                    sc):
                                c.append(
                                    str(data.attributes[sc].value))
                            if data.hasAttribute(
                                    pf):
                                d.append(
                                    str(data.attributes[pf].value))
                            if data.hasAttribute(
                                    pp):
                                d.append(
                                    str(data.attributes[pp].value))
                            if data.hasAttribute(
                                    ap):
                                d.append(
                                    str(data.attributes[ap].value))

                for scheme in c:
                    if b == []:
                        if '@string' in (str(scheme)):
                            f.write(
                                strdomvalue(
                                    str(scheme)) + '://')
                        else:
                            f.write(
                                str(scheme) + '://')

                    for host in b:
                        if d == []:
                            if '@string' in (scheme):
                                one = strdomvalue(
                                    scheme)
                            else:
                                one = str(scheme)
                            if '@string' in (str(host)):
                                two = strdomvalue(
                                    str(host))
                            else:
                                two = str(host)
                            f.write(
                                one + '://' + two + '\n')
                        for path in d:
                            if '@string' in (str(scheme)):
                                one = strdomvalue(
                                    str(scheme))
                            else:
                                one = str(scheme)
                            if '@string' in (str(host)):
                                two = strdomvalue(
                                    str(host))
                            else:
                                two = str(host)
                            if '@string' in (path):
                                three = strdomvalue(
                                    str(path))
                            else:
                                three = str(path)
                            f.write(
                                one + '://' + two + three + '\n')

                b = []
                c = []
    f.write(
        '\n\n\nRefer:- https://github.com/Shapa7276/Android-Deeplink-Parser')
