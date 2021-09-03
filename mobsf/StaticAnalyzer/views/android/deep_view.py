# -*- coding: utf_8 -*-
"""Module for manifest_view."""

import logging
import os
import re
from pathlib import Path
from xml.dom.minidom import parseString

import xml.dom.minidom,os
import subprocess,time,sys


from django.conf import settings
from django.shortcuts import render

from mobsf.MobSF.utils import print_n_send_error_response
from mobsf.StaticAnalyzer.views.android.manifest_analysis import (
    get_manifest_file,
)


logger = logging.getLogger(__name__)

dirdir=''
def run(request):
    """View the manifest."""
    try:
        directory = settings.BASE_DIR  # BASE DIR
        md5 = request.GET['md5']  # MD5
        typ = request.GET['type']  # APK or SOURCE
        binary = request.GET['bin']
        match = re.match('^[0-9a-f]{32}$', md5)
        if (match
            and (typ in ['eclipse', 'studio', 'apk'])
                and (binary in ['1', '0'])):
            app_dir = os.path.join(
                settings.UPLD_DIR, md5 + '/')  # APP DIRECTORY
            tools_dir = os.path.join(
                directory, 'StaticAnalyzer/tools/')  # TOOLS DIR
            if binary == '1':
                is_binary = True
            elif binary == '0':
                is_binary = False
            app_path = os.path.join(app_dir, md5 + '.apk')
            manifest_file = get_manifest_file(
                app_dir,
                app_path,
                tools_dir,
                typ,
                is_binary)
            mfile = Path(app_dir+"deeplink.txt")
            global dirdir
            dirdir=app_dir
            deeplink()
            if mfile.exists():
                deepfile = mfile.read_text('utf-8', 'ignore')
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
            return render(request, template, context)
    except Exception:
        logger.exception('Viewing AndroidManifest.xml')
        return print_n_send_error_response(request,
                                           'Error Viewing AndroidManifest.xml')



def strdomvalue(name):
    strdata = ''
    with open(dirdir+'apktool_out/res/values/strings.xml','r') as f:
        strdata = f.read()
    strdom = parseString(strdata)
    strings = (strdom.getElementsByTagName('string'))
    for lol in strings :
        for node in (lol.childNodes):
            if node.nodeType == node.TEXT_NODE:
                if("@string/"+str(lol.attributes["name"].value)==name):
                    return (node.data)


def deeplink():
    data = ''
    with open(dirdir+'apktool_out/AndroidManifest.xml','r') as f:
        data = f.read()
    a = [] 
    b= []
    c= []
    d= []
    e=[]
    i=0;
    f = open(dirdir+"deeplink.txt", "w")
    f.write("All Deeplinks Listed Below!")
    dom = parseString(data)
    activities = (dom.getElementsByTagName('activity')+dom.getElementsByTagName('activity-alias'))
    package = (dom.getElementsByTagName('manifest'))
    for lol in package:
        package_name= (lol.attributes["package"].value)

    for activity in activities:
        intentFilterTag = activity.getElementsByTagName("intent-filter")
        if len(intentFilterTag) > 0:
            f.write("\n------------------------------------"+activity.attributes["android:name"].value+"----------------------------------------------\n")
            for intent in intentFilterTag:
                dataTag = intent.getElementsByTagName("data")
                if len(dataTag) > 0:

                    #calladb(str(activity.attributes["android:name"].value),package_name)
                    for data in dataTag:
                        if (data.attributes.length==3 and data.hasAttribute("android:pathPrefix")) :
                            if "@string" in (str(data.attributes["android:scheme"].value)):
                                one=strdomvalue(str(data.attributes["android:scheme"].value))
                            else:
                                one=str(data.attributes["android:scheme"].value)
                            if "@string" in (str(data.attributes["android:host"].value)):
                                two=strdomvalue(str(data.attributes["android:host"].value))
                            else:
                                two=str(data.attributes["android:host"].value)
                            if "@string" in (str(data.attributes["android:pathPrefix"].value)):
                                three=strdomvalue(str(data.attributes["android:pathPrefix"].value))
                            else:
                                three=str(data.attributes["android:pathPrefix"].value)
                            f.write(one+"://"+two+three+"\n")
                            #callhttpdeep(str(one+"://"+two+three),package_name)
                            
                        if (data.attributes.length==3 and data.hasAttribute("android:pathPattern")) :
                            if "@string" in (str(data.attributes["android:scheme"].value)):
                                one=strdomvalue(str(data.attributes["android:scheme"].value))
                            else:
                                one=str(data.attributes["android:scheme"].value)
                            if "@string" in (str(data.attributes["android:host"].value)):
                                two=strdomvalue(str(data.attributes["android:host"].value))
                            else:
                                two=str(data.attributes["android:host"].value)
                            if "@string" in (str(data.attributes["android:pathPattern"].value)):
                                three=strdomvalue(str(data.attributes["android:pathPattern"].value))
                            else:
                                three=str(data.attributes["android:pathPattern"].value)
                            f.write(one+"://"+two+three+"\n")
                        if (data.attributes.length==3 and data.hasAttribute("android:path")) :
                            if "@string" in (str(data.attributes["android:scheme"].value)):
                                one=strdomvalue(str(data.attributes["android:scheme"].value))
                            else:
                                one=str(data.attributes["android:scheme"].value)
                            if "@string" in (str(data.attributes["android:host"].value)):
                                two=strdomvalue(str(data.attributes["android:host"].value))
                            else:
                                two=str(data.attributes["android:host"].value)
                            if "@string" in (str(data.attributes["android:path"].value)):
                                three=strdomvalue(str(data.attributes["android:path"].value))
                            else:
                                three=str(data.attributes["android:path"].value)
                            f.write(one+"://"+two+three+"\n")                       
                        if (data.attributes.length==2 and (data.hasAttribute("android:host")and data.hasAttribute("android:scheme"))) :
                            if "@string" in (str(data.attributes["android:scheme"].value)):
                                one=strdomvalue(str(data.attributes["android:scheme"].value))
                            else:
                                one=str(data.attributes["android:scheme"].value)
                            if "@string" in (str(data.attributes["android:host"].value)):
                                two=strdomvalue(str(data.attributes["android:host"].value))
                            else:
                                two=str(data.attributes["android:host"].value)
                            f.write(one+"://"+two+"\n")
                            #callhttpdeep(str(one+"://"+two),package_name)

                        if (data.attributes.length==1) :
                            if data.hasAttribute("android:host") :
                                b.append(str(data.attributes["android:host"].value))
                            if data.hasAttribute("android:scheme"):
                                c.append(str(data.attributes["android:scheme"].value))
                            if data.hasAttribute("android:pathPrefix"):
                                d.append(str(data.attributes["android:pathPrefix"].value))
                            if data.hasAttribute("android:pathPattern"):
                                d.append(str(data.attributes["android:pathPattern"].value))
                            if data.hasAttribute("android:path"):
                                d.append(str(data.attributes["android:path"].value))
                                
                            
                    
                for scheme in c:
                    if b==[]:
                        if "@string" in (str(scheme)):
                                f.write(strdomvalue(str(scheme))+"://")
                        else:
                                f.write(str(scheme)+"://")
                         

                    for host in b:      
                        if d==[]:
                            if "@string" in (scheme):
                                one=strdomvalue(scheme)
                            else:
                                one=str(scheme)
                            if "@string" in (str(host)):
                                two=strdomvalue(str(host))
                            else:
                                two=str(host)
                            f.write(one+"://"+two+"\n")
                        for path in d:
                            if "@string" in (str(scheme)):
                                one=strdomvalue(str(scheme))
                            else:
                                one=str(scheme)
                            if "@string" in (str(host)):
                                two=strdomvalue(str(host))
                            else:
                                two=str(host)
                            if "@string" in (path):
                                three=strdomvalue(str(path))
                            else:
                                three=str(path)
                            f.write(one+"://"+two+three+"\n")
                        
                        
                a=[]    
                b=[]                  
                c=[]




                  