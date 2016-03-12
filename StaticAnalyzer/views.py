# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.http import HttpResponse
from django.template.loader import get_template
from StaticAnalyzer.models import StaticAnalyzerAndroid,StaticAnalyzerIPA,StaticAnalyzerIOSZIP
from django.conf import settings
from django.utils.html import escape
from MobSF.exception_printer import PrintException
from xml.dom import minidom
from .dvm_permissions import DVM_PERMISSIONS
import sqlite3 as sq
import io,re,os,glob,hashlib, zipfile, subprocess,ntpath,shutil,platform,ast,sys,plistlib
try:
    import xhtml2pdf.pisa as pisa
except:
    PrintException("[ERROR] xhtml2pdf is not installed. Cannot generate PDF reports")
try:
    import StringIO
    StringIO = StringIO.StringIO
except Exception:
    from io import StringIO

def PDF(request):
    try:
        MD5=request.GET['md5']
        TYP=request.GET['type']
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            if (TYP=='APK' or TYP=='ANDZIP'):
                DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists():
                    print "\n[INFO] Fetching data from DB for PDF Report Generation (Android)"
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
                    'native' : DB[0].NATIVE,
                    'dynamic' : DB[0].DYNAMIC,
                    'reflection' : DB[0].REFLECT,
                    'crypto': DB[0].CRYPTO,
                    'obfus': DB[0].OBFUS,
                    'api': DB[0].API,
                    'dang': DB[0].DANG,
                    'urls': DB[0].URLS,
                    'emails': DB[0].EMAILS,
                    'strings': python_list(DB[0].STRINGS),
                    'zipped' : DB[0].ZIPPED,
                    'mani': DB[0].MANI
                    }
                    if TYP=='APK':
                        template= get_template("static_analysis_pdf.html")
                    else:
                        template= get_template("static_analysis_zip_pdf.html")
            elif re.findall('IPA|IOSZIP',TYP):
                if TYP=='IPA':
                    DB=StaticAnalyzerIPA.objects.filter(MD5=MD5)
                    if DB.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (IOS IPA)"
                        context = {
                        'title' : DB[0].TITLE,
                        'name' : DB[0].APPNAMEX,
                        'size' : DB[0].SIZE,
                        'md5': DB[0].MD5,
                        'sha1' : DB[0].SHA1,
                        'sha256' : DB[0].SHA256,
                        'plist' : DB[0].INFOPLIST,
                        'bin_name' : DB[0].BINNAME,
                        'id' : DB[0].IDF,
                        'ver' : DB[0].VERSION,
                        'sdk' : DB[0].SDK,
                        'pltfm' : DB[0].PLTFM,
                        'min' : DB[0].MINX,
                        'bin_anal' : DB[0].BIN_ANAL,
                        'libs' : DB[0].LIBS,
                        'files' : python_list(DB[0].FILES),
                        'file_analysis' : DB[0].SFILESX,
                        }
                        template= get_template("ios_binary_analysis_pdf.html")
                elif TYP=='IOSZIP':
                    DB=StaticAnalyzerIOSZIP.objects.filter(MD5=MD5)
                    if DB.exists():
                        print "\n[INFO] Fetching data from DB for PDF Report Generation (IOS ZIP)"
                        context = {
                        'title' : DB[0].TITLE,
                        'name' : DB[0].APPNAMEX,
                        'size' : DB[0].SIZE,
                        'md5': DB[0].MD5,
                        'sha1' : DB[0].SHA1,
                        'sha256' : DB[0].SHA256,
                        'plist' : DB[0].INFOPLIST,
                        'bin_name' : DB[0].BINNAME,
                        'id' : DB[0].IDF,
                        'ver' : DB[0].VERSION,
                        'sdk' : DB[0].SDK,
                        'pltfm' : DB[0].PLTFM,
                        'min' : DB[0].MINX,
                        'bin_anal' : DB[0].BIN_ANAL,
                        'libs' : DB[0].LIBS,
                        'files' : python_list(DB[0].FILES),
                        'file_analysis' : DB[0].SFILESX,
                        'api' : DB[0].HTML,
                        'insecure' : DB[0].CODEANAL,
                        'urls' : DB[0].URLnFile,
                        'emails' : DB[0].EmailnFile
                        }
                        template= get_template("ios_source_analysis_pdf.html")
            else:
                return HttpResponseRedirect('/error/') 
            html  = template.render(context)
            result = StringIO()
            pdf = pisa.pisaDocument(StringIO( "{0}".format(html.encode('utf-8'))), result)
            if not pdf.err:
                return HttpResponse(result.getvalue(), content_type='application/pdf')
            else:
                return HttpResponseRedirect('/error/') 
        else:
            return HttpResponseRedirect('/error/') 
    except:
        
        PrintException("[ERROR] PDF Report Generation Error")
        return HttpResponseRedirect('/error/') 
        pass
def Java(request):
    try:
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        typ=request.GET['type']
        if m:
            MD5=request.GET['md5']
            if typ=='eclipse':
                SRC=os.path.join(settings.UPLD_DIR, MD5+'/src/')
                t=typ
            elif typ=='studio':
                SRC=os.path.join(settings.UPLD_DIR, MD5+'/app/src/main/java/')
                t=typ
            elif typ=='apk':
                SRC=os.path.join(settings.UPLD_DIR, MD5+'/java_source/')
                t=typ
            else:
                return HttpResponseRedirect('/error/')
            html=''
            for dirName, subDir, files in os.walk(SRC):
                for jfile in files:
                    if jfile.endswith(".java"):
                        file_path=os.path.join(SRC,dirName,jfile)
                        if "+" in jfile:
                            fp2=os.path.join(SRC,dirName,jfile.replace("+","x"))
                            shutil.move(file_path,fp2)
                            file_path=fp2
                        fileparam=file_path.replace(SRC,'')
                        html+="<tr><td><a href='../ViewSource/?file="+escape(fileparam)+"&md5="+MD5+"&type="+t+"'>"+escape(fileparam)+"</a></td></tr>"
        context = {'title': 'Java Source',
                    'files': html,
                    'md5': MD5,
                    'type': typ,
                    }
        template="java.html"
        return render(request,template,context)
    except:
        PrintException("[ERROR] Getting Java Files")
        return HttpResponseRedirect('/error/')
def Smali(request):
    try:
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m:
            MD5=request.GET['md5']
            SRC=os.path.join(settings.UPLD_DIR, MD5+'/smali_source/')
            html=''
            for dirName, subDir, files in os.walk(SRC):
                for jfile in files:
                    if jfile.endswith(".smali"):
                        file_path=os.path.join(SRC,dirName,jfile)
                        if "+" in jfile:
                            fp2=os.path.join(SRC,dirName,jfile.replace("+","x"))
                            shutil.move(file_path,fp2)
                            file_path=fp2
                        fileparam=file_path.replace(SRC,'')
                        html+="<tr><td><a href='../ViewSource/?file="+escape(fileparam)+"&md5="+MD5+"'>"+escape(fileparam)+"</a></td></tr>"
        context = {'title': 'Smali Source',
                    'files': html,
                    'md5': MD5,
                    }
        template="smali.html"
        return render(request,template,context)
    except:
        PrintException("[ERROR] Getting Smali Files")
        return HttpResponseRedirect('/error/')
def Find(request):
    try:
        m=re.match('[0-9a-f]{32}',request.POST['md5'])
        if m:
            MD5=request.POST['md5']
            q=request.POST['q']
            code=request.POST['code']
            matches=[]
            if code=='java':
                SRC=os.path.join(settings.UPLD_DIR, MD5+'/java_source/')
                ext='.java'
            elif code=='smali':
                SRC=os.path.join(settings.UPLD_DIR, MD5+'/smali_source/')
                ext='.smali'
            else:
                return HttpResponseRedirect('/error/')
            for dirName, subDir, files in os.walk(SRC):
                for jfile in files:
                    if jfile.endswith(ext):
                        file_path=os.path.join(SRC,dirName,jfile)
                        if "+" in jfile:
                            fp2=os.path.join(SRC,dirName,jfile.replace("+","x"))
                            shutil.move(file_path,fp2)
                            file_path=fp2
                        fileparam=file_path.replace(SRC,'')
                        with io.open(file_path,mode='r',encoding="utf8",errors="ignore") as f:
                            dat=f.read()
                        if q in dat:
                            matches.append("<a href='../ViewSource/?file="+escape(fileparam)+"&md5="+MD5+"&type=apk'>"+escape(fileparam)+"</a>")
        flz=len(matches)   
        context = {'title': 'Search Results',
        'matches': matches,
        'term': q,
        'found' : str(flz),
        }
        template="search.html"
        return render(request,template,context)
    except:
        PrintException("[ERROR] Searching Failed")
        return HttpResponseRedirect('/error/')     
def ViewSource(request):
    try:
        fil=''
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m and (request.GET['file'].endswith('.java') or request.GET['file'].endswith('.smali')):
            fil=request.GET['file']
            MD5=request.GET['md5']
            if (("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil)):
                return HttpResponseRedirect('/error/')
            else:
                if fil.endswith('.java'):
                    typ=request.GET['type']
                    if typ=='eclipse':
                        SRC=os.path.join(settings.UPLD_DIR, MD5+'/src/')
                    elif typ=='studio':
                        SRC=os.path.join(settings.UPLD_DIR, MD5+'/app/src/main/java/')
                    elif typ=='apk':
                        SRC=os.path.join(settings.UPLD_DIR, MD5+'/java_source/')
                    else:
                        return HttpResponseRedirect('/error/')
                elif fil.endswith('.smali'):
                    SRC=os.path.join(settings.UPLD_DIR, MD5+'/smali_source/')
                sfile=os.path.join(SRC,fil)
                dat=''
                with io.open(sfile, mode='r',encoding="utf8",errors="ignore") as f:
                    dat=f.read()
        else:
            return HttpResponseRedirect('/error/')
        context = {'title': escape(ntpath.basename(fil)),
                   'file': escape(ntpath.basename(fil)),
                   'dat': dat}
        template="view_source.html"
        return render(request,template,context)
    except:
        PrintException("[ERROR] Viewing Source")
        return HttpResponseRedirect('/error/')
def ManifestView(request):
    try:
        DIR=settings.BASE_DIR   #BASE DIR
        MD5=request.GET['md5']  #MD5
        TYP=request.GET['type'] #APK or SOURCE
        BIN=request.GET['bin']
        m=re.match('[0-9a-f]{32}',MD5)
        if m and (TYP=='eclipse' or TYP=='studio' or TYP=='apk') and (BIN=='1' or BIN=='0'):
            APP_DIR=os.path.join(settings.UPLD_DIR, MD5+'/') #APP DIRECTORY
            TOOLS_DIR=os.path.join(DIR, 'StaticAnalyzer/tools/')  #TOOLS DIR
            if BIN=='1':
                x=True
            elif BIN=='0':
                x=False
            MANI=ReadManifest(APP_DIR,TOOLS_DIR,TYP,x)
            context = {'title': 'AndroidManifest.xml',
                        'file': 'AndroidManifest.xml',
                        'dat': MANI}
            template="view_mani.html"
            return render(request,template,context)
    except:
        PrintException("[ERROR] Viewing AndroidManifest.xml")
        return HttpResponseRedirect('/error/')

def python_list(value):
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)

def StaticAnalyzer(request):
    try:
        #Input validation
        TYP=request.GET['type']
        m=re.match('[0-9a-f]{32}',request.GET['checksum'])
        if ((m) and (request.GET['name'].endswith('.apk') or request.GET['name'].endswith('.zip')) and ((TYP=='zip') or (TYP=='apk'))):
            DIR=settings.BASE_DIR        #BASE DIR
            APP_NAME=request.GET['name'] #APP ORGINAL NAME
            MD5=request.GET['checksum']  #MD5
            APP_DIR=os.path.join(settings.UPLD_DIR, MD5+'/') #APP DIRECTORY
            TOOLS_DIR=os.path.join(DIR, 'StaticAnalyzer/tools/')  #TOOLS DIR
            print "[INFO] Starting Analysis on : "+APP_NAME
            RESCAN= str(request.GET.get('rescan', 0))
            if TYP=='apk':
                #Check if in DB
                DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN=='0':
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
                    'native' : DB[0].NATIVE,
                    'dynamic' : DB[0].DYNAMIC,
                    'reflection' : DB[0].REFLECT,
                    'crypto': DB[0].CRYPTO,
                    'obfus': DB[0].OBFUS,
                    'api': DB[0].API,
                    'dang': DB[0].DANG,
                    'urls': DB[0].URLS,
                    'emails': DB[0].EMAILS,
                    'strings': python_list(DB[0].STRINGS),
                    'zipped' : DB[0].ZIPPED,
                    'mani': DB[0].MANI,
                    'e_act': DB[0].E_ACT,
                    'e_ser': DB[0].E_SER,
                    'e_bro': DB[0].E_BRO,
                    'e_cnt': DB[0].E_CNT,
                    }
                else:
                    APP_FILE=MD5 + '.apk'        #NEW FILENAME
                    APP_PATH=APP_DIR+APP_FILE    #APP PATH
                    #ANALYSIS BEGINS
                    SIZE=str(FileSize(APP_PATH)) + 'MB'   #FILE SIZE
                    SHA1, SHA256= HashGen(APP_PATH)       #SHA1 & SHA256 HASHES
        
                    FILES=Unzip(APP_PATH,APP_DIR)
                    CERTZ = GetHardcodedCert(FILES)
                    print "[INFO] APK Extracted"
                    PARSEDXML= GetManifest(APP_DIR,TOOLS_DIR,'',True) #Manifest XML
                    MANI='../ManifestView/?md5='+MD5+'&type=apk&bin=1'
                    SERVICES,ACTIVITIES,RECEIVERS,PROVIDERS,LIBRARIES,PERM,PACKAGENAME,MAINACTIVITY,MIN_SDK,MAX_SDK,TARGET_SDK,ANDROVER,ANDROVERNAME=ManifestData(PARSEDXML,APP_DIR)
                    MANIFEST_ANAL,EXPORTED_ACT,EXPORTED_CNT=ManifestAnalysis(PARSEDXML,MAINACTIVITY)
                    PERMISSIONS=FormatPermissions(PERM)
                    CNT_ACT =len(ACTIVITIES)
                    CNT_PRO =len(PROVIDERS)
                    CNT_SER =len(SERVICES)
                    CNT_BRO = len(RECEIVERS)
        
                    CERT_INFO=CertInfo(APP_DIR,TOOLS_DIR)
                    Dex2Jar(APP_DIR,TOOLS_DIR)
                    Dex2Smali(APP_DIR,TOOLS_DIR)
                    Jar2Java(APP_DIR,TOOLS_DIR)
        
                    API,DANG,URLS,EMAILS,CRYPTO,OBFUS,REFLECT,DYNAMIC,NATIVE=CodeAnalysis(APP_DIR,MD5,PERMISSIONS,"apk")
                    print "\n[INFO] Generating Java and Smali Downloads"
                    GenDownloads(APP_DIR,MD5)
                    STRINGS=Strings(APP_FILE,APP_DIR,TOOLS_DIR)
                    ZIPPED='&type=apk'
    
                    print "\n[INFO] Connecting to Database"
                    try:
                        #SAVE TO DB
                        if RESCAN=='1':
                            print "\n[INFO] Updating Database..."
                            StaticAnalyzerAndroid.objects.filter(MD5=MD5).update(TITLE = 'Static Analysis',
                            APP_NAME = APP_NAME,
                            SIZE = SIZE,
                            MD5= MD5,
                            SHA1 = SHA1,
                            SHA256 = SHA256,
                            PACKAGENAME = PACKAGENAME,
                            MAINACTIVITY= MAINACTIVITY,
                            TARGET_SDK = TARGET_SDK,
                            MAX_SDK = MAX_SDK,
                            MIN_SDK = MIN_SDK,
                            ANDROVERNAME = ANDROVERNAME,
                            ANDROVER= ANDROVER,
                            MANIFEST_ANAL= MANIFEST_ANAL,
                            PERMISSIONS = PERMISSIONS,
                            FILES = FILES,
                            CERTZ = CERTZ,
                            ACTIVITIES = ACTIVITIES,
                            RECEIVERS = RECEIVERS,
                            PROVIDERS = PROVIDERS,
                            SERVICES = SERVICES,
                            LIBRARIES = LIBRARIES,
                            CNT_ACT = CNT_ACT,
                            CNT_PRO = CNT_PRO,
                            CNT_SER = CNT_SER,
                            CNT_BRO = CNT_BRO,
                            CERT_INFO= CERT_INFO,
                            NATIVE = NATIVE,
                            DYNAMIC = DYNAMIC,
                            REFLECT = REFLECT,
                            CRYPTO= CRYPTO,
                            OBFUS= OBFUS,
                            API= API,
                            DANG= DANG,
                            URLS= URLS,
                            EMAILS= EMAILS,
                            STRINGS= STRINGS,
                            ZIPPED= ZIPPED,
                            MANI= MANI,
                            EXPORTED_ACT=EXPORTED_ACT,
                            E_ACT=EXPORTED_CNT["act"],
                            E_SER=EXPORTED_CNT["ser"],
                            E_BRO=EXPORTED_CNT["bro"],
                            E_CNT=EXPORTED_CNT["cnt"])
                        elif RESCAN=='0':
                            print "\n[INFO] Saving to Database"
                            STATIC_DB=StaticAnalyzerAndroid(TITLE = 'Static Analysis',
                            APP_NAME = APP_NAME,
                            SIZE = SIZE,
                            MD5= MD5,
                            SHA1 = SHA1,
                            SHA256 = SHA256,
                            PACKAGENAME = PACKAGENAME,
                            MAINACTIVITY= MAINACTIVITY,
                            TARGET_SDK = TARGET_SDK,
                            MAX_SDK = MAX_SDK,
                            MIN_SDK = MIN_SDK,
                            ANDROVERNAME = ANDROVERNAME,
                            ANDROVER= ANDROVER,
                            MANIFEST_ANAL= MANIFEST_ANAL,
                            PERMISSIONS = PERMISSIONS,
                            FILES = FILES,
                            CERTZ = CERTZ,
                            ACTIVITIES = ACTIVITIES,
                            RECEIVERS = RECEIVERS,
                            PROVIDERS = PROVIDERS,
                            SERVICES = SERVICES,
                            LIBRARIES = LIBRARIES,
                            CNT_ACT = CNT_ACT,
                            CNT_PRO = CNT_PRO,
                            CNT_SER = CNT_SER,
                            CNT_BRO = CNT_BRO,
                            CERT_INFO= CERT_INFO,
                            NATIVE = NATIVE,
                            DYNAMIC = DYNAMIC,
                            REFLECT = REFLECT,
                            CRYPTO= CRYPTO,
                            OBFUS= OBFUS,
                            API= API,
                            DANG= DANG,
                            URLS= URLS,
                            EMAILS= EMAILS,
                            STRINGS= STRINGS,
                            ZIPPED= ZIPPED,
                            MANI= MANI,
                            EXPORTED_ACT=EXPORTED_ACT,
                            E_ACT=EXPORTED_CNT["act"],
                            E_SER=EXPORTED_CNT["ser"],
                            E_BRO=EXPORTED_CNT["bro"],
                            E_CNT=EXPORTED_CNT["cnt"])
                            STATIC_DB.save()
                    except:
                        PrintException("[ERROR] Saving to Database Failed")
                        pass
                    context = {
                    'title' : 'Static Analysis',
                    'name' : APP_NAME,
                    'size' : SIZE,
                    'md5': MD5,
                    'sha1' : SHA1,
                    'sha256' : SHA256,
                    'packagename' : PACKAGENAME,
                    'mainactivity' : MAINACTIVITY,
                    'targetsdk' : TARGET_SDK,
                    'maxsdk' : MAX_SDK,
                    'minsdk' : MIN_SDK,
                    'androvername' : ANDROVERNAME,
                    'androver': ANDROVER,
                    'manifest': MANIFEST_ANAL,
                    'permissions' : PERMISSIONS,
                    'files' : FILES,
                    'certz' : CERTZ,
                    'activities' : ACTIVITIES,
                    'receivers' : RECEIVERS,
                    'providers' : PROVIDERS,
                    'services' : SERVICES,
                    'libraries' : LIBRARIES,
                    'act_count' : CNT_ACT,
                    'prov_count' : CNT_PRO,
                    'serv_count' : CNT_SER,
                    'bro_count' : CNT_BRO,
                    'certinfo': CERT_INFO,
                    'native' : NATIVE,
                    'dynamic' : DYNAMIC,
                    'reflection' : REFLECT,
                    'crypto': CRYPTO,
                    'obfus': OBFUS,
                    'api': API,
                    'dang': DANG,
                    'urls': URLS,
                    'emails': EMAILS,
                    'strings': STRINGS,
                    'zipped' : ZIPPED,
                    'mani': MANI,
                    'e_act': EXPORTED_CNT["act"],
                    'e_ser': EXPORTED_CNT["ser"],
                    'e_bro': EXPORTED_CNT["bro"],
                    'e_cnt': EXPORTED_CNT["cnt"], 
                    }
                template="static_analysis.html"
                return render(request,template,context)
            elif TYP=='zip':
                #Check if in DB
                DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN=='0':
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
                    'emails': DB[0].EMAILS,
                    'mani': DB[0].MANI,
                    'e_act': DB[0].E_ACT,
                    'e_ser': DB[0].E_SER,
                    'e_bro': DB[0].E_BRO,
                    'e_cnt': DB[0].E_CNT,
                    }
                else:
                    APP_FILE=MD5 + '.zip'        #NEW FILENAME
                    APP_PATH=APP_DIR+APP_FILE    #APP PATH
                    print "[INFO] Extracting ZIP"
                    FILES = Unzip(APP_PATH,APP_DIR)
                    CERTZ = GetHardcodedCert(FILES)
                    #Check if Valid Directory Structure and get ZIP Type
                    pro_type,Valid=ValidAndroidZip(APP_DIR)
                    print "[INFO] ZIP Type - " + pro_type
                    if Valid and (pro_type=='eclipse' or pro_type=='studio'):
                        #ANALYSIS BEGINS
                        SIZE=str(FileSize(APP_PATH)) + 'MB'   #FILE SIZE
                        SHA1,SHA256= HashGen(APP_PATH)        #SHA1 & SHA256 HASHES
                        PARSEDXML= GetManifest(APP_DIR,TOOLS_DIR,pro_type,False)   #Manifest XML
                        MANI='../ManifestView/?md5='+MD5+'&type='+pro_type+'&bin=0'
                        SERVICES,ACTIVITIES,RECEIVERS,PROVIDERS,LIBRARIES,PERM,PACKAGENAME,MAINACTIVITY,MIN_SDK,MAX_SDK,TARGET_SDK,ANDROVER,ANDROVERNAME=ManifestData(PARSEDXML,APP_DIR)
                        MANIFEST_ANAL,EXPORTED_ACT,EXPORTED_CNT=ManifestAnalysis(PARSEDXML,MAINACTIVITY)
                        PERMISSIONS=FormatPermissions(PERM)
                        CNT_ACT =len(ACTIVITIES)
                        CNT_PRO =len(PROVIDERS)
                        CNT_SER =len(SERVICES)
                        CNT_BRO = len(RECEIVERS)
                        API,DANG,URLS,EMAILS,CRYPTO,OBFUS,REFLECT,DYNAMIC,NATIVE=CodeAnalysis(APP_DIR,MD5,PERMISSIONS,pro_type)
                        print "\n[INFO] Connecting to Database"
                        try:
                            #SAVE TO DB
                            if RESCAN=='1':
                                print "\n[INFO] Updating Database..."
                                StaticAnalyzerAndroid.objects.filter(MD5=MD5).update(TITLE = 'Static Analysis',
                                APP_NAME = APP_NAME,
                                SIZE = SIZE,
                                MD5= MD5,
                                SHA1 = SHA1,
                                SHA256 = SHA256,
                                PACKAGENAME = PACKAGENAME,
                                MAINACTIVITY= MAINACTIVITY,
                                TARGET_SDK = TARGET_SDK,
                                MAX_SDK = MAX_SDK,
                                MIN_SDK = MIN_SDK,
                                ANDROVERNAME = ANDROVERNAME,
                                ANDROVER= ANDROVER,
                                MANIFEST_ANAL= MANIFEST_ANAL,
                                PERMISSIONS = PERMISSIONS,
                                FILES = FILES,
                                CERTZ = CERTZ,
                                ACTIVITIES = ACTIVITIES,
                                RECEIVERS = RECEIVERS,
                                PROVIDERS = PROVIDERS,
                                SERVICES = SERVICES,
                                LIBRARIES = LIBRARIES,
                                CNT_ACT = CNT_ACT,
                                CNT_PRO = CNT_PRO,
                                CNT_SER = CNT_SER,
                                CNT_BRO = CNT_BRO,
                                CERT_INFO= "",
                                NATIVE = NATIVE,
                                DYNAMIC = DYNAMIC,
                                REFLECT = REFLECT,
                                CRYPTO= CRYPTO,
                                OBFUS= OBFUS,
                                API= API,
                                DANG= DANG,
                                URLS= URLS,
                                EMAILS= EMAILS,
                                STRINGS= "",
                                ZIPPED= "",
                                MANI= MANI,
                                EXPORTED_ACT=EXPORTED_ACT,
                                E_ACT=EXPORTED_CNT["act"],
                                E_SER=EXPORTED_CNT["ser"],
                                E_BRO=EXPORTED_CNT["bro"],
                                E_CNT=EXPORTED_CNT["cnt"])
                            elif RESCAN=='0':
                                print "\n[INFO] Saving to Database"
                                STATIC_DB=StaticAnalyzerAndroid(TITLE = 'Static Analysis',
                                APP_NAME = APP_NAME,
                                SIZE = SIZE,
                                MD5= MD5,
                                SHA1 = SHA1,
                                SHA256 = SHA256,
                                PACKAGENAME = PACKAGENAME,
                                MAINACTIVITY= MAINACTIVITY,
                                TARGET_SDK = TARGET_SDK,
                                MAX_SDK = MAX_SDK,
                                MIN_SDK = MIN_SDK,
                                ANDROVERNAME = ANDROVERNAME,
                                ANDROVER= ANDROVER,
                                MANIFEST_ANAL= MANIFEST_ANAL,
                                PERMISSIONS = PERMISSIONS,
                                FILES = FILES,
                                CERTZ = CERTZ,
                                ACTIVITIES = ACTIVITIES,
                                RECEIVERS = RECEIVERS,
                                PROVIDERS = PROVIDERS,
                                SERVICES = SERVICES,
                                LIBRARIES = LIBRARIES,
                                CNT_ACT = CNT_ACT,
                                CNT_PRO = CNT_PRO,
                                CNT_SER = CNT_SER,
                                CNT_BRO = CNT_BRO,
                                CERT_INFO= "",
                                NATIVE = NATIVE,
                                DYNAMIC = DYNAMIC,
                                REFLECT = REFLECT,
                                CRYPTO= CRYPTO,
                                OBFUS= OBFUS,
                                API= API,
                                DANG= DANG,
                                URLS= URLS,
                                EMAILS= EMAILS,
                                STRINGS= "",
                                ZIPPED= "",
                                MANI= MANI,
                                EXPORTED_ACT=EXPORTED_ACT,
                                E_ACT=EXPORTED_CNT["act"],
                                E_SER=EXPORTED_CNT["ser"],
                                E_BRO=EXPORTED_CNT["bro"],
                                E_CNT=EXPORTED_CNT["cnt"])
                                STATIC_DB.save()
                        except:
                            PrintException("[ERROR] Saving to Database Failed")
                            pass
                        context = {
                        'title' : 'Static Analysis',
                        'name' : APP_NAME,
                        'size' : SIZE,
                        'md5': MD5,
                        'sha1' : SHA1,
                        'sha256' : SHA256,
                        'packagename' : PACKAGENAME,
                        'mainactivity' : MAINACTIVITY,
                        'targetsdk' : TARGET_SDK,
                        'maxsdk' : MAX_SDK,
                        'minsdk' : MIN_SDK,
                        'androvername' : ANDROVERNAME,
                        'androver': ANDROVER,
                        'manifest': MANIFEST_ANAL,
                        'permissions' : PERMISSIONS,
                        'files' : FILES,
                        'certz' : CERTZ,
                        'activities' : ACTIVITIES,
                        'receivers' : RECEIVERS,
                        'providers' : PROVIDERS,
                        'services' : SERVICES,
                        'libraries' : LIBRARIES,
                        'act_count' : CNT_ACT,
                        'prov_count' : CNT_PRO,
                        'serv_count' : CNT_SER,
                        'bro_count' : CNT_BRO,
                        'native' : NATIVE,
                        'dynamic' : DYNAMIC,
                        'reflection' : REFLECT,
                        'crypto': CRYPTO,
                        'obfus': OBFUS,
                        'api': API,
                        'dang': DANG,
                        'urls': URLS,
                        'emails': EMAILS,
                        'mani': MANI,
                        'e_act': EXPORTED_CNT["act"],
                        'e_ser': EXPORTED_CNT["ser"],
                        'e_bro': EXPORTED_CNT["bro"],
                        'e_cnt': EXPORTED_CNT["cnt"],                        
                        }
                    elif Valid and pro_type=='ios':
                        print "[INFO] Redirecting to iOS Source Code Analyzer"
                        return HttpResponseRedirect('/StaticAnalyzer_iOS/?name='+APP_NAME+'&type=ios&checksum='+MD5)
                    else:
                        return HttpResponseRedirect('/ZIP_FORMAT/')
                template="static_analysis_android_zip.html"
                return render(request,template,context)
            else:
                print "\n[ERROR] Only APK,IPA and Zipped Android/iOS Source code supported now!"  
        else:
            return HttpResponseRedirect('/error/')

    except Exception as e:
        PrintException("[ERROR] Static Analyzer")
        context = {
        'title' : 'Error',
        'exp' : e.message,
        'doc' : e.__doc__
        }
        template="error.html"
        return render(request,template,context)
def GetHardcodedCert(files):
    try:
        print "[INFO] Getting Hardcoded Certificates"
        certz=''
        for f in files:
            ext=f.split('.')[-1]
            if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                certz+=escape(f) + "</br>"
        if len(certz)>1:
            certz="<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>"+certz+"</td><tr>"
        return certz
        return re.sub(RE_XML_ILLEGAL, "?", dat)
    except:
        PrintException("[ERROR] Getting Hardcoded Certificates")

def ReadManifest(APP_DIR,TOOLS_DIR,TYP,BIN):
    try:
        dat=''

        if BIN==True:
            print "[INFO] Getting Manifest from Binary"
            print "[INFO] AXML -> XML"
            manifest=os.path.join(APP_DIR,"AndroidManifest.xml")
            CP_PATH=TOOLS_DIR + 'AXMLPrinter2.jar'
            args=[settings.JAVA_PATH+'java','-jar', CP_PATH, manifest]
            dat=subprocess.check_output(args)
        else:
            print "[INFO] Getting Manifest from Source"
            if TYP=="eclipse":
                manifest=os.path.join(APP_DIR,"AndroidManifest.xml")
            elif TYP=="studio":
                manifest=os.path.join(APP_DIR,"app/src/main/AndroidManifest.xml")
            with io.open(manifest,mode='r',encoding="utf8",errors="ignore") as f:
                dat=f.read()
        return dat
    except:
        PrintException("[ERROR] Reading Manifest file")

def GetManifest(APP_DIR,TOOLS_DIR,TYP,BIN):
    try:
        dat=''
        mfest=''
        dat=ReadManifest(APP_DIR,TOOLS_DIR,TYP,BIN).replace("\n","")
        try:
            print "[INFO] Parsing AndroidManifest.xml"
            mfest=minidom.parseString(dat)
        except:
            PrintException("[ERROR] Pasrsing AndroidManifest.xml")
            mfest=minidom.parseString(r'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="Failed"  android:versionName="Failed" package="Failed"  platformBuildVersionCode="Failed" platformBuildVersionName="Failed XML Parsing" ></manifest>')      
            print "[WARNING] Using Fake XML to continue the Analysis"
        return mfest
    except:
        PrintException("[ERROR] Parsing Manifest file")
def ValidAndroidZip(APP_DIR):
    try:
        print "[INFO] Checking for ZIP Validity and Mode"
        #Eclipse
        man=os.path.isfile(os.path.join(APP_DIR,"AndroidManifest.xml"))
        src=os.path.exists(os.path.join(APP_DIR,"src/"))
        if man and src:
            return 'eclipse',True
        #Studio
        man=os.path.isfile(os.path.join(APP_DIR,"app/src/main/AndroidManifest.xml"))
        src=os.path.exists(os.path.join(APP_DIR,"app/src/main/java/"))
        if man and src:
            return 'studio',True
        #iOS Source
        xcode = [f for f in os.listdir(APP_DIR) if f.endswith(".xcodeproj")]
        if xcode:
            return 'ios',True
        return '',False
    except:
        PrintException("[ERROR] Determining Upload type")

def HashGen(APP_PATH):
    try:
        print "[INFO] Generating Hashes"
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        BLOCKSIZE = 65536
        with io.open(APP_PATH, mode='rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                sha1.update(buf)
                sha256.update(buf)
                buf = afile.read(BLOCKSIZE)
        sha1val = sha1.hexdigest()
        sha256val=sha256.hexdigest()
        return sha1val, sha256val
    except:
        PrintException("[ERROR] Generating Hashes")

def FileSize(APP_PATH): return round(float(os.path.getsize(APP_PATH)) / (1024 * 1024),2)
def GenDownloads(APP_DIR,MD5):
    try:
        print "[INFO] Generating Downloads"
        #For Java
        DIR=os.path.join(APP_DIR,'java_source/')
        DWD=os.path.join(settings.DWD_DIR, MD5 + '-java.zip')
        zipf = zipfile.ZipFile(DWD, 'w')
        zipdir(DIR, zipf)
        zipf.close()
        #For Smali
        DIR=os.path.join(APP_DIR,'smali_source/')
        DWD=os.path.join(settings.DWD_DIR, MD5 + '-smali.zip')
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

def Unzip(APP_PATH, EXT_PATH):
    print "[INFO] Unzipping"
    try:
        files=[]
        with zipfile.ZipFile(APP_PATH, "r") as z:
                z.extractall(EXT_PATH)
                files=z.namelist()
        return files
    except:
        PrintException("[ERROR] Unzipping Error")
        if platform.system()=="Windows":
            print "\n[INFO] Not yet Implemented."
        else:
            print "\n[INFO] Using the Default OS Unzip Utility."
            try:
                subprocess.call(['unzip', '-o', '-q', APP_PATH, '-d', EXT_PATH])
                dat=subprocess.check_output(['unzip','-qq','-l',APP_PATH])
                dat=dat.split('\n')
                x=['Length   Date   Time   Name']
                x=x+dat
                return x
            except:
                PrintException("[ERROR] Unzipping Error")

def FormatPermissions(PERMISSIONS):
    try:
        print "[INFO] Formatting Permissions"
        DESC=''
        for ech in PERMISSIONS:
            DESC=DESC + '<tr><td>' + ech + '</td>'
            for l in PERMISSIONS[ech]:
                DESC= DESC + '<td>' + l + '</td>'
            DESC= DESC+ '</tr>'
        DESC=DESC.replace('dangerous','<span class="label label-danger">dangerous</span>').replace('normal','<span class="label label-info">normal</span>').replace('signatureOrSystem','<span class="label label-warning">SignatureOrSystem</span>').replace('signature','<span class="label label-success">signature</span>')
        return DESC
    except:
        PrintException("[ERROR] Formatting Permissions")

def CertInfo(APP_DIR,TOOLS_DIR):
    try:
        print "[INFO] Reading Code Signing Certificate"
        cert=os.path.join(APP_DIR,'META-INF/')
        CP_PATH=TOOLS_DIR + 'CertPrint.jar'
        files = [ f for f in os.listdir(cert) if os.path.isfile(os.path.join(cert,f)) ]
        if "CERT.RSA" in files:
            certfile=os.path.join(cert,"CERT.RSA")
        else:
            for f in files:
                if f.lower().endswith(".rsa"):
                    certfile=os.path.join(cert,f)
                elif f.lower().endswith(".dsa"):
                    certfile=os.path.join(cert,f)

        args=[settings.JAVA_PATH+'java','-jar', CP_PATH, certfile]
        dat=''
        dat=escape(subprocess.check_output(args)).replace('\n', '</br>')
        return dat
    except:
        PrintException("[ERROR] Reading Code Signing Certificate")

def WinFixJava(TOOLS_DIR):
    try:
        print "[INFO] Running JAVA path fix in Windows"
        DMY=os.path.join(TOOLS_DIR,'d2j2/d2j_invoke.tmp')
        ORG=os.path.join(TOOLS_DIR,'d2j2/d2j_invoke.bat')
        dat=''
        with open(DMY,'r') as f:
            dat=f.read().replace("[xxx]",settings.JAVA_PATH+"java")
        with open(ORG,'w') as f:
            f.write(dat)
    except:
        PrintException("[ERROR] Running JAVA path fix in Windows")

def Dex2Jar(APP_DIR,TOOLS_DIR):
    try:
        print "[INFO] DEX -> JAR"
        if platform.system()=="Windows":
            WinFixJava(TOOLS_DIR)
            D2J=os.path.join(TOOLS_DIR,'d2j2/') +'d2j-dex2jar.bat'
        else:
            INV=os.path.join(TOOLS_DIR,'d2j2/') +'d2j_invoke.sh'
            D2J=os.path.join(TOOLS_DIR,'d2j2/') +'d2j-dex2jar.sh'
            subprocess.call(["chmod", "777", D2J])
            subprocess.call(["chmod", "777", INV])
        args=[D2J,APP_DIR+'classes.dex','-o',APP_DIR +'classes.jar']
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting Dex to JAR")

def Dex2Smali(APP_DIR,TOOLS_DIR):
    try:
        print "[INFO] DEX -> SMALI"
        DEX_PATH=APP_DIR+'classes.dex'
        BS_PATH=TOOLS_DIR+ 'baksmali.jar'
        OUTPUT=os.path.join(APP_DIR,'smali_source/')
        args=[settings.JAVA_PATH+'java','-jar',BS_PATH,DEX_PATH,'-o',OUTPUT]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting DEX to SMALI")

def Jar2Java(APP_DIR,TOOLS_DIR):
    try:
        print "[INFO] JAR -> JAVA"
        JAR_PATH=APP_DIR + 'classes.jar'
        OUTPUT=os.path.join(APP_DIR, 'java_source/')
        if settings.DECOMPILER=='jd-core':
            JD_PATH=TOOLS_DIR + 'jd-core.jar'
            args=[settings.JAVA_PATH+'java','-jar', JD_PATH, JAR_PATH,OUTPUT]
        elif settings.DECOMPILER=='cfr':
            JD_PATH=TOOLS_DIR + 'cfr_0_101.jar'
            args=[settings.JAVA_PATH+'java','-jar', JD_PATH,JAR_PATH,'--outputdir',OUTPUT]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Converting JAR to JAVA")
        
def Strings(APP_FILE,APP_DIR,TOOLS_DIR):
    try:
        print "[INFO] Extracting Strings from APK"
        strings=TOOLS_DIR+'strings_from_apk.jar'
        args=[settings.JAVA_PATH+'java','-jar',strings,APP_DIR+APP_FILE,APP_DIR]
        subprocess.call(args)
        dat=''
        try:
            with io.open(APP_DIR+'strings.json', mode='r', encoding="utf8",errors="ignore") as f:
                dat=f.read()
        except:
            pass
        dat=dat[1:-1].split(",")
        return dat
    except:
        PrintException("[ERROR] Extracting Strings from APK")

def ManifestData(mfxml,app_dir):
    try:
        print "[INFO] Extracting Manifest Data"
        SVC=[]
        ACT=[]
        BRD=[]
        CNP=[]
        LIB=[]
        PERM=[]
        DP={}
        package=''
        minsdk=''
        maxsdk=''
        targetsdk=''
        mainact=''
        androidversioncode=''
        androidversionname=''
        permissions = mfxml.getElementsByTagName("uses-permission")
        manifest = mfxml.getElementsByTagName("manifest")
        activities = mfxml.getElementsByTagName("activity")
        services = mfxml.getElementsByTagName("service")
        providers = mfxml.getElementsByTagName("provider")
        receivers = mfxml.getElementsByTagName("receiver")
        libs = mfxml.getElementsByTagName("uses-library")
        sdk=mfxml.getElementsByTagName("uses-sdk")
        for node in sdk:
            minsdk=node.getAttribute("android:minSdkVersion")
            maxsdk=node.getAttribute("android:maxSdkVersion")
            targetsdk=node.getAttribute("android:targetSdkVersion")
        for node in manifest:
            package = node.getAttribute("package")
            androidversioncode=node.getAttribute("android:versionCode")
            androidversionname=node.getAttribute("android:versionName")
        for activity in activities:
            act = activity.getAttribute("android:name")
            ACT.append(act)
            if len(mainact)<1:
                # ^ Fix for Shitty Manifest with more than one MAIN
                for sitem in activity.getElementsByTagName("action"):
                    val = sitem.getAttribute("android:name")
                    if val == "android.intent.action.MAIN" :
                        mainact=activity.getAttribute("android:name")
                if mainact=='':
                    for sitem in activity.getElementsByTagName("category") :
                        val = sitem.getAttribute( "android:name" )
                        if val == "android.intent.category.LAUNCHER" :
                            mainact=activity.getAttribute("android:name")
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
            perm= permission.getAttribute("android:name")
            PERM.append(perm)

        for i in PERM:
            prm = i
            pos = i.rfind(".")
            if pos != -1 :
                prm = i[pos+1:]
            try :
                DP[ i ] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][ prm ]
            except KeyError :
                DP[ i ] = [ "dangerous", "Unknown permission from android reference", "Unknown permission from android reference" ]
        else:
            pass
        return SVC,ACT,BRD,CNP,LIB,DP,package,mainact,minsdk,maxsdk,targetsdk,androidversioncode,androidversionname
    except:
        PrintException("[ERROR] Extracting Manifest Data")
        
def ManifestAnalysis(mfxml,mainact):
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
        granturipermissions = mfxml.getElementsByTagName("grant-uri-permission")
        for node in manifest:
            package = node.getAttribute("package")
        RET=''
        EXPORTED=[]
        ##SERVICES
        ##search for services without permissions set
        #if a service is exporeted and has no permission
        #nor an intent filter, flag it
        #I doubt if this part gets executed evver
        for service in services:
            if service.getAttribute("android:exported") == 'true':
                perm = ''
                if service.getAttribute("android:permission"):
                    #service permission exists
                    perm =' (permission '+service.getAttribute("android:permission")+' exists.) '
                servicename = service.getAttribute("android:name")
                RET=RET +'<tr><td>Service (' + servicename + ') is not Protected.'+perm+' <br>[android:exported=true]</td><td><span class="label label-danger">high</span></td><td> A service was found to be shared with other apps on the device without an intent filter or a permission requirement therefore leaving it accessible to any other application on the device.</td></tr>'
                exp_count["ser"] = exp_count["ser"] + 1
        ##APPLICATIONS
        for application in applications:

            if application.getAttribute("android:debuggable") == "true":
                RET=RET+ '<tr><td>Debug Enabled For App <br>[android:debuggable=true]</td><td><span class="label label-danger">high</span></td><td>Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes.</td></tr>'
            if application.getAttribute("android:allowBackup") == "true":
                RET=RET+ '<tr><td>Application Data can be Backed up<br>[android:allowBackup=true]</td><td><span class="label label-warning">medium</span></td><td>This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.</td></tr>'
            elif application.getAttribute("android:allowBackup") == "false":
                pass
            else:
                RET=RET+ '<tr><td>Application Data can be Backed up<br>[android:allowBackup] flag is missing.</td><td><span class="label label-warning">medium</span></td><td>The flag [android:allowBackup] should be set to false. By default it is set to true and allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.</td></tr>'
            if application.getAttribute("android:testOnly")== "true":
                RET=RET+ '<tr><td>Application is in Test Mode <br>[android:testOnly=true]</td><td><span class="label label-danger">high</span></td><td> It may expose functionality or data outside of itself that would cause a security hole.</td></tr>'
            for node in application.childNodes:
                ad=''
                if node.nodeName == 'activity':
                    itmname= 'Activity'
                    cnt_id= "act"
                    ad='n'
                elif node.nodeName == 'activity-alias':
                    itmname ='Activity-Alias'
                    cnt_id= "act"
                    ad='n'
                elif node.nodeName == 'provider':
                    itmname = 'Content Provider'
                    cnt_id= "cnt"
                elif node.nodeName == 'receiver':
                    itmname = 'Broadcast Receiver'
                    cnt_id= "bro"
                elif node.nodeName == 'service':
                    itmname = 'Service'
                    cnt_id= "ser"
                else:
                    itmname = 'NIL'
                item=''
                #Task Affinity
                if ((itmname =='Activity' or itmname=='Activity-Alias') and (node.getAttribute("android:taskAffinity"))):
                    item=node.getAttribute("android:name")
                    RET=RET+ '<tr><td>TaskAffinity is set for Activity </br>('+item + ')</td><td><span class="label label-danger">high</span></td><td>If taskAffinity is set, then other application could read the Intents sent to Activities belonging to another task. Always use the default setting keeping the affinity as the package name in order to prevent sensitive information inside sent or received Intents from being read by another application.</td></tr>'
                #LaunchMode
                if ((itmname =='Activity' or itmname=='Activity-Alias') and ((node.getAttribute("android:launchMode")=='singleInstance') or (node.getAttribute("android:launchMode")=='singleTask'))):
                    item=node.getAttribute("android:name")
                    RET=RET+ '<tr><td>Launch Mode of Activity ('+item + ') is not standard.</td><td><span class="label label-danger">high</span></td><td>An Activity should not be having the launch mode attribute set to "singleTask/singleInstance" as it becomes root Activity and it is possible for other applications to read the contents of the calling Intent. So it is required to use the "standard" launch mode attribute when sensitive information is included in an Intent.</td></tr>'
                #Exported Check
                item=''
                isExp=False
                if ('NIL' != itmname) and (node.getAttribute("android:exported") == 'true'):
                    isExp=True
                    perm=''
                    item=node.getAttribute("android:name")
                    if node.getAttribute("android:permission"):
                        #permission exists
                        perm = ' (permission '+node.getAttribute("android:permission")+' exists.) '
                    if item!=mainact:
                        if (itmname =='Activity' or itmname=='Activity-Alias'):
                            EXPORTED.append(item)
                        RET=RET +'<tr><td>'+itmname+' (' + item + ') is not Protected.'+perm+' <br>[android:exported=true]</td><td><span class="label label-danger">high</span></td><td> A'+ad+' '+itmname+' was found to be shared with other apps on the device therefore leaving it accessible to any other application on the device.</td></tr>'
                        exp_count[cnt_id] = exp_count[cnt_id] + 1
                else:
                    isExp=False
                impE=False
                if ('NIL' != itmname) and (node.getAttribute("android:exported") == 'false'):
                    impE=True
                else:
                    impE=False
                if (isExp==False and impE==False):
                    isInf=False
                    #Logic to support intent-filter
                    intentfilters = node.childNodes
                    for i in intentfilters:
                        inf=i.nodeName
                        if inf=="intent-filter":
                            isInf=True
                    if isInf:
                        item=node.getAttribute("android:name")
                        if item!=mainact:
                            if (itmname =='Activity' or itmname=='Activity-Alias'):
                                EXPORTED.append(item)
                            RET=RET +'<tr><td>'+itmname+' (' + item + ') is not Protected.<br>An intent-filter exists.</td><td><span class="label label-danger">high</span></td><td> A'+ad+' '+itmname+' was found to be shared with other apps on the device therefore leaving it accessible to any other application on the device. The presence of intent-filter indicates that the '+itmname+' is explicitly exported.</td></tr>'
                            exp_count[cnt_id] = exp_count[cnt_id] + 1

        ##GRANT-URI-PERMISSIONS
        title = 'Improper Content Provider Permissions'
        desc = ('A content provider permission was set to allows access from any other app on the ' +
                'device. Content providers may contain sensitive information about an app and therefore should not be shared.')
        for granturi in granturipermissions:
            if granturi.getAttribute("android:pathPrefix") == '/':
                RET=RET+ '<tr><td>' + title + '<br> [pathPrefix=/] </td>' + '<td><span class="label label-danger">high</span></td><td>'+ desc+'</td></tr>'
            elif granturi.getAttribute("android:path") == '/':
                RET=RET+ '<tr><td>' + title + '<br> [path=/] </td>' + '<td><span class="label label-danger">high</span></td><td>'+ desc+'</td></tr>'
            elif granturi.getAttribute("android:pathPattern") == '*':
                RET=RET+ '<tr><td>' + title + '<br> [path=*]</td>' + '<td><span class="label label-danger">high</span></td><td>'+ desc +'</td></tr>'

        ##DATA
        for data in datas:
            if data.getAttribute("android:scheme") == "android_secret_code":
                xmlhost = data.getAttribute("android:host")
                desc = ("A secret code was found in the manifest. These codes, when entered into the dialer " +
                    "grant access to hidden content that may contain sensitive information.")
                RET=RET+  '<tr><td>Dailer Code: '+ xmlhost + 'Found <br>[android:scheme="android_secret_code"]</td><td><span class="label label-danger">high</span></td><td>'+ desc + '</td></tr>'
            elif data.getAttribute("android:port"):
                dataport = data.getAttribute("android:port")
                title = "Data SMS Receiver Set"
                desc = "A binary SMS recevier is configured to listen on a port. Binary SMS messages sent to a device are processed by the application in whichever way the developer choses. The data in this SMS should be properly validated by the application. Furthermore, the application should assume that the SMS being received is from an untrusted source."
                RET=RET+  '<tr><td> on Port: ' + dataport +  'Found<br>[android:port]</td><td><span class="label label-danger">high</span></td><td>'+ desc +'</td></tr>'

        ##INTENTS

        for intent in intents:
            if intent.getAttribute("android:priority").isdigit():
                value = intent.getAttribute("android:priority")
                if int(value) > 100:
                    RET=RET+ '<tr><td>High Intent Priority ('+ value +')<br>[android:priority]</td><td><span class="label label-warning">medium</span></td><td>By setting an intent priority higher than another intent, the app effectively overrides other requests.</td></tr>'
        ##ACTIONS
        for action in actions:
            if action.getAttribute("android:priority").isdigit():
                value = action.getAttribute("android:priority")
                if int(value) > 100:
                    RET=RET + '<tr><td>High Action Priority (' + value+')<br>[android:priority]</td><td><span class="label label-warning">medium</span></td><td>By setting an action priority higher than another action, the app effectively overrides other requests.</td></tr>'
        if len(RET)< 2:
            RET='<tr><td>None</td><td>None</td><td>None</td><tr>'
        return RET,EXPORTED,exp_count
    except:
        PrintException("[ERROR] Performing Manifest Analysis")

def CodeAnalysis(APP_DIR,MD5,PERMS,TYP):
    try:
        print "[INFO] Static Android Code Analysis Started"
        c = {key: [] for key in ('inf_act','inf_ser','inf_bro','log','fileio','rand','d_hcode','dex_cert','dex_tamper','d_rootcheck','d_root','d_ssl_pin','dex_root','dex_debug_key','dex_debug','dex_debug_con','dex_emulator','d_webviewdisablessl','d_webviewdebug','d_sensitive','d_ssl','d_sqlite','d_con_world_readable','d_con_world_writable','d_con_private','d_extstorage','d_tmpfile','d_jsenabled','gps','crypto','exec','server_socket','socket','datagramp','datagrams','ipc','msg','webview_addjs','webview','webviewget','webviewpost','httpcon','urlcon','jurl','httpsurl','nurl','httpclient','notify','cellinfo','cellloc','subid','devid','softver','simserial','simop','opname','contentq','refmethod','obf','gs','bencode','bdecode','dex','mdigest')}
        crypto=False
        obfus=False
        reflect=False
        dynamic=False
        native=False
        EmailnFile=''
        URLnFile=''
        if TYP=="apk":
            JS=os.path.join(APP_DIR, 'java_source/')
        elif TYP=="studio":
            JS=os.path.join(APP_DIR, 'app/src/main/java/')
        elif TYP=="eclipse":
            JS=os.path.join(APP_DIR, 'src/')
        print "[INFO] Code Analysis Started on - " + JS
        for dirName, subDir, files in os.walk(JS):
            for jfile in files:
                jfile_path=os.path.join(JS,dirName,jfile)
                if "+" in jfile:
                    p2=os.path.join(JS,dirName,jfile.replace("+","x"))
                    shutil.move(jfile_path,p2)
                    jfile_path=p2
                repath=dirName.replace(JS,'')
                if jfile.endswith('.java') and not (repath.startswith('android\\') or repath.startswith('com\\google\\')) :
                    dat=''
                    with io.open(jfile_path,mode='r',encoding="utf8",errors="ignore") as f:
                        dat=f.read()
                    #Initialize
                    URLS=[]
                    EMAILS=[]
                    #Code Analysis
                    #print "[INFO] Doing Code Analysis on - " + jfile_path

                    if (re.findall('MODE_WORLD_READABLE|Context.MODE_WORLD_READABLE',dat)):
                        c['d_con_world_readable'].append(jfile_path.replace(JS,''))
                    if (re.findall('MODE_WORLD_WRITABLE|Context.MODE_WORLD_WRITABLE',dat)):
                        c['d_con_world_writable'].append(jfile_path.replace(JS,''))
                    if (re.findall('MODE_PRIVATE|Context.MODE_PRIVATE',dat)):
                        c['d_con_private'].append(jfile_path.replace(JS,''))
                    if ((('WRITE_EXTERNAL_STORAGE') in PERMS) and (('.getExternalStorage') in dat or ('.getExternalFilesDir(') in dat)):
                        c['d_extstorage'].append(jfile_path.replace(JS,''))
                    if (('WRITE_EXTERNAL_STORAGE') in PERMS) and (('.createTempFile(') in dat):
                        c['d_tmpfile'].append(jfile_path.replace(JS,''))
                    if (('setJavaScriptEnabled(true)') in dat and ('.addJavascriptInterface(') in dat ):
                        c['d_jsenabled'].append(jfile_path.replace(JS,''))
                    if (('.setWebContentsDebuggingEnabled(true)') in dat and ('WebView') in dat ):
                        c['d_webviewdebug'].append(jfile_path.replace(JS,''))
                    if (('onReceivedSslError(WebView') in dat and ('.proceed();') in dat ):
                        c['d_webviewdisablessl'].append(jfile_path.replace(JS,''))
                    if ((('rawQuery(') in dat or ('execSQL(') in dat) and (('android.database.sqlite') in dat)):
                        c['d_sqlite'].append(jfile_path.replace(JS,''))
                    if ((('javax.net.ssl') in dat) and (('TrustAllSSLSocket-Factory') in dat or ('AllTrustSSLSocketFactory') in dat or ('NonValidatingSSLSocketFactory')  in dat or('ALLOW_ALL_HOSTNAME_VERIFIER') in dat or ('.setDefaultHostnameVerifier(') in dat or ('NullHostnameVerifier(') in dat)):
                        c['d_ssl'].append(jfile_path.replace(JS,''))
                    #Add Sachin's Code Here and Add support for detecting insecure ssl algoo's 

                    if (('password = "') in dat.lower() or ('secret = "') in dat.lower() or ('username = "') in dat.lower() or ('key = "') in dat.lower()):
                        c['d_sensitive'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('DebugDetector.isDebuggable') in dat):
                        c['dex_debug'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('DebugDetector.isDebuggerConnected') in dat):
                        c['dex_debug_con'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('EmulatorDetector.isRunningInEmulator') in dat):
                        c['dex_emulator'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('DebugDetector.isSignedWithDebugKey') in dat):
                        c['dex_debug_key'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('RootDetector.isDeviceRooted') in dat):
                        c['dex_root'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('TamperDetector.checkApk') in dat):
                        c['dex_tamper'].append(jfile_path.replace(JS,''))
                    if (('import dexguard.util') in dat and ('CertificateChecker.checkCertificate') in dat):
                        c['dex_cert'].append(jfile_path.replace(JS,''))
                    if (('org.thoughtcrime.ssl.pinning') in dat and (('PinningHelper.getPinnedHttpsURLConnection') in dat or ('PinningHelper.getPinnedHttpClient') in dat or ('PinningSSLSocketFactory(') in dat)):
                        c['d_ssl_pin'].append(jfile_path.replace(JS,''))
                    if (('com.noshufou.android.su') in dat or ('com.thirdparty.superuser') in dat or ('eu.chainfire.supersu') in dat or ('com.koushikdutta.superuser') in dat or ('eu.chainfire.') in dat):
                        c['d_root'].append(jfile_path.replace(JS,''))
                    if (('.contains("test-keys")') in dat or ('/system/app/Superuser.apk') in dat or ('isDeviceRooted()') in dat or ('/system/bin/failsafe/su') in dat or ('/system/sd/xbin/su') in dat or ('"/system/xbin/which", "su"') in dat or ('RootTools.isAccessGiven()') in dat):
                        c['d_rootcheck'].append(jfile_path.replace(JS,''))
                    if (re.findall('java.util.Random',dat)):
                        c['rand'].append(jfile_path.replace(JS,''))
                    if(re.findall('Log.|System.out.print',dat)):
                        c['log'].append(jfile_path.replace(JS,''))
                    if ".hashCode()" in dat:
                        c['d_hcode'].append(jfile_path.replace(JS,''))

                    
                    #Inorder to Add rule to Code Analysis, add identifier to c, add rule here and define identifier description and severity the bottom of this function.
                    #API Check
                    if (re.findall("System.loadLibrary\(|System.load\(", dat)):
                        native=True
                    if(re.findall('dalvik.system.DexClassLoader|java.security.ClassLoader|java.net.URLClassLoader|java.security.SecureClassLoader',dat)):
                        dynamic=True
                    if(re.findall('java.lang.reflect.Method|java.lang.reflect.Field|Class.forName',dat)):
                        reflect=True
                    if (re.findall('javax.crypto|kalium.crypto|bouncycastle.crypto',dat)):
                        crypto=True
                        c['crypto'].append(jfile_path.replace(JS,''))
                    if (('utils.AESObfuscator') in dat and ('getObfuscator') in dat):
                        c['obf'].append(jfile_path.replace(JS,''))
                        obfus=True

                    if (('getRuntime().exec(') in dat and ('getRuntime(') in dat):
                        c['exec'].append(jfile_path.replace(JS,''))
                    if (('ServerSocket') in dat and ('net.ServerSocket') in dat):
                        c['server_socket'].append(jfile_path.replace(JS,''))
                    if (('Socket') in dat and ('net.Socket') in dat):
                        c['socket'].append(jfile_path.replace(JS,''))
                    if (('DatagramPacket') in dat and ('net.DatagramPacket') in dat):
                        c['datagramp'].append(jfile_path.replace(JS,''))
                    if (('DatagramSocket') in dat and ('net.DatagramSocket') in dat):
                        c['datagrams'].append(jfile_path.replace(JS,''))
                    if (re.findall('IRemoteService|IRemoteService.Stub|IBinder|Intent',dat)):
                        c['ipc'].append(jfile_path.replace(JS,''))
                    if ((('sendMultipartTextMessage') in dat or  ('sendTextMessage') in dat or ('vnd.android-dir/mms-sms') in dat) and (('telephony.SmsManager') in dat)):
                        c['msg'].append(jfile_path.replace(JS,''))
                    if (('addJavascriptInterface') in dat and ('WebView') in dat and ('android.webkit') in dat):
                        c['webview_addjs'].append(jfile_path.replace(JS,''))
                    if (('WebView') in dat and ('loadData') in dat and ('android.webkit') in dat):
                        c['webviewget'].append(jfile_path.replace(JS,''))
                    if (('WebView') in dat and ('postUrl') in dat and ('android.webkit') in dat):
                        c['webviewpost'].append(jfile_path.replace(JS,''))
                    if ((('HttpURLConnection') in dat or ('org.apache.http') in dat) and (('openConnection') in dat or ('connect') in dat or ('HttpRequest') in dat)):
                        c['httpcon'].append(jfile_path.replace(JS,''))
                    if ((('net.URLConnection') in dat) and (('connect') in dat or ('openConnection') in dat or ('openStream') in dat)):
                        c['urlcon'].append(jfile_path.replace(JS,''))
                    if ((('net.JarURLConnection') in dat) and (('JarURLConnection') in dat or ('jar:') in dat)):
                        c['jurl'].append(jfile_path.replace(JS,''))
                    if ((('javax.net.ssl.HttpsURLConnection') in dat)and (('HttpsURLConnection') in dat or ('connect') in dat)):
                        c['httpsurl'].append(jfile_path.replace(JS,''))
                    if (('net.URL') and ('openConnection' or 'openStream')) in dat:
                        c['nurl'].append(jfile_path.replace(JS,''))
                    if (re.findall('http.client.HttpClient|net.http.AndroidHttpClient|http.impl.client.AbstractHttpClient',dat)):
                        c['httpclient'].append(jfile_path.replace(JS,''))
                    if (('app.NotificationManager') in dat and ('notify') in dat):
                        c['notify'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getAllCellInfo') in dat):
                        c['cellinfo'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getCellLocation') in dat):
                        c['cellloc'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getSubscriberId') in dat):
                        c['subid'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getDeviceId') in dat):
                        c['devid'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getDeviceSoftwareVersion') in dat):
                        c['softver'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getSimSerialNumber') in dat):
                        c['simserial'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getSimOperator') in dat):
                        c['simop'].append(jfile_path.replace(JS,''))
                    if (('telephony.TelephonyManager') in dat and ('getSimOperatorName') in dat):
                        c['opname'].append(jfile_path.replace(JS,''))
                    if (('content.ContentResolver') in dat and ('query') in dat):
                        c['contentq'].append(jfile_path.replace(JS,''))
                    if (('java.lang.reflect.Method') in dat and ('invoke') in dat):
                        c['refmethod'].append(jfile_path.replace(JS,''))
                    if (('getSystemService') in dat):
                        c['gs'].append(jfile_path.replace(JS,''))
                    if ((('android.util.Base64') in dat) and (('.encodeToString') in dat or ('.encode') in dat)):
                        c['bencode'].append(jfile_path.replace(JS,''))
                    if (('android.util.Base64') in dat and ('.decode') in dat):
                        c['bdecode'].append(jfile_path.replace(JS,''))
                    if ((('dalvik.system.PathClassLoader') in dat or ('dalvik.system.DexFile') in dat or ('dalvik.system.DexPathList') in dat or ('dalvik.system.DexClassLoader') in dat) and (('loadDex') in dat or ('loadClass') in dat or ('DexClassLoader') in dat or ('loadDexFile') in dat)):
                        c['dex'].append(jfile_path.replace(JS,''))
                    if ((('java.security.MessageDigest') in dat) and (('MessageDigestSpi') in dat or ('MessageDigest') in dat)):
                        c['mdigest'].append(jfile_path.replace(JS,''))
                    if ((('android.location') in dat )and (('getLastKnownLocation(') in dat or ('requestLocationUpdates(') in dat or ('getLatitude(') in dat or ('getLongitude(') in dat)):
                        c['gps'].append(jfile_path.replace(JS,''))
                    if(re.findall('OpenFileOutput|getSharedPreferences|SharedPreferences.Editor|getCacheDir|getExternalStorageState|openOrCreateDatabase',dat)):
                        c['fileio'].append(jfile_path.replace(JS,''))
                    if (re.findall('startActivity\(|startActivityForResult\(',dat)):
                        c['inf_act'].append(jfile_path.replace(JS,''))
                    if (re.findall('startService\(|bindService\(',dat)):
                        c['inf_ser'].append(jfile_path.replace(JS,''))
                    if (re.findall('sendBroadcast\(|sendOrderedBroadcast\(|sendStickyBroadcast\(',dat)):
                        c['inf_bro'].append(jfile_path.replace(JS,''))
                    
                   

                    fl=jfile_path.replace(JS,'')
                    base_fl=ntpath.basename(fl)
                    
                    #URLs My Custom regex
                    p = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE) 
                    urllist=re.findall(p, dat.lower())
                    uflag=0
                    for url in urllist:
                        if url not in URLS:
                            URLS.append(url)
                            uflag=1
                    if uflag==1:
                        URLnFile+="<tr><td>" + "<br>".join(URLS) + "</td><td><a href='../ViewSource/?file=" + escape(fl)+"&md5="+MD5+"&type="+TYP+"'>"+escape(base_fl)+"</a></td></tr>"
                    
                    #Email Etraction Regex
                    
                    regex = re.compile("[\w.-]+@[\w-]+\.[\w.]+")
                    eflag=0
                    for email in regex.findall(dat.lower()):
                        if ((email not in EMAILS) and (not email.startswith('//'))):
                            EMAILS.append(email)
                            eflag=1
                    if eflag==1:
                        EmailnFile+="<tr><td>" + "<br>".join(EMAILS) + "</td><td><a href='../ViewSource/?file=" + escape(fl)+"&md5="+MD5+"&type="+TYP+"'>"+escape(base_fl)+"</a></td></tr>"
                    
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        #API Description
        dc ={'gps':'GPS Location',
            'crypto':'Crypto ',
            'exec': 'Execute System Command ',
            'server_socket':'TCP Server Socket ' ,
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
        html=''
        for ky in dc:
            if c[ky]:
                link=''
                hd="<tr><td>"+dc[ky]+"</td><td>"
                for l in c[ky]:
                    link+="<a href='../ViewSource/?file="+ escape(l) +"&md5="+MD5+"&type="+TYP+"'>"+escape(ntpath.basename(l))+"</a> "
                html+=hd+link+"</td></tr>"
        #Code Review Description
        dg={'d_sensitive' : "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
            'd_ssl': 'Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole.',
            'd_sqlite': 'App uses SQLite Database and execute raw SQL query. Untrusted user input in raw SQL queries can cause SQL Injection. Also sensitive information should be encrypted and written to the database.',
            'd_con_world_readable':'The file is World Readable. Any App can read from the file',
            'd_con_world_writable':'The file is World Writable. Any App can write to the file',
            'd_con_private':'App can write to App Directory. Sensitive Information should be encrypted.',
            'd_extstorage': 'App can read/write to External Storage. Any App can read data written to External Storage.',
            'd_tmpfile': 'App creates temp file. Sensitive information should never be written into a temp file.',
            'd_jsenabled':'Insecure WebView Implementation. Execution of user controlled code in WebView is a critical Security Hole.',
            'd_webviewdisablessl':'Insecure WebView Implementation. WebView ignores SSL Certificate Errors.',
            'd_webviewdebug':'Remote WebView debugging is enabled.',
            'dex_debug': 'DexGuard Debug Detection code to detect wheather an App is debuggable or not is identified.',
            'dex_debug_con':'DexGuard Debugger Detection code is identified.',
            'dex_debug_key':'DecGuard code to detect wheather the App is signed with a debug key or not is identified.',
            'dex_emulator':'DexGuard Emulator Detection code is identified.',
            'dex_root':'DexGuard Root Detection code is identified.',
            'dex_tamper' : 'DexGuard App Tamper Detection code is identified.',
            'dex_cert' : 'DexGuard Signer Certificate Tamper Detection code is identified.',
            'd_ssl_pin':' This App uses an SSL Pinning Library (org.thoughtcrime.ssl.pinning) to prevent MITM attacks in secure communication channel.',
            'd_root' : 'This App may request root (Super User) privileges.',
            'd_rootcheck' : 'This App may have root detection capabilities.',
            'd_hcode' : 'This App uses Java Hash Code. It\'s a weak hash function and should never be used in Secure Crypto Implementation.',
            'rand' : 'The App uses an insecure Random Number Generator.',
            'log' : 'The App logs information. Sensitive information should never be logged.',
            }

                    

        dang=''
        spn_dang='<span class="label label-danger">high</span>'
        spn_info='<span class="label label-info">info</span>'
        spn_sec='<span class="label label-success">secure</span>'
        spn_warn='<span class="label label-warning">warning</span>'

        for k in dg:
            if c[k]:
                link=''
                if (re.findall('d_con_private|log',k)):
                    hd='<tr><td>'+dg[k]+'</td><td>'+spn_info+'</td><td>'
                elif (re.findall('d_rootcheck|dex_cert|dex_tamper|dex_debug|dex_debug_con|dex_debug_key|dex_emulator|dex_root|d_ssl_pin',k)):
                    hd='<tr><td>'+dg[k]+'</td><td>'+spn_sec+'</td><td>'
                elif (re.findall('d_jsenabled',k)):
                    hd='<tr><td>'+dg[k]+'</td><td>'+spn_warn+'</td><td>'
                else:
                    hd='<tr><td>'+dg[k]+'</td><td>'+spn_dang+'</td><td>'

                for ll in c[k]:
                    link+="<a href='../ViewSource/?file="+ escape(ll) +"&md5="+MD5+"&type="+TYP+"'>"+escape(ntpath.basename(ll))+"</a> "

                dang+=hd+link+"</td></tr>"

        return html,dang,URLnFile,EmailnFile,crypto,obfus,reflect,dynamic,native
    except:
        PrintException("[ERROR] Performing Code Analysis")
        
##############################################################
# Code to support iOS Static Code Anlysis
##############################################################
#iOS Support Functions
def StaticAnalyzer_iOS(request):
    try:
        #Input validation
        print "[INFO] iOS Static Analysis Started"
        TYP=request.GET['type']
        RESCAN= str(request.GET.get('rescan', 0))
        m=re.match('[0-9a-f]{32}',request.GET['checksum'])
        if ((m) and (request.GET['name'].endswith('.ipa') or request.GET['name'].endswith('.zip')) and ((TYP=='ipa') or (TYP=='ios'))):
            DIR=settings.BASE_DIR        #BASE DIR
            APP_NAME=request.GET['name'] #APP ORGINAL NAME
            MD5=request.GET['checksum']  #MD5
            APP_DIR=os.path.join(settings.UPLD_DIR, MD5+'/') #APP DIRECTORY
            TOOLS_DIR=os.path.join(DIR, 'StaticAnalyzer/tools/mac/')  #TOOLS DIR
            if TYP=='ipa':
                #DB
                DB=StaticAnalyzerIPA.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN=='0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                    'title' : DB[0].TITLE,
                    'name' : DB[0].APPNAMEX,
                    'size' : DB[0].SIZE,
                    'md5': DB[0].MD5,
                    'sha1' : DB[0].SHA1,
                    'sha256' : DB[0].SHA256,
                    'plist' : DB[0].INFOPLIST,
                    'bin_name' : DB[0].BINNAME,
                    'id' : DB[0].IDF,
                    'ver' : DB[0].VERSION,
                    'sdk' : DB[0].SDK,
                    'pltfm' : DB[0].PLTFM,
                    'min' : DB[0].MINX,
                    'bin_anal' : DB[0].BIN_ANAL,
                    'libs' : DB[0].LIBS,
                    'files' : python_list(DB[0].FILES),
                    'file_analysis' : DB[0].SFILESX,
                    }
                else:
                    print "[INFO] iOS Binary (IPA) Analysis Started"
                    APP_FILE=MD5 + '.ipa'        #NEW FILENAME
                    APP_PATH=APP_DIR+APP_FILE    #APP PATH
                    BIN_DIR=os.path.join(APP_DIR,"Payload/")
                    #ANALYSIS BEGINS
                    SIZE=str(FileSize(APP_PATH)) + 'MB'   #FILE SIZE
                    SHA1, SHA256= HashGen(APP_PATH)       #SHA1 & SHA256 HASHES
                    print "[INFO] Extracting IPA"
                    Unzip(APP_PATH,APP_DIR)               #EXTRACT IPA
                    FILES,SFILES=iOS_ListFiles(BIN_DIR,MD5,True,'ipa')   #Get Files, normalize + to x, and convert binary plist -> xml
                    INFO_PLIST,BIN_NAME,ID,VER,SDK,PLTFM,MIN,LIBS,BIN_ANAL=BinaryAnalysis(BIN_DIR,TOOLS_DIR,APP_DIR)
                    #Saving to DB
                    print "\n[INFO] Connecting to DB"
                    if RESCAN=='1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerIPA.objects.filter(MD5=MD5).update(TITLE='Static Analysis',APPNAMEX=APP_NAME,SIZE=SIZE,MD5=MD5,SHA1=SHA1,SHA256=SHA256,INFOPLIST=INFO_PLIST,BINNAME=BIN_NAME,IDF=ID,VERSION=VER,SDK=SDK,PLTFM=PLTFM,MINX=MIN,BIN_ANAL=BIN_ANAL,LIBS=LIBS,FILES=FILES,SFILESX=SFILES)
                    elif RESCAN=='0':
                        print "\n[INFO] Saving to Database"
                        STATIC_DB=StaticAnalyzerIPA(TITLE='Static Analysis',APPNAMEX=APP_NAME,SIZE=SIZE,MD5=MD5,SHA1=SHA1,SHA256=SHA256,INFOPLIST=INFO_PLIST,BINNAME=BIN_NAME,IDF=ID,VERSION=VER,SDK=SDK,PLTFM=PLTFM,MINX=MIN,BIN_ANAL=BIN_ANAL,LIBS=LIBS,FILES=FILES,SFILESX=SFILES)
                        STATIC_DB.save()
                    context = {
                    'title' : 'Static Analysis',
                    'name' : APP_NAME,
                    'size' : SIZE,
                    'md5': MD5,
                    'sha1' : SHA1,
                    'sha256' : SHA256,
                    'plist' : INFO_PLIST,
                    'bin_name' : BIN_NAME,
                    'id' : ID,
                    'ver' : VER,
                    'sdk' : SDK,
                    'pltfm' : PLTFM,
                    'min' : MIN,
                    'bin_anal' : BIN_ANAL,
                    'libs' : LIBS,
                    'files' : FILES,
                    'file_analysis' : SFILES,
                    }
                template="ios_binary_analysis.html"
                return render(request,template,context)
            elif TYP=='ios':
                DB=StaticAnalyzerIOSZIP.objects.filter(MD5=MD5)
                if DB.exists() and RESCAN=='0':
                    print "\n[INFO] Analysis is already Done. Fetching data from the DB..."
                    context = {
                    'title' : DB[0].TITLE,
                    'name' : DB[0].APPNAMEX,
                    'size' : DB[0].SIZE,
                    'md5': DB[0].MD5,
                    'sha1' : DB[0].SHA1,
                    'sha256' : DB[0].SHA256,
                    'plist' : DB[0].INFOPLIST,
                    'bin_name' : DB[0].BINNAME,
                    'id' : DB[0].IDF,
                    'ver' : DB[0].VERSION,
                    'sdk' : DB[0].SDK,
                    'pltfm' : DB[0].PLTFM,
                    'min' : DB[0].MINX,
                    'bin_anal' : DB[0].BIN_ANAL,
                    'libs' : DB[0].LIBS,
                    'files' : python_list(DB[0].FILES),
                    'file_analysis' : DB[0].SFILESX,
                    'api' : DB[0].HTML,
                    'insecure' : DB[0].CODEANAL,
                    'urls' : DB[0].URLnFile,
                    'emails' : DB[0].EmailnFile
                    }
                else:
                    print "[INFO] iOS Source Code Analysis Started"
                    APP_FILE=MD5 + '.zip'        #NEW FILENAME
                    APP_PATH=APP_DIR+APP_FILE    #APP PATH
                    #ANALYSIS BEGINS - Already Unzipped
                    print "[INFO] ZIP Already Extracted"
                    SIZE=str(FileSize(APP_PATH)) + 'MB'   #FILE SIZE
                    SHA1, SHA256= HashGen(APP_PATH)       #SHA1 & SHA256 HASHES
                    FILES,SFILES=iOS_ListFiles(APP_DIR,MD5,False,'ios')
                    HTML,CODEANAL,URLnFile,EmailnFile,INFO_PLIST,BIN_NAME,ID,VER,SDK,PLTFM,MIN=iOS_Source_Analysis(APP_DIR,MD5)
                    LIBS,BIN_ANAL='',''
                    #Saving to DB
                    print "\n[INFO] Connecting to DB"
                    if RESCAN=='1':
                        print "\n[INFO] Updating Database..."
                        StaticAnalyzerIOSZIP.objects.filter(MD5=MD5).update(TITLE = 'Static Analysis',
                        APPNAMEX=APP_NAME,
                        SIZE=SIZE,
                        MD5=MD5,
                        SHA1=SHA1,
                        SHA256=SHA256,
                        INFOPLIST=INFO_PLIST,
                        BINNAME=BIN_NAME,
                        IDF=ID,
                        VERSION=VER,
                        SDK=SDK,
                        PLTFM=PLTFM,
                        MINX=MIN,
                        BIN_ANAL=BIN_ANAL,
                        LIBS=LIBS,
                        FILES=FILES,
                        SFILESX=SFILES,
                        HTML=HTML,
                        CODEANAL=CODEANAL,
                        URLnFile=URLnFile,
                        EmailnFile=EmailnFile)
                    elif RESCAN=='0':
                        print "\n[INFO] Saving to Database"
                        STATIC_DB=StaticAnalyzerIOSZIP(TITLE = 'Static Analysis',
                        APPNAMEX=APP_NAME,
                        SIZE=SIZE,
                        MD5=MD5,
                        SHA1=SHA1,
                        SHA256=SHA256,
                        INFOPLIST=INFO_PLIST,
                        BINNAME=BIN_NAME,
                        IDF=ID,
                        VERSION=VER,
                        SDK=SDK,
                        PLTFM=PLTFM,
                        MINX=MIN,
                        BIN_ANAL=BIN_ANAL,
                        LIBS=LIBS,
                        FILES=FILES,
                        SFILESX=SFILES,
                        HTML=HTML,
                        CODEANAL=CODEANAL,
                        URLnFile=URLnFile,
                        EmailnFile=EmailnFile)
                        STATIC_DB.save()
                    context = {
                    'title' : 'Static Analysis',
                    'name' : APP_NAME,
                    'size' : SIZE,
                    'md5': MD5,
                    'sha1' : SHA1,
                    'sha256' : SHA256,
                    'plist' : INFO_PLIST,
                    'bin_name' : BIN_NAME,
                    'id' : ID,
                    'ver' : VER,
                    'sdk' : SDK,
                    'pltfm' : PLTFM,
                    'min' : MIN,
                    'bin_anal' : BIN_ANAL,
                    'libs' : LIBS,
                    'files' : FILES,
                    'file_analysis' : SFILES,
                    'api' : HTML,
                    'insecure' : CODEANAL,
                    'urls' : URLnFile,
                    'emails' : EmailnFile
                    }
                template="ios_source_analysis.html"
                return render(request,template,context)
            else:
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    except Exception as e:
        PrintException("[ERROR] Static Analyzer iOS")
        context = {
        'title' : 'Error',
        'exp' : e.message,
        'doc' : e.__doc__
        }
        template="error.html"
        return render(request,template,context)
def ViewFile(request):
    try:
        print "[INFO] View iOS Files"
        fil=request.GET['file']
        typ=request.GET['type']
        MD5=request.GET['md5']
        mode=request.GET['mode']
        m=re.match('[0-9a-f]{32}',MD5)
        ext=fil.split('.')[-1]
        f=re.search("plist|db|sqlitedb|sqlite|txt|m",ext)
        if m and f and re.findall('xml|db|txt|m',typ) and re.findall('ios|ipa',mode):
            if (("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil)):
                return HttpResponseRedirect('/error/')
            else:
                if mode=='ipa':
                    SRC=os.path.join(settings.UPLD_DIR, MD5+'/Payload/')
                elif mode=='ios':
                    SRC=os.path.join(settings.UPLD_DIR, MD5+'/')
                sfile=os.path.join(SRC,fil)
                dat=''
                if typ=='m':
                    format='cpp'
                    with io.open(sfile,mode='r',encoding="utf8",errors="ignore") as f:
                        dat=f.read()
                elif typ=='xml':
                    format='xml'
                    with io.open(sfile,mode='r',encoding="utf8",errors="ignore") as f:
                        dat=f.read()
                elif typ=='db':
                    format='plain'
                    dat=HandleSqlite(sfile)
                elif typ=='txt':
                    format='plain'
                    APP_DIR=os.path.join(settings.UPLD_DIR, MD5+'/')
                    FILE=os.path.join(APP_DIR,"classdump.txt")
                    with io.open(FILE,mode='r',encoding="utf8",errors="ignore") as f:
                        dat=f.read()
        else:
            return HttpResponseRedirect('/error/')
        context = {'title': escape(ntpath.basename(fil)),
                   'file': escape(ntpath.basename(fil)),
                   'type': format,
                   'dat' : dat}
        template="view.html"
        return render(request,template,context)
    except:
        PrintException("[ERROR] View iOS File")
        return HttpResponseRedirect('/error/')
def readBinXML(FILE):
    try:
        args=['plutil','-convert','xml1',FILE]
        dat=subprocess.check_output(args)
        with io.open(FILE,mode='r',encoding="utf8",errors="ignore") as f:
            dat=f.read() 
        return dat
    except:
        PrintException("[ERROR] Converting Binary XML to Readable XML")
        
def HandleSqlite(SFile):
    try:
        print "[INFO] Dumping SQLITE Database"
        data=''
        con = sq.connect(SFile)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables=cur.fetchall()
        for table in tables:
            data+= "\nTABLE: "+str(table[0]).decode('utf8', 'ignore')+" \n=====================================================\n"
            cur.execute("PRAGMA table_info('%s')" % table)
            rows=cur.fetchall()
            head=''
            for r in rows:
                head+=str(r[1]).decode('utf8', 'ignore') + " | "
            data+=head + " \n=====================================================================\n"
            cur.execute("SELECT * FROM '%s'" % table)
            rows=cur.fetchall()
            for r in rows:
                dat=''
                for x in r:
                    dat+=str(x).decode('utf8', 'ignore') + " | "
                data+=dat+"\n"
        return data
    except:
        PrintException("[ERROR] Dumping SQLITE Database")
        pass

def iOS_ListFiles(SRC,MD5,BIN,MODE):
    try:
        print "[INFO] Get Files, BIN Plist -> XML, and Normalize"
        #Multi function, Get Files, BIN Plist -> XML, normalize + to x
        filez=[]
        certz=''
        sfiles=''
        db=''
        plist=''
        certz=''
        for dirName, subDir, files in os.walk(SRC):
            for jfile in files:
                if not jfile.endswith(".DS_Store"):
                    file_path=os.path.join(SRC,dirName,jfile)
                    if "+" in jfile:
                        plus2x=os.path.join(SRC,dirName,jfile.replace("+","x"))
                        shutil.move(file_path,plus2x)
                        file_path=plus2x
                    fileparam=file_path.replace(SRC,'')
                    filez.append(fileparam)
                    ext=jfile.split('.')[-1]
                    if re.search("cer|pem|cert|crt|pub|key|pfx|p12", ext):
                        certz+=escape(file_path.replace(SRC,'')) + "</br>"
                    if re.search("db|sqlitedb|sqlite", ext):
                        db+="<a href='../ViewFile/?file="+escape(fileparam)+"&type=db&mode="+MODE+"&md5="+MD5+"''> "+escape(fileparam)+" </a></br>"
                    if jfile.endswith(".plist"):
                        if BIN:
                            readBinXML(file_path)
                        plist+="<a href='../ViewFile/?file="+escape(fileparam)+"&type=xml&mode="+MODE+"&md5="+MD5+"''> "+escape(fileparam)+" </a></br>"
        if len(db)>1:
            db="<tr><td>SQLite Files</td><td>"+db+"</td></tr>"   
            sfiles+=db
        if len(plist)>1:
            plist="<tr><td>Plist Files</td><td>"+plist+"</td></tr>"
            sfiles+=plist
        if len(certz)>1:
            certz="<tr><td>Certificate/Key Files Hardcoded inside the App.</td><td>"+certz+"</td><tr>"
            sfiles+=certz
        return filez,sfiles
    except:
        PrintException("[ERROR] iOS List Files")
        
def BinaryAnalysis(SRC,TOOLS_DIR,APP_DIR):
    try:
        print "[INFO] Starting Binary Analysis"
        dirs = os.listdir(SRC)
        for d in dirs:
            if d.endswith(".app"):
                    break
        BIN_DIR=os.path.join(SRC,d)         #Full Dir/Payload/x.app
        XML_FILE=os.path.join(BIN_DIR,"Info.plist")
        BIN=d.replace(".app","") 
        BIN_NAME=BIN
        ID=""
        VER=""
        SDK=""
        PLTFM=""
        MIN=""
        XML=""
        
        try:
            print "[INFO] Reading Info.plist"
            XML=readBinXML(XML_FILE)
            p=plistlib.readPlistFromString(XML)
            BIN_NAME = BIN = ID = VER = SDK = PLTFM = MIN = ""
            if "CFBundleDisplayName" in p:
                BIN_NAME=p["CFBundleDisplayName"]
            if "CFBundleExecutable" in p:
                BIN=p["CFBundleExecutable"]
            if "CFBundleIdentifier" in p:
                ID=p["CFBundleIdentifier"]
            if "CFBundleVersion" in p:
                VER=p["CFBundleVersion"]
            if "DTSDKName" in p:
                SDK=p["DTSDKName"]
            if "DTPlatformVersion" in p:
                PLTFM=p["DTPlatformVersion"]
            if "MinimumOSVersion" in p:
                MIN=p["MinimumOSVersion"]
            
        except:
            PrintException("[ERROR] - Reading from Info.plist")
            pass

        BIN_PATH=os.path.join(BIN_DIR,BIN)  #Full Dir/Payload/x.app/x
        print "[INFO] iOS Binary : " + BIN
        print "[INFO] Running otool against the Binary"
        #Libs Used
        LIBS=''
        args=['otool','-L',BIN_PATH]
        dat=subprocess.check_output(args)
        dat=escape(dat.replace(BIN_DIR + "/",""))
        LIBS=dat.replace("\n","</br>")
        #PIE
        args=['otool','-hv',BIN_PATH]
        dat=subprocess.check_output(args)
        if "PIE" in dat:
            PIE= "<tr><td><strong>fPIE -pie</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Position Independent Executable (PIE) flag. This enables Address Space Layout Randomization (ASLR), a memory protection mechanism for exploit mitigation.</td></tr>"
        else:
            PIE="<tr><td><strong>fPIE -pie</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Position Independent Executable (PIE) flag. So Address Space Layout Randomization (ASLR) is missing. ASLR is a memory protection mechanism for exploit mitigation.</td></tr>"
        #Stack Smashing Protection & ARC
        args=['otool','-Iv',BIN_PATH]
        dat=subprocess.check_output(args)
        if "stack_chk_guard" in dat:
            SSMASH="<tr><td><strong>fstack-protector-all</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Stack Smashing Protector (SSP) flag and is having protection against Stack Overflows/Stack Smashing Attacks.</td></tr>"
        else:
            SSMASH= "<tr><td><strong>fstack-protector-all</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to Stack Overflows/Stack Smashing Attacks.</td></tr>"
        #ARC
        if "_objc_release" in dat:
            ARC="<tr><td><strong>fobjc-arc</strong> flag is Found</td><td><span class='label label-success'>Secure</span></td><td>App is compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and is an exploit mitigation mechanism against memory corruption vulnerabilities.</td></tr>"
        else:
            ARC="<tr><td><strong>fobjc-arc</strong> flag is not Found</td><td><span class='label label-danger'>Insecure</span></td><td>App is not compiled with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and protects from memory corruption vulnerabilities.</td></tr>"
        ##########
        BANNED_API=''
        x=re.findall("alloca|gets|memcpy|scanf|sprintf|sscanf|strcat|StrCat|strcpy|StrCpy|strlen|StrLen|strncat|StrNCat|strncpy|StrNCpy|strtok|swprintf|vsnprintf|vsprintf|vswprintf|wcscat|wcscpy|wcslen|wcsncat|wcsncpy|wcstok|wmemcpy",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            BANNED_API="<tr><td>Binary make use of banned API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may contain the following banned API(s) </br><strong>" + str(x) + "</strong>.</td></tr>"
        WEAK_CRYPTO=''
        x=re.findall("kCCAlgorithmDES|kCCAlgorithm3DES||kCCAlgorithmRC2|kCCAlgorithmRC4|kCCOptionECBMode|kCCOptionCBCMode",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            WEAK_CRYPTO="<tr><td>Binary make use of some Weak Crypto API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following weak crypto API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        CRYPTO=''
        x=re.findall("CCKeyDerivationPBKDF|CCCryptorCreate|CCCryptorCreateFromData|CCCryptorRelease|CCCryptorUpdate|CCCryptorFinal|CCCryptorGetOutputLength|CCCryptorReset|CCCryptorRef|kCCEncrypt|kCCDecrypt|kCCAlgorithmAES128|kCCKeySizeAES128|kCCKeySizeAES192|kCCKeySizeAES256|kCCAlgorithmCAST|SecCertificateGetTypeID|SecIdentityGetTypeID|SecKeyGetTypeID|SecPolicyGetTypeID|SecTrustGetTypeID|SecCertificateCreateWithData|SecCertificateCreateFromData|SecCertificateCopyData|SecCertificateAddToKeychain|SecCertificateGetData|SecCertificateCopySubjectSummary|SecIdentityCopyCertificate|SecIdentityCopyPrivateKey|SecPKCS12Import|SecKeyGeneratePair|SecKeyEncrypt|SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify|SecKeyGetBlockSize|SecPolicyCopyProperties|SecPolicyCreateBasicX509|SecPolicyCreateSSL|SecTrustCopyCustomAnchorCertificates|SecTrustCopyExceptions|SecTrustCopyProperties|SecTrustCopyPolicies|SecTrustCopyPublicKey|SecTrustCreateWithCertificates|SecTrustEvaluate|SecTrustEvaluateAsync|SecTrustGetCertificateCount|SecTrustGetCertificateAtIndex|SecTrustGetTrustResult|SecTrustGetVerifyTime|SecTrustSetAnchorCertificates|SecTrustSetAnchorCertificatesOnly|SecTrustSetExceptions|SecTrustSetPolicies|SecTrustSetVerifyDate|SecCertificateRef|SecIdentityRef|SecKeyRef|SecPolicyRef|SecTrustRef",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            CRYPTO="<tr><td>Binary make use of the following Crypto API(s)</td><td><span class='label label-info'>Info</span></td><td>The binary may use the following crypto API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        WEAK_HASH=''
        x=re.findall("CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            WEAK_HASH="<tr><td>Binary make use of the following Weak HASH API(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following weak hash API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        HASH=''
        x=re.findall("CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            HASH="<tr><td>Binary make use of the following HASH API(s)</td><td><span class='label label-info'>Info</span></td><td>The binary may use the following hash API(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        RAND=''
        x=re.findall("srand|random",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            RAND="<tr><td>Binary make use of the insecure Random Function(s)</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use the following insecure Random Function(s)</br><strong>" + str(x) + "</strong>.</td></tr>"
        LOG=''
        x=re.findall("NSLog",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            LOG="<tr><td>Binary make use of Logging Function</td><td><span class='label label-info'>Info</span></td><td>The binary may use <strong>NSLog</strong> function for logging.</td></tr>"
        MALL=''
        x=re.findall("malloc",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            MALL="<tr><td>Binary make use of <strong>malloc</strong> Function</td><td><span class='label label-danger'>Insecure</span></td><td>The binary may use <strong>malloc</strong> function instead of <strong>calloc</strong>.</td></tr>"
        DBG=''
        x=re.findall("ptrace",dat)
        x=list(set(x))
        x=', '.join(x)
        if len(x)>1:
            DBG="<tr><td>Binary calls <strong>ptrace</strong> Function for anti-debugging.</td><td><span class='label label-success'>Secure</span></td><td>The binary may use <strong>ptrace</strong> function. It is used to detect and prevent debuggers.</td></tr>"
        else:
            DBG="<tr><td>Binary does not call <strong>ptrace</strong> Function for anti-debugging.</td><td><span class='label label-warning'>Warning</span></td><td>The binary does not use <strong>ptrace</strong> function. It is used to detect and prevent debuggers.</td></tr>"
        CDUMP=''
        WVIEW=''
        try:
            print "[INFO] Running class-dump-z against the Binary"
            CLASSDUMPZ_BIN=os.path.join(TOOLS_DIR,'class-dump-z')
            subprocess.call(["chmod", "777", CLASSDUMPZ_BIN])
            dat=subprocess.check_output([CLASSDUMPZ_BIN,BIN_PATH])
            CDUMP=dat
            FILE=os.path.join(APP_DIR,"classdump.txt")
            with open(FILE,"w") as f:
                f.write(CDUMP)
            if "UIWebView" in CDUMP:
                WVIEW="<tr><td>Binary uses WebView Component.</td><td><span class='label label-info'>Info</span></td><td>The binary may use WebView Component.</td></tr>"
       
        except:
            PrintException("[ERROR] - Cannot perform class dump")
            pass

        BIN_RES=PIE+SSMASH+ARC+BANNED_API+WEAK_CRYPTO+CRYPTO+WEAK_HASH+HASH+RAND+LOG+MALL+DBG+WVIEW
        #classdump
        return XML,BIN_NAME,ID,VER,SDK,PLTFM,MIN,LIBS,BIN_RES
    except:
        PrintException("[ERROR] iOS Binary Analysis")
        
def iOS_Source_Analysis(SRC,MD5):
    try:
        print "[INFO] Starting iOS Source Code and PLIST Analysis"
        APP=''
        InfoP=''
        BIN_NAME=''
        BIN=''
        ID=''
        VER=''
        SDK=''
        PLTFM=''
        MIN=''
        XML=''
        for f in os.listdir(SRC):
            if f.endswith(".xcodeproj"):
                APP=f.replace(".xcodeproj","")
        PlistFile=APP+"-Info.plist"
        for dirName, subDir, files in os.walk(SRC):
            for jfile in files:
                if PlistFile in jfile:
                    InfoP=os.path.join(SRC,dirName,jfile)
                    break
        with io.open(InfoP, mode='r',encoding="utf8",errors="ignore") as f:
            XML=f.read()
        p=plistlib.readPlistFromString(XML)
        BIN_NAME=p["CFBundleDisplayName"]
        BIN=p["CFBundleExecutable"] 
        ID=p["CFBundleIdentifier"]
        VER=p["CFBundleVersion"]
        SDK=''#p["DTSDKName"]
        PLTFM=''#p["DTPlatformVersion"]
        MIN=''#p["MinimumOSVersion"]

        #Code Analysis
        EmailnFile=''
        URLnFile=''
        c = {key: [] for key in ('i_buf','webv','i_log','net','i_sqlite','fileio')}
        for dirName, subDir, files in os.walk(SRC):
            for jfile in files:
                if jfile.endswith(".m"):

                    jfile_path=os.path.join(SRC,dirName,jfile)
                    if "+" in jfile:
                        p2=os.path.join(SRC,dirName,jfile.replace("+","x"))
                        shutil.move(jfile_path,p2)
                        jfile_path=p2
                    repath=dirName.replace(SRC,'')
                    dat=''
                    with io.open(jfile_path,mode='r',encoding="utf8",errors="ignore") as f:
                        dat=f.read()
                    
                    URLS=[]
                    EMAILS=[]

                    #API
                    if (re.findall("NSURL|CFStream|NSStream",dat)):
                        c['net'].append(jfile_path.replace(SRC,''))
                    if (re.findall("Keychain|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete", dat)):
                        c['fileio'].append(jfile_path.replace(SRC,''))
                    if (re.findall("WebView|UIWebView",dat)):
                        c['webv'].append(jfile_path.replace(SRC,''))
                    #CODE-ISSUES
                    if (re.findall("strcpy|memcpy|strcat|strncat|strncpy|sprintf|vsprintf|gets",dat)):
                        c['i_buf'].append(jfile_path.replace(SRC,''))
                    if (re.findall("NSLog",dat)):
                        c['i_log'].append(jfile_path.replace(SRC,''))
                    if (re.findall("sqlite3_exec",dat)):
                        c['i_sqlite'].append(jfile_path.replace(SRC,''))
        
                    fl=jfile_path.replace(SRC,'')
                    base_fl=ntpath.basename(fl)
                    #URLs My Custom regex
                    p = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE) 
                    urllist=re.findall(p, dat.lower())
                    uflag=0
                    for url in urllist:
                        if url not in URLS:
                            URLS.append(url)
                            uflag=1
                    if uflag==1:
                        URLnFile+="<tr><td>" + "<br>".join(URLS) + "</td><td><a href='../ViewFile/?file=" + escape(fl)+"&type=m&mode=ios&md5="+MD5+"'>"+escape(base_fl)+"</a></td></tr>"
                    
                    #Email Etraction Regex
                    
                    regex = re.compile("[\w.-]+@[\w-]+\.[\w.]+")
                    eflag=0
                    for email in regex.findall(dat.lower()):
                        if ((email not in EMAILS) and (not email.startswith('//'))):
                            EMAILS.append(email)
                            eflag=1
                    if eflag==1:
                        EmailnFile+="<tr><td>" + "<br>".join(EMAILS) + "</td><td><a href='../ViewFile/?file=" + escape(fl)+"&type=m&mode=ios&md5="+MD5+"'>"+escape(base_fl)+"</a></td></tr>"
        print "[INFO] Finished Code Analysis, Email and URL Extraction"
        dc={'webv' : 'WebView Component',
            'net' : 'Network Calls',
            'fileio' : 'Local File I/O Operations.',
            }
        html=''
        for ky in dc:
            if c[ky]:
                link=''
                hd="<tr><td>"+dc[ky]+"</td><td>"
                for l in c[ky]:
                    link+="<a href='../ViewFile/?file="+ escape(l) +"&type=m&mode=ios&md5="+MD5+"'>"+escape(ntpath.basename(l))+"</a> "
                html+=hd+link+"</td></tr>"
        dg={'i_buf' : 'The App may contain banned API(s). These API(s) are insecure and must not be used.',
            'i_log' : 'The App logs information. Sensitive information should never be logged.',
            'i_sqlite' : 'App uses SQLite Database. Sensitive Information should be encrypted.',
            }
        dang=''
        spn_dang='<span class="label label-danger">high</span>'
        spn_info='<span class="label label-info">info</span>'
        spn_sec='<span class="label label-success">secure</span>'
        for k in dg:
            if c[k]:
                link=''
                if (re.findall('i_sqlite',k)):
                    hd='<tr><td>'+dg[k]+'</td><td>'+spn_info+'</td><td>'
                else:
                    hd='<tr><td>'+dg[k]+'</td><td>'+spn_dang+'</td><td>'

                for ll in c[k]:
                    link+="<a href='../ViewFile/?file="+ escape(ll) +"&type=m&mode=ios&md5="+MD5+"'>"+escape(ntpath.basename(ll))+"</a> "

                dang+=hd+link+"</td></tr>"

        return html,dang,URLnFile,EmailnFile,XML,BIN_NAME,ID,VER,SDK,PLTFM,MIN
    except:
        PrintException("[ERROR] iOS Source Code Analysis")
        

