from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
import re,os, glob,hashlib, zipfile, subprocess,ntpath
from xml.dom import minidom
from tools.apkinfo import apk, dvm, analysis
from tools.apkinfo.behaviour import *
from ast import literal_eval
def Java(request):
    try:
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m:
            MD5=request.GET['md5']
            SRC=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/java_source/')
            html=''
            for dirName, subDir, files in os.walk(SRC):
                for jfile in files:
                    file_path=os.path.join(SRC,dirName,jfile)
                    fileparam=file_path.replace(SRC,'')
                    html+="<tr><td><a href='../ViewSource/?file="+fileparam+"&md5="+MD5+"'>"+fileparam+"</a></td></tr>"
        context = {'title': 'Java Source',
                    'files': html,}
        template="java.html"
        return render(request,template,context)
    except:
        return HttpResponseRedirect('/error/')
def Smali(request):
    try:
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m:
            MD5=request.GET['md5']
            SRC=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/smali_source/')
            html=''
            for dirName, subDir, files in os.walk(SRC):
                for jfile in files:
                    file_path=os.path.join(SRC,dirName,jfile)
                    fileparam=file_path.replace(SRC,'')
                    html+="<tr><td><a href='../ViewSource/?file="+fileparam+"&md5="+MD5+"'>"+fileparam+"</a><td><tr>"
        context = {'title': 'Smali Source',
                    'files': html,}
        template="smali.html"
        return render(request,template,context)
    except:
        return HttpResponseRedirect('/error/')
def ViewSource(request):
    try:

        fil=''
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m and (request.GET['file'].endswith('.java') or request.GET['file'].endswith('.smali')):
            fil=request.GET['file']
            MD5=request.GET['md5']
            if fil.endswith('.java'):
                SRC=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/java_source/')
            elif fil.endswith('.smali'):
                SRC=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/smali_source/')
            sfile=SRC+fil
            dat=''
            with open(sfile,'r') as f:
                dat=f.read()
        dat=dat.decode("windows-1252").encode("utf8")
        context = {'title': ntpath.basename(fil),
                   'file': ntpath.basename(fil),
                   'dat': dat}
        template="view_source.html"
        return render(request,template,context)
    except:
        return HttpResponseRedirect('/error/')
                
        
def StaticAnalyzer(request):
    #try:
    #Input validation
    m=re.match('[0-9a-f]{32}',request.GET['checksum'])
    if m and request.GET['name'].endswith('.apk'):
        DIR=settings.BASE_DIR        #BASE DIR
        APP_NAME=request.GET['name'] #APP ORGINAL NAME
        MD5=request.GET['checksum']  #MD5
        APP_DIR=os.path.join(DIR,'uploads/'+MD5+'/') #APP DIRECTORY
        APP_FILE=MD5 + '.apk'        #NEW FILENAME
        APP_PATH=APP_DIR+APP_FILE    #APP PATH
        TOOLS_DIR=os.path.join(DIR, 'StaticAnalyzer/tools/')  #TOOLS DIR
        #ANALYSIS BEGINS
        SIZE=str(FileSize(APP_PATH)) + 'MB'   #FILE SIZE
        SHA1, SHA256= HashGen(APP_PATH)       #SHA1 & SHA256 HASHES
        Unzip(APP_PATH,APP_DIR)               #EXTRACT APK
        a=ApkInfo(APP_PATH)                   #GET APK INFOS
        PACKAGENAME=a.get_package()           #GET PACKAGE NAME
        MAINACTIVITY =a.get_main_activity()   #GET MAIN ACTIVITY NAME
        TARGET_SDK =a.get_target_sdk_version()
        MAX_SDK=a.get_max_sdk_version()
        MIN_SDK=a.get_min_sdk_version()
        ANDROVERNAME=a.get_androidversion_name()
        ANDROVER= a.get_androidversion_code()
        PERMISSIONS =FormatPermissions(a.get_details_permissions())
        FILES = a.get_files()
        MANIFEST_ANAL=ManifestAnalysis(a.get_AndroidManifest())
        ACTIVITIES =a.get_activities()
        PROVIDERS =a.get_providers()
        RECEIVERS =a.get_receivers()
        SERVICES =a.get_services()
        LIBRARIES= a.get_libraries()
        CNT_ACT =len(ACTIVITIES)
        CNT_PRO =len(PROVIDERS)
        CNT_SER =len(SERVICES)
        b,c=CodeBehaviour(a)
        NATIVE=b['native']
        DYNAMIC=b['dynamic']
        REFLECTION=b['reflection']
        TELELEAK=c['teleleak']
        SETTINGSHARV =c['settingsleak']
        LOCLOOK = c['loc']
        INTERFACE = c['inter']
        TELEABUSE= c['teleabuse']
        AVEVAS = c['videvo']
        SUSPCONN = c['suspconn']
        PIMLEAK= c['pimleak']
        CODEEXEC = c['codeexec']
        CERT_INFO=CertInfo(APP_DIR,TOOLS_DIR).replace('\n', '</br>')
        Dex2Jar(APP_DIR,TOOLS_DIR)
        Dex2Smali(APP_DIR,TOOLS_DIR)
        Jar2Java(APP_DIR,TOOLS_DIR)
        API,DANG,URLS,EMAILS,CRYPTO,OBFUS=CodeAnalysis(APP_DIR,MD5,PERMISSIONS)
        GenDownloads(APP_DIR,MD5)
        STRINGS=Strings(APP_FILE,APP_DIR,TOOLS_DIR)
        
    else:
         return HttpResponseRedirect('/error/')
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
        'activities' : ACTIVITIES,
        'receivers' : RECEIVERS,
        'providers' : PROVIDERS,
        'services' : SERVICES,
        'libraries' : LIBRARIES,
        'act_count' : CNT_ACT,
        'prov_count' : CNT_PRO,
        'serv_count' : CNT_SER,
        'certinfo': CERT_INFO,
        'native' : NATIVE,
        'dynamic' : DYNAMIC,
        'reflection' : REFLECTION,
        'crypto': CRYPTO,
        'obfus': OBFUS,
        'teleleak' : TELELEAK,
        'settingsleak' : SETTINGSHARV,
        'loc' : LOCLOOK,
        'inter' : INTERFACE,
        'teleabuse' : TELEABUSE,
        'videvo' : AVEVAS,
        'suspconn' : SUSPCONN,
        'pimleak' : PIMLEAK,
        'codeexec' : CODEEXEC,
        'api': API,
        'dang': DANG,
        'urls': URLS,
        'emails': EMAILS,
        'strings': STRINGS,
        }
    template="static_analysis.html"
    return render(request,template,context)
'''
    except Exception as e:
        context = {
        'title' : 'Error',
        'exp' : e.message,
        'doc' : e.__doc__
        }
        template="error.html"
        return render(request,template,context)
'''
def HashGen(APP_PATH):
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    BLOCKSIZE = 65536
    with open(APP_PATH, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            sha1.update(buf)
            sha256.update(buf)
            buf = afile.read(BLOCKSIZE)
    sha1val = sha1.hexdigest()
    sha256val=sha256.hexdigest()
    return sha1val, sha256val
def FileSize(APP_PATH): return round(float(os.path.getsize(APP_PATH)) / (1024 * 1024),2)
def GenDownloads(APP_DIR,MD5):
    #For Java
    DIR=os.path.join(APP_DIR,'java_source/')
    DWD=os.path.join(settings.BASE_DIR,'static/downloads/') + MD5 + '-java.zip'
    zipf = zipfile.ZipFile(DWD, 'w')
    zipdir(DIR, zipf)
    zipf.close()
    #For Smali
    DIR=os.path.join(APP_DIR,'smali_source/')
    DWD=os.path.join(settings.BASE_DIR,'static/downloads/') + MD5 + '-smali.zip'
    zipf = zipfile.ZipFile(DWD, 'w')
    zipdir(DIR, zipf)
    zipf.close()
def zipdir(path, zip):
    for root, dirs, files in os.walk(path):
        for file in files:
            zip.write(os.path.join(root, file))
def Unzip(APP_PATH, EXT_PATH):
    with zipfile.ZipFile(APP_PATH, "r") as z:
            z.extractall(EXT_PATH)
def ApkInfo(APP_PATH):
    a=apk.APK(APP_PATH)
    if a.is_valid_APK():
        return a
def FormatPermissions(PERMISSIONS):
    DESC=''
    for ech in PERMISSIONS:
        DESC=DESC + '<tr><td>' + ech + '</td>'
        for l in PERMISSIONS[ech]:
            DESC= DESC + '<td>' + l + '</td>'
        DESC= DESC+ '</tr>'
    DESC=DESC.replace('dangerous','<span class="label label-danger">dangerous</span>').replace('normal','<span class="label label-info">normal</span>').replace('signatureOrSystem','<span class="label label-warning">SignatureOrSystem</span>').replace('signature','<span class="label label-success">signature</span>')
    return DESC
def CodeBehaviour(apk):
    vm = dvm.DalvikVMFormat( apk.get_dex() )
    vmx = analysis.uVMAnalysis( vm )
    x = analysis.VMAnalysis( vm )
    
    cod = {'native': analysis.is_native_code(vmx), 'dynamic': analysis.is_native_code(vmx), 'reflection': analysis.is_reflection_code(vmx) }
    try:
        pimleak=gather_PIM_data_leakage(x)
    except:
        pimleak=['Analysis Failed']
        pass
    try:
        teleleak=gather_telephony_identifiers_leakage(x)
    except:
        teleleak=['Analysis Failed']
        pass
    try:
        settingsleak=gather_device_settings_harvesting(x)
    except:
        settingsleak=['Analysis Failed']
        pass
    try:
        loc=gather_location_lookup(x)
    except:
        loc=['Analysis Failed']
        pass
    try:
        inter=gather_connection_interfaces_exfiltration(x)
    except:
        inter=['Analysis Failed']
    try:
        teleabuse=gather_telephony_services_abuse(apk,x)
    except:
        teleabuse=['Analysis Failed']
    try:
        videvo=gather_audio_video_eavesdropping(x)
    except:
        videvo = ['Analysis Failed']
    try:
        suspconn=gather_suspicious_connection_establishment(x)
    except:
        suspconn=['Analysis Failed']
    try:
        codeexec=gather_code_execution(x)
    except:
        codeexec =['Analysis Failed']
        
        
    
    beh = {'pimleak': pimleak,'teleleak': teleleak,'settingsleak':settingsleak,
           'loc': loc,'inter':inter,'teleabuse': teleabuse,
           'videvo': videvo,'suspconn': suspconn,'codeexec': codeexec}
    return cod,beh
'''
    for i in vmx.get_methods() :
      i.create_tags()
      if not i.tags.empty() :
        print i.method.get_class_name(), i.method.get_name(), i.tags
'''

def CertInfo(APP_DIR,TOOLS_DIR):
    cert=os.path.join(APP_DIR,'META-INF/')
    os.chdir(cert)
    certname=''
    for f in glob.glob("*.rsa"):
        certname=f
    if len(certname) < 2:
        for f in glob.glob("*.dsa"):
            certname=f    
    cert=cert+certname
    args=[TOOLS_DIR+'keytool.exe','-printcert', '-file', cert]
    return subprocess.check_output(args)


def Dex2Jar(APP_DIR,TOOLS_DIR):
    D2J=os.path.join(TOOLS_DIR,'d2j/') +'d2j-dex2jar.bat'
    args=[D2J,APP_DIR+'classes.dex','-o',APP_DIR +'classes.jar']
    subprocess.call(args)
def Dex2Smali(APP_DIR,TOOLS_DIR):
    DEX_PATH=APP_DIR+'classes.dex'
    BS_PATH=TOOLS_DIR+ 'baksmali.jar'
    OUTPUT=os.path.join(APP_DIR,'smali_source/')
    args=[settings.JAVA_PATH+'java','-jar',BS_PATH,DEX_PATH,'-o',OUTPUT]
    subprocess.call(args)
    
def Jar2Java(APP_DIR,TOOLS_DIR):
    JAR_PATH=APP_DIR + 'classes.jar'
    JD_PATH=TOOLS_DIR + 'jd-core.jar'
    OUTPUT=os.path.join(APP_DIR, 'java_source/')
    args=[settings.JAVA_PATH+'java','-jar', JD_PATH, JAR_PATH,OUTPUT]
    subprocess.call(args)
def Strings(APP_FILE,APP_DIR,TOOLS_DIR):
    strings=TOOLS_DIR+'strings_from_apk.jar'
    args=[settings.JAVA_PATH+'java','-jar',strings,APP_DIR+APP_FILE,APP_DIR]
    subprocess.call(args)
    dat=''
    try:
        with open(APP_DIR+'strings.json','r') as f:
            dat=f.read()
    except:
        pass
    dat=dat[1:-1].split(",")
    return dat
def ManifestAnalysis(mfxml):
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
    ##SERVICES  
    ##search for services without permissions set
    #if a service is exporeted and has no permission
    #nor an intent filter, flag it
    for service in services:    
        if service.getAttribute("android:exported") == 'true':
            perm = ''
            if service.getAttribute("android:permission"):
                #service permission exists
                perm =' (permission '+service.getAttribute("android:permission")+' exists.) '
            servicename = service.getAttribute("android:name")
            if servicename.startswith('.'):
                servicename=(package+servicename).replace('..','.')
            RET=RET +'<tr><td>Service (' + servicename + ') is not Protected.'+perm+' <br>[android:exported=true]</td><td><span class="label label-danger">high</span></td><td> A service was found to be shared with other apps on the device without an intent filter or a permission requirement therefore leaving it accessible to any other application on the device.</td></tr>'

    ##APPLICATIONS
    for application in applications:
        
        if application.getAttribute("android:debuggable") == "true":
            RET=RET+ '<tr><td>Debug Enabled For App <br>[android:debuggable=true]</td><td><span class="label label-danger">high</span></td><td>Debugging was enabled on the app which makes it easier for reverse engineers to hook a debugger to it. This allows dumping a stack trace and accessing debugging helper classes.</td></tr>' 
        
        if application.getAttribute("android:allowBackup") =="true":
            RET=RET+ '<tr><td>Application Data can be Backed up<br>[android:allowBackup=true]</td><td><span class="label label-warning">medium</span></td><td>This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.</td></tr>'
        elif application.getAttribute("android:allowBackup") =="false":
            pass
        else:
            RET=RET+ '<tr><td>Application Data can be Backed up<br>[android:allowBackup] flag is missing.</td><td><span class="label label-warning">medium</span></td><td>The flag [android:allowBackup] should be set to false. By default it is set to true and allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.</td></tr>'
        if application.getAttribute("android:testOnly")== "true":
            RET=RET+ '<tr><td>Application is in Test Mode <br>[android:testOnly=true]</td><td><span class="label label-danger">high</span></td><td> It may expose functionality or data outside of itself that would cause a security hole.</td></tr>'
        for node in application.childNodes:
            ad=''
            if node.nodeName == 'activity':
                itmname= 'Activity'
                ad='n'
            elif node.nodeName == 'provider':
                itmname = 'Content Provider'
            elif node.nodeName == 'receiver':
                itmname = 'Broadcast Receiver'
            else:
                itmname = 'NIL'
            if ('NIL' != itmname) and (node.getAttribute("android:exported") == 'true'):
                perm=''
                if node.getAttribute("android:permission"):
                    #permission exists
                    perm = ' (permission '+node.getAttribute("android:permission")+' exists.) '
                item=node.getAttribute("android:name")
                if item.startswith('.'):
                    item=(package+item).replace('..','.')                                                         
                RET=RET +'<tr><td>'+itmname+' (' + item + ') is not Protected.'+perm+' <br>[android:exported=true]</td><td><span class="label label-danger">high</span></td><td> A'+ad+' '+itmname+' was found to be shared with other apps on the device without an intent filter or a permission requirement therefore leaving it accessible to any other application on the device.</td></tr>'
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
    return RET


def CodeAnalysis(APP_DIR,MD5,PERMS):
    c = {key: [] for key in ('d_webviewdisablessl','d_webviewdebug','d_sensitive','d_ssl','d_sqlite','d_con_world_readable','d_con_world_writable','d_con_private','d_extstorage','d_jsenabled','gps','crypto','exec','server_socket','socket','datagramp','datagrams','ipc','msg','webview_addjs','webview','webviewget','webviewpost','httpcon','urlcon','jurl','httpsurl','nurl','httpclient','notify','cellinfo','cellloc','subid','devid','softver','simserial','simop','opname','contentq','refmethod','obf','gs','bencode','bdecode','dex','mdigest')}
    crypto=False
    obfus=False
    EmailnFile=''
    URLnFile=''
    JS=os.path.join(APP_DIR, 'java_source/')
    for dirName, subDir, files in os.walk(JS):
        for jfile in files:
            jfile_path=os.path.join(JS,dirName,jfile)
            repath=dirName.replace(JS,'')
            if jfile.endswith('.java') and not (repath.startswith('android\\') or repath.startswith('com\\google\\')) :
                with open(jfile_path,'r') as f:
                    dat=f.read()
                #Initialize
                URLS=[]
                EMAILS=[]
                #Insecure Coding
                if (('MODE_WORLD_READABLE') in dat or ('Context.MODE_WORLD_READABLE') in dat):
                    c['d_con_world_readable'].append(jfile_path.replace(JS,''))
                if (('MODE_WORLD_WRITABLE') in dat or ('Context.MODE_WORLD_WRITABLE') in dat):
                    c['d_con_world_writable'].append(jfile_path.replace(JS,''))
                if (('MODE_PRIVATE') in dat or ('Context.MODE_PRIVATE') in dat):
                    c['d_con_private'].append(jfile_path.replace(JS,''))
                if ((('WRITE_EXTERNAL_STORAGE') in PERMS) and (('.getExternalStorage') in dat or ('.getExternalFilesDir(') in dat)):
                    c['d_extstorage'].append(jfile_path.replace(JS,''))
                if (('setJavaScriptEnabled(true)') in dat and ('.addJavascriptInterface(') in dat ):
                    c['d_jsenabled'].append(jfile_path.replace(JS,''))
                if (('.setWebContentsDebuggingEnabled(true)') in dat and ('WebView') in dat ):
                    c['d_webviewdebug'].append(jfile_path.replace(JS,''))
                if (('onReceivedSslError(WebView') in dat and ('.proceed();') in dat ):
                    c['d_webviewdisablessl'].append(jfile_path.replace(JS,''))  
                if ((('rawQuery(') in dat or ('query(') in dat or ('SQLiteDatabase') in dat) and (('android.database.sqlite.') in dat)):
                    c['d_sqlite'].append(jfile_path.replace(JS,''))
                if ((('javax.net.ssl') in dat) and (('TrustAllSSLSocket-Factory') in dat or ('AllTrustSSLSocketFactory') in dat or ('NonValidatingSSLSocketFactory')  in dat or
                    ('ALLOW_ALL_HOSTNAME_VERIFIER') in dat or ('.setDefaultHostnameVerifier(') in dat or ('NullHostnameVerifier(') in dat)):
                    c['d_ssl'].append(jfile_path.replace(JS,''))
                if (('password = "') in dat.lower() or ('secret = "') in dat.lower() or ('username = "') in dat.lower()):
                    c['d_sensitive'].append(jfile_path.replace(JS,''))
                
                #API Check
                if (('javax.crypto') in dat or ('kalium.crypto') in dat or ('bouncycastle.crypto') in dat):
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
                if (('IRemoteService') in dat or ('IRemoteService.Stub') in dat or ('IBinder') in dat):
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
                if (('http.client.HttpClient') in dat or ('net.http.AndroidHttpClient') in dat or ('http.impl.client.AbstractHttpClient') in dat):
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
                if ((('dalvik.system.PathClassLoader') in dat or ('dalvik.system.DexFile') in dat or ('dalvik.system.DexPathList') in dat) and (('loadDex') in dat or ('loadClass') in dat or ('loadDexFile') in dat)):
                    c['dex'].append(jfile_path.replace(JS,''))
                if ((('java.security.MessageDigest') in dat) and (('MessageDigestSpi') in dat or ('MessageDigest') in dat)):
                    c['mdigest'].append(jfile_path.replace(JS,''))
                if((('android.location') in dat )and (('getLastKnownLocation(') in dat or ('requestLocationUpdates(') in dat or ('getLatitude(') in dat or ('getLongitude(') in dat)):
                    c['gps'].append(jfile_path.replace(JS,''))
                #URLs John Gruber's regex to find URLs
                PAT = re.compile(ur'(?i)\b((?:(https?|ftp|file)://|www\d{0,3}[.]|data:|javascript:)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
                fl=jfile_path.replace(JS,'')
                base_fl=ntpath.basename(fl)
                uflag=0
                for mgroups in PAT.findall(dat.lower()):
                    if mgroups[0] not in URLS:
                        URLS.append(mgroups[0])
                        uflag=1
                if uflag==1:
                    URLnFile+="<tr><td>" + "<br>".join(URLS) + "</td><td><a href='../ViewSource/?file=" + fl+"&md5="+MD5+"'>"+base_fl+"</a></td></tr>"
                #Email Etraction Regex
                regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                                    "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                                    "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
                eflag=0
                for email in regex.findall(dat.lower()):
                    if ((email[0] not in EMAILS) and (not email[0].startswith('//'))):
                        EMAILS.append(email[0])
                        eflag=1
                if eflag==1:
                    EmailnFile+="<tr><td>" + "<br>".join(EMAILS) + "</td><td><a href='../ViewSource/?file=" + fl+"&md5="+MD5+"'>"+base_fl+"</a></td></tr>"
    dc ={'gps':'GPS Location','crypto':'Crypto ','exec': 'Execute System Command ','server_socket':'TCP Server Socket ' ,'socket': 'TCP Socket ','datagramp': 'UDP Datagram Packet ','datagrams': 'UDP Datagram Socket ','ipc': 'Inter Process Communication ','msg': 'Send SMS ','webview_addjs':'WebView JavaScript Interface ','webview': 'WebView Load HTML/JavaScript ','webviewget': 'WebView GET Request ','webviewpost': 'WebView POST Request ','httpcon': 'HTTP Connection ','urlcon':'URL Connection to file/http/https/ftp/jar ','jurl':'JAR URL Connection ','httpsurl':'HTTPS Connection ','nurl':'URL Connection supports file,http,https,ftp and jar ','httpclient':'HTTP Requests, Connections and Sessions ','notify': 'Android Notifications ','cellinfo':'Get Cell Information ','cellloc':'Get Cell Location ','subid':'Get Subscriber ID ','devid':'Get Device ID, IMEI,MEID/ESN etc. ','softver':'Get Software Version, IMEI/SV etc. ','simserial': 'Get SIM Serial Number ','simop': 'Get SIM Provider Details ','opname':'Get SIM Operator Name ','contentq':'Query Database of SMS, Contacts etc. ','refmethod':'Java Reflection Method Invocation ','obf': 'Obfuscation ','gs':'Get System Service ','bencode':'Base64 Encode ','bdecode':'Base64 Decode ','dex':'Load and Manipulate Dex Files ','mdigest': 'Message Digest '}
    html=''
    for ky in dc:
        if c[ky]:
            link=''
            hd="<tr><td>"+dc[ky]+"</td><td>"
            for l in c[ky]:
                link+="<a href='../ViewSource/?file="+ l +"&md5="+MD5+"'>"+ntpath.basename(l)+"</a> "
            html+=hd+link+"</td></tr>"
    dg={'d_sensitive' : "Files may contain hardcoded sensitive informations like usernames, passwords, keys etc.",
        'd_ssl': 'Insecure Implementation of SSL. Trusting all the certificates or accepting self signed certificates is a critical Security Hole.',
        'd_sqlite': 'App uses SQLite Database. Sensitive Information should be encrypted.',
        'd_con_world_readable':'The Object is World Readable. Any App can read from the Object',
        'd_con_world_writable':'The Object is World Writable. Any App can write to the Object',
        'd_con_private':'App can write to App Directory. Sensitive Information should be encrypted.',
        'd_extstorage': 'App can read/write to External Storage. Any App can read data written to External Storage.',
        'd_jsenabled':'Insecure WebView Implementation. Execution of user controlled code in WebView is a critical Security Hole.',
        'd_webviewdisablessl':'Insecure WebView Implementation. WebView ignores SSL Certificate Errors.',
        'd_webviewdebug':'Remote WebView debugging is enabled.'}
    dang=''
    spn_dang='<span class="label label-danger">high</span>'
    spn_info='<span class="label label-info">info</span>'
    for k in dg:
        if c[k]:
            link=''
            if (k == 'd_sqlite' or k == 'd_con_private'):
                hd='<tr><td>'+dg[k]+'</td><td>'+spn_info+'</td><td>'
            else:
                hd='<tr><td>'+dg[k]+'</td><td>'+spn_dang+'</td><td>'
                
            for ll in c[k]:
                link+="<a href='../ViewSource/?file="+ ll +"&md5="+MD5+"'>"+ntpath.basename(ll)+"</a> "

            dang+=hd+link+"</td></tr>"
   
    return html,dang,URLnFile,EmailnFile,crypto,obfus                            
    
    
