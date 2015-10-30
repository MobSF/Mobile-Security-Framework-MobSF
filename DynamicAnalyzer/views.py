# -*- coding: utf_8 -*-
from django.shortcuts import render
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import subprocess,os,re,shutil,tarfile,ntpath,platform,io,signal,json,random,time,ast,sys,psutil
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.html import escape
import sqlite3 as sq
from StaticAnalyzer.models import StaticAnalyzerAndroid
def python_list(value):
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)
#Dynamic Analyzer Calls begins here!
proxy_process=0 # Store PID of Proxy
def DynamicAnalyzer(request):
    if request.method == 'POST':
        MD5=request.POST['md5']
        PKG=request.POST['pkg']
        LNCH=request.POST['lng']
        if re.findall(";|\$\(|\|\||&&",PKG) or re.findall(";|\$\(|\|\||&&",LNCH):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/') 
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            VBOXEXE=settings.VBOX
            UUID=settings.UUID
            SUUID=settings.SUUID
            #Start DM
            RefreshVM(UUID,SUUID,VBOXEXE)
            context = {'md5' : MD5,
                   'pkg' : PKG,
                   'lng' : LNCH,
                   'title': 'Start Testing',}
            template="start_test.html"
            return render(request,template,context)
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')
#AJAX
def GetEnv(request):
    global proxy_process
    if request.method == 'POST':
        data = {}
        MD5=request.POST['md5']
        PKG=request.POST['pkg']
        LNCH=request.POST['lng']
        if re.findall(";|\$\(|\|\||&&",PKG) or re.findall(";|\$\(|\|\||&&",LNCH):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/') 
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            DIR=settings.BASE_DIR
            APP_DIR=os.path.join(DIR,'uploads/'+MD5+'/') #APP DIRECTORY
            APP_FILE=MD5 + '.apk'        #NEW FILENAME
            APP_PATH=APP_DIR+APP_FILE    #APP PATH
            TOOLS_DIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
            DWD_DIR=os.path.join(DIR,'static/downloads/')
            VM_IP=settings.VM_IP #VM IP
            PROXY_IP=settings.PROXY_IP #Proxy IP
            PORT=settings.PORT #Proxy Port
            proxy_process=WebProxy(TOOLS_DIR,APP_DIR,PROXY_IP,PORT,'10')
            ConnectInstallRun(TOOLS_DIR,VM_IP,APP_PATH,PKG,LNCH,True) #Change True to support non-activity components
            data = {'ready': 'yes'}
            return HttpResponse(json.dumps(data), content_type='application/json') 
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')
#AJAX
def TakeScreenShot(request):
    if request.method == 'POST':
        MD5=request.POST['md5']
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            data = {}
            r=random.randint(1, 1000000)
            DIR=settings.BASE_DIR
            SCRDIR=os.path.join(DIR,'uploads/'+MD5+'/screenshots-apk/')#make sure that list only png from this directory
            TOOLSDIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
            adb=getADB(TOOLSDIR)
            subprocess.call([adb, "shell", "screencap", "-p", "/system/screen.png"], shell=True)
            subprocess.call([adb, "pull", "/system/screen.png", SCRDIR + "screenshot-"+str(r)+".png"], shell=True)
            print "\n[INFO] Screenshot Taken"
            data = {'screenshot': 'yes'}
            return HttpResponse(json.dumps(data), content_type='application/json') 
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')
#AJAX
def ExecuteADB(request):
    if request.method == 'POST':
        data = {}
        CMD=request.POST['cmd']
        '''
        #Allow it Since it's functional
        if re.findall(";|\$\(|\|\||&&",CMD):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/')
        '''
        TOOLSDIR=os.path.join(settings.BASE_DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
        adb=getADB(TOOLSDIR)
        args=[adb] + CMD.split(' ')
        try:
            resp=subprocess.check_output(args)
        except subprocess.CalledProcessError as e:
             raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
        data = {'cmd': 'yes','resp': resp}
        return HttpResponse(json.dumps(data), content_type='application/json')
    else:
        return HttpResponseRedirect('/error/')
#AJAX
def FinalTest(request):
    if request.method == 'POST':
        data = {}
        MD5=request.POST['md5']
        PACKAGE=request.POST['pkg']
        if re.findall(";|\$\(|\|\||&&",PACKAGE):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/') 
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            DIR=settings.BASE_DIR
            APKDIR=os.path.join(DIR,'uploads/'+MD5+'/')
            TOOLSDIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
            adb=getADB(TOOLSDIR)
            
            #Change to check output of subprocess when analysis is done
            #Can't RCE
            os.system(adb+' logcat -d dalvikvm:W ActivityManager:I > "'+APKDIR + 'logcat.txt"')
            print "\n[INFO] Downloading Logcat logs"
            os.system(adb+' logcat -d Xposed:I *:S > "'+APKDIR + 'x_logcat.txt"')
            print "\n[INFO] Downloading Droidmon API Monitor Logcat logs"
            #Can't RCE
            os.system(adb+' shell dumpsys > "'+APKDIR + 'dump.txt"');
            print "\n[INFO] Downloading Dumpsys logs"

            subprocess.call([adb, "shell", "am", "force-stop", PACKAGE], shell=True)
            print "\n[INFO] Stopping Application"
            data = {'final': 'yes'}
            return HttpResponse(json.dumps(data), content_type='application/json') 
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')
#AJAX
def DumpData(request):
    global proxy_process
    if request.method == 'POST':
        data = {}
        PACKAGE=request.POST['pkg']
        MD5=request.POST['md5']
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            if re.findall(";|\$\(|\|\||&&",PACKAGE):
                print "[ATTACK] Possible RCE"
                return HttpResponseRedirect('/error/')
            DIR=settings.BASE_DIR
            APKDIR=os.path.join(DIR,'uploads/'+MD5+'/')
            TOOLSDIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
            adb=getADB(TOOLSDIR)

            print "\n[INFO] Deleting Dump Status File"
            subprocess.call([adb, "shell", "rm", "-rf","/sdcard/mobsec_status"], shell=True)
            print "\n[INFO] Creating TAR of Application Files."
            subprocess.call([adb, "shell", "am", "startservice", "-a", PACKAGE, "opensecurity.ajin.datapusher/.GetPackageLocation"], shell=True)
            print "\n[INFO] Waiting for TAR dump to complete..."
            timeout=100
            start_time=time.time()
            while True:
                current_time=time.time()
                if "MOBSEC-TAR-CREATED" in subprocess.check_output([adb, "shell", "cat", "/sdcard/mobsec_status"], shell=True):
                    break
                if (current_time-start_time) > timeout:
                    print "\n[ERROR] TAR Generation Failed...."
                    break
            print "\n[INFO] Dumping Application Files from Device/VM"
            subprocess.call([adb, "pull", "/sdcard/"+PACKAGE+".tar", APKDIR+PACKAGE+".tar"], shell=True)
            print "\n[INFO] Stopping ADB"
            subprocess.call([adb,"kill-server"], shell=True)
            try:
                if proxy_process!=0:
                    print "\n[INFO] Stopping WebProxy with PID: " +str(proxy_process)
                    p = psutil.Process(proxy_process)
                    p.terminate()
                    #os.kill(proxy_process,signal.SIGKILL)
                    proxy_process=0
                else:
                    print "\n[WARNING] WebProxy still running. Kill it manually!"
            except Exception as e:
                print "\n[ERROR] WebProxy Error - " + str(e)
                pass
            data = {'dump': 'yes'}
            return HttpResponse(json.dumps(data), content_type='application/json') 
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')
#AJAX
def ExportedActivityTester(request):
    MD5=request.POST['md5']
    PKG=request.POST['pkg']
    m=re.match('[0-9a-f]{32}',MD5)
    if m:
        if re.findall(";|\$\(|\|\||&&",PKG):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/')
        if request.method == 'POST':
            DIR=settings.BASE_DIR
            APP_DIR=os.path.join(DIR,'uploads/'+MD5+'/')
            TOOLS_DIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
            SCRDIR=os.path.join(APP_DIR,'screenshots-apk/')
            data = {}
            adb=getADB(TOOLS_DIR)

            DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
            if DB.exists():
                print "\n[INFO] Fetching Exported Activity List from DB"
                EXPORTED_ACT=python_list(DB[0].EXPORTED_ACT)
                if len(EXPORTED_ACT)>0:
                    n=0
                    print "\n[INFO] Starting Exported Activity Tester..."
                    print "\n[INFO] "+str(len(EXPORTED_ACT))+" Exported Activities Identified"
                    for line in EXPORTED_ACT:
                        try:
                            n+=1
                            print "\n[INFO] Launching Exported Activity - "+ str(n)+ ". "+line
                            subprocess.call([adb,"shell", "am","start", "-n", PKG+"/"+line], shell=True)
                            Wait(4)
                            subprocess.call([adb, "shell", "screencap", "-p", "/system/screen.png"], shell=True)
                            #? get appended from Air :-() if activity names are used
                            subprocess.call([adb, "pull", "/system/screen.png", SCRDIR + "expact-"+str(n)+".png"], shell=True)
                            print "\n[INFO] Activity Screenshot Taken"
                            subprocess.call([adb, "shell", "am", "force-stop", PKG], shell=True)
                            print "\n[INFO] Stopping App"
                        except subprocess.CalledProcessError as e:
                            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
                    data = {'expacttest': 'done'}
                else:
                    print "\n[INFO] Exported Activity Tester - No Activity Found!"
                    data = {'expacttest': 'noact'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                print "\n[ERROR] Entry does not exist in DB."
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')

#AJAX
def ActivityTester(request):
    MD5=request.POST['md5']
    PKG=request.POST['pkg']
    m=re.match('[0-9a-f]{32}',MD5)
    if m:
        if re.findall(";|\$\(|\|\||&&",PKG):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/')
        if request.method == 'POST':
            DIR=settings.BASE_DIR
            APP_DIR=os.path.join(DIR,'uploads/'+MD5+'/')
            TOOLS_DIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
            SCRDIR=os.path.join(APP_DIR,'screenshots-apk/')
            data = {}
            adb=getADB(TOOLS_DIR)
            DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
            if DB.exists():
                print "\n[INFO] Fetching Activity List from DB"
                ACTIVITIES=python_list(DB[0].ACTIVITIES)
                if len(ACTIVITIES)>0:
                    n=0
                    print "\n[INFO] Starting Activity Tester..."
                    print "\n[INFO] "+str(len(ACTIVITIES))+" Activities Identified"
                    for line in ACTIVITIES:
                        try:
                            n+=1
                            print "\n[INFO] Launching Activity - "+ str(n)+ ". "+line
                            subprocess.call([adb,"shell", "am","start", "-n", PKG+"/"+line], shell=True)
                            Wait(4)
                            subprocess.call([adb, "shell", "screencap", "-p", "/system/screen.png"], shell=True)
                            #? get appended from Air :-() if activity names are used
                            subprocess.call([adb, "pull", "/system/screen.png", SCRDIR + "act-"+str(n)+".png"], shell=True)
                            print "\n[INFO] Activity Screenshot Taken"
                            subprocess.call([adb, "shell", "am", "force-stop", PKG], shell=True)
                            print "\n[INFO] Stopping App"
                        except subprocess.CalledProcessError as e:
                            raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
                    data = {'acttest': 'done'}
                else:
                    print "\n[INFO] Activity Tester - No Activity Found!"
                    data = {'acttest': 'noact'}
                return HttpResponse(json.dumps(data), content_type='application/json')
            else:
                print "\n[ERROR] Entry does not exist in DB."
                return HttpResponseRedirect('/error/')
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')

def Wait(sec):
    print "\n[INFO] Waiting for "+str(sec)+ " seconds..."
    time.sleep(sec)
            
def Report(request):
    if request.method == 'GET':
        MD5=request.GET['md5']
        PKG=request.GET['pkg']
        if re.findall(";|\$\(|\|\||&&",PKG):
            print "[ATTACK] Possible RCE"
            return HttpResponseRedirect('/error/') 
        m=re.match('[0-9a-f]{32}',MD5)
        if m:
            DIR=settings.BASE_DIR
            APP_DIR=os.path.join(DIR,'uploads/'+MD5+'/') #APP DIRECTORY
            DWD_DIR=os.path.join(DIR,'static/downloads/')
            DRDMONAPISLOC=os.path.join(APP_DIR,'x_logcat.txt') #Use check_outputs instead later.
            API_NET,API_BASE64, API_FILEIO, API_BINDER, API_CRYPTO, API_DEVICEINFO, API_CNTVL,API_SMS,API_SYSPROP,API_DEXLOADER,API_RELECT,API_ACNTMNGER,API_CMD=APIAnalysis(PKG,DRDMONAPISLOC)
            URL,EMAIL,HTTP,XML,SQLiteDB,OtherFiles=RunAnalysis(APP_DIR,MD5,PKG)
            Download(MD5,DWD_DIR,APP_DIR,PKG)
            #Only After Download Process is Done
            IMGS=[]
            ACTIMGS=[]
            ACT={}
            EXPACTIMGS=[]
            EXPACT={}
            try:
                for img in os.listdir(os.path.join(DWD_DIR,MD5+"-screenshots-apk/")):
                    if img.endswith(".png"):
                        if img.startswith("act"):
                            ACTIMGS.append(img)
                        elif img.startswith("expact"):
                            EXPACTIMGS.append(img)
                        else:
                            IMGS.append(img)
                DB=StaticAnalyzerAndroid.objects.filter(MD5=MD5)
                if DB.exists():
                    print "\n[INFO] Fetching Exported Activity & Activity List from DB"
                    EXPORTED_ACT=python_list(DB[0].EXPORTED_ACT)
                    ACTDESC=python_list(DB[0].ACTIVITIES)
                    if len(ACTIMGS)>0:
                        if len(ACTIMGS)==len(ACTDESC):
                            ACT = dict(zip(ACTIMGS, ACTDESC))
                    if len(EXPACTIMGS)>0:
                        if len(EXPACTIMGS)==len(EXPORTED_ACT):
                            EXPACT = dict(zip(EXPACTIMGS, EXPORTED_ACT))
                else:
                    print "\n[WARNING] Entry does not exists in the DB."
            except Exception as e:
                print "\n[ERROR] Screenshot Sorting : "+str(e)

            context = {'emails' : EMAIL,
                   'urls' : URL,
                   'md5' : MD5,
                   'http' : HTTP,
                   'xml': XML,
                   'sqlite' : SQLiteDB,
                   'others' : OtherFiles,
                   'imgs': IMGS,
                   'acttest': ACT,
                   'expacttest': EXPACT,
                   'net': API_NET,
                   'base64':API_BASE64,
                   'crypto':API_CRYPTO,
                   'fileio':API_FILEIO,
                   'binder':API_BINDER,
                   'divinfo': API_DEVICEINFO,
                   'cntval': API_CNTVL,
                   'sms': API_SMS,
                   'sysprop': API_SYSPROP,
                   'dexload': API_DEXLOADER,
                   'reflect': API_RELECT,
                   'sysman': API_ACNTMNGER,
                   'process': API_CMD}
            template="dynamic_analysis.html"
            return render(request,template,context)
        else:
            return HttpResponseRedirect('/error/')
    else:
        return HttpResponseRedirect('/error/')



def RefreshVM(uuid,snapshot_uuid,vbox_exe):
    #Close VM
    args=[vbox_exe,'controlvm',uuid,'poweroff']
    subprocess.call(args)
    print "\n[INFO] VM Closed"
    #Restore Snapshot
    args=[vbox_exe,'snapshot',uuid,'restore',snapshot_uuid]
    subprocess.call(args)
    print "\n[INFO] VM Restore Snapshot"
    #Start Fresh VM
    args=[vbox_exe,'startvm',uuid]
    subprocess.call(args)
    print "\n[INFO] VM Starting"

def WebProxy(TOOLSDIR,APKDIR,ip,port,exectime):
    global proxy_process
    #Remove the old occurance of the files too.
    #Check if this works in windows without setting the path
    log=os.path.join(APKDIR,'Weblog.txt')
    if os.path.exists(log):
        os.remove(log)
    pyexe=os.path.join(TOOLSDIR,'pyWebProxy/proxy.py')
    args=['python',pyexe,ip,port,log]
    if proxy_process==0:
        x=subprocess.Popen(args)
        print "\n[INFO] HTTPS Proxy (PID: "+str(x.pid)+") Running on "+ str(ip)+ ":"+str(port)
        return x.pid
    else:
        return 0

def getADB(TOOLSDIR):
    adb=''
    if platform.system()=="Darwin":
        adb_dir=os.path.join(TOOLSDIR, 'adb/mac/')
        subprocess.call(["chmod", "777", adb_dir], shell=True)
        adb=os.path.join(TOOLSDIR , 'adb/mac/adb')
    elif platform.system()=="Linux":
        adb_dir=os.path.join(TOOLSDIR, 'adb/linux/')
        subprocess.call(["chmod", "777", adb_dir], shell=True)
        adb=os.path.join(TOOLSDIR , 'adb/linux/adb')
    elif platform.system()=="Windows":
        adb=os.path.join(TOOLSDIR , 'adb/windows/adb.exe')
    return adb

def ConnectInstallRun(TOOLSDIR,IP,APKPATH,PACKAGE,LAUNCH,isACT):
    #-------check strace under monkeyrunner 
    adb=getADB(TOOLSDIR)
    subprocess.call([adb, "kill-server"], shell=True)
    subprocess.call([adb, "start-server"], shell=True)
    print "\n[INFO] ADB Started"
    Wait(7) 
    print "\n[INFO] Connecting to VM"
    subprocess.call([adb, "connect", IP], shell=True)
    subprocess.call([adb, "wait-for-device"], shell=True)
    print "\n[INFO] Mounting"
    subprocess.call([adb, "shell", "mount", "-o", "rw,remount", "-t", "rfs", "/dev/block/sda6", "/system"], shell=True)
    print "\n[INFO] Installing APK"
    subprocess.call([adb, "install", APKPATH], shell=True)
    if isACT:
        runApp = PACKAGE + "/" + LAUNCH
        print "\n[INFO] Launching APK Main Activity"
        subprocess.call([adb, "shell", "am", "start", "-n", runApp], shell=True)
    else:
        #Handle Service or Give Choice to Select in Future.
        pass
    print "[INFO] Testing Environment is Ready!"


def HandleSqlite(SFile):   
    try:
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
        pass
def APIAnalysis(PKG,LOCATION):

    dat=""
    API_BASE64=[]
    API_FILEIO=[]
    API_RELECT=[]
    API_SYSPROP=[]
    API_CNTRSLVR=[]
    API_CNTVAL=[]
    API_BINDER=[]
    API_CRYPTO=[]
    API_ACNTMNGER=[]
    API_DEVICEINFO=[]
    API_NET=[]
    API_DEXLOADER=[]
    API_CMD=[]
    API_SMS=[]
    try:
        with open(LOCATION,"r") as f:
            dat=f.readlines()
        ID="Droidmon-apimonitor-" + PKG +":"
        for line in dat:
            if (ID) in line:
                #print "LINE: " + line
                param, value = line.split(ID,1)
                #print "PARAM is :" + param
                #print "Value is :"+ value
                try:
                    APIs=json.loads(value)
                    RET=''
                    CLS=''
                    MTD=''
                    ARGS=''
                    MTD= str(APIs["method"]) 
                    CLS= str(APIs["class"])
                    #print "Called Class: " + CLS
                    #print "Called Method: " + MTD
                    if APIs.get('return'):
                        RET=str(APIs["return"])
                        #print "Return Data: " + RET
                    else:
                        #print "No Return Data"
                        RET = "No Return Data"
                    if APIs.get('args'):
                        ARGS=str(APIs["args"])
                        #print "Passed Arguments" + ARGS
                    else:
                        #print "No Arguments Passed"
                        ARGS= "No Arguments Passed"
                    #XSS Safe
                    D="</br>METHOD: "+ escape(MTD) + "</br>ARGUMENTS: "+ escape(ARGS) + "</br>RETURN DATA: "+escape(RET)
                    
                    if re.findall("android.util.Base64",CLS):
                        API_BASE64.append(D)
                    if re.findall('libcore.io|android.app.SharedPreferencesImpl$EditorImpl',CLS):
                        API_FILEIO.append(D)
                    if re.findall('java.lang.reflect',CLS):
                        API_RELECT.append(D)
                    if re.findall('android.content.ContentResolver|android.location.Location|android.media.AudioRecord|android.media.MediaRecorder|android.os.SystemProperties',CLS):
                        API_SYSPROP.append(D)
                    if re.findall('android.app.Activity|android.app.ContextImpl|android.app.ActivityThread',CLS):
                        API_BINDER.append(D)
                    if re.findall('javax.crypto.spec.SecretKeySpec|javax.crypto.Cipher|javax.crypto.Mac',CLS):
                        API_CRYPTO.append(D)
                    if re.findall('android.accounts.AccountManager|android.app.ApplicationPackageManager|android.app.NotificationManager|android.net.ConnectivityManager|android.content.BroadcastReceiver',CLS):
                        API_ACNTMNGER.append(D)
                    if re.findall('android.telephony.TelephonyManager|android.net.wifi.WifiInfo|android.os.Debug',CLS):
                        API_DEVICEINFO.append(D)
                    if re.findall('dalvik.system.BaseDexClassLoader|dalvik.system.DexFile|dalvik.system.DexClassLoader|dalvik.system.PathClassLoader',CLS):
                        API_DEXLOADER.append(D)
                    if re.findall('java.lang.Runtime|java.lang.ProcessBuilder|java.io.FileOutputStream|java.io.FileInputStream|android.os.Process',CLS):
                        API_CMD.append(D)
                    if re.findall('android.content.ContentValues',CLS):
                        API_CNTVAL.append(D)
                    if re.findall('android.telephony.SmsManager',CLS):
                        API_SMS.append(D)
                    if re.findall('java.net.URL|org.apache.http.impl.client.AbstractHttpClient',CLS):
                        API_NET.append(D)
                except:
                    print "\n[ERROR] Parsing JSON Failed for: \n" + value
    except:
        pass
    return list(set(API_NET)),list(set(API_BASE64)), list(set(API_FILEIO)), list(set(API_BINDER)), list(set(API_CRYPTO)), list(set(API_DEVICEINFO)), list(set(API_CNTVAL)), list(set(API_SMS)), list(set(API_SYSPROP)),list(set(API_DEXLOADER)),list(set(API_RELECT)),list(set(API_ACNTMNGER)),list(set(API_CMD)) 
def Download(MD5,DWDDIR,APKDIR,PKG):
    print "\n[INFO] Copying Files to Downloads"
    Logcat=os.path.join(APKDIR,'logcat.txt')
    xLogcat=os.path.join(APKDIR,'x_logcat.txt')
    Dumpsys=os.path.join(APKDIR,'dump.txt')
    Sshot=os.path.join(APKDIR,'screenshots-apk/')
    Web=os.path.join(APKDIR,'Weblog.txt')
    Star=os.path.join(APKDIR, PKG+'.tar')

    
    DLogcat=os.path.join(DWDDIR,MD5+'-logcat.txt')
    DxLogcat=os.path.join(DWDDIR,MD5+'-x_logcat.txt')
    DDumpsys=os.path.join(DWDDIR,MD5+'-dump.txt')
    DSshot=os.path.join(DWDDIR,MD5+'-screenshots-apk/')
    DWeb=os.path.join(DWDDIR,MD5+'-Weblog.txt')
    DStar=os.path.join(DWDDIR,MD5+'-AppData.tar')
   
    shutil.copyfile(Logcat,DLogcat)
    shutil.copyfile(xLogcat,DxLogcat)
    shutil.copyfile(Dumpsys,DDumpsys)
    try:
        shutil.copytree(Sshot,DSshot)
    except:
        pass
    try:
        shutil.copyfile(Web,DWeb)
    except:
        pass  
    try:
        shutil.copyfile(Star,DStar)
    except:
        pass  
def RunAnalysis(APKDIR,MD5,PACKAGE):
    Web=os.path.join(APKDIR,'Weblog.txt')
    Logcat=os.path.join(APKDIR,'logcat.txt')
    xLogcat=os.path.join(APKDIR,'x_logcat.txt')
    traffic=''
    wb=''
    xlg=''
    try:
        with io.open(Web,mode='r',encoding="utf8",errors="ignore") as f:
            wb=f.read()
    except:
        pass

    with io.open(Logcat,mode='r',encoding="utf8",errors="ignore") as f:
        traffic=f.read()
    with io.open(xLogcat,mode='r',encoding="utf8",errors="ignore") as f:
        xlg=f.read()
    traffic=wb+traffic+xlg
    URLS=[]
    #URLs My Custom regex
    p = re.compile(ur'((?:https?://|s?ftps?://|file://|javascript:|data:|www\d{0,3}[.])[\w().=/;,#:@?&~*+!$%\'{}-]+)', re.UNICODE) 
    urllist=re.findall(p, traffic.lower())
    for url in urllist:
        if url not in URLS:
            URLS.append(url)
                        
    #Email Etraction Regex
    EMAILS=[]
    regex = re.compile(("[\w.-]+@[\w-]+\.[\w.]+"))
    for email in regex.findall(traffic.lower()):
        if ((email not in EMAILS) and (not email.startswith('//'))):
            if email=="yodleebanglore@gmail.com":
                pass
            else:
                EMAILS.append(email)
    #Extract Device Data
    try:
        TARLOC=os.path.join(APKDIR,PACKAGE+'.tar')
        UNTAR_DIR = os.path.join(APKDIR,'DYNAMIC_DeviceData/')
        if not os.path.exists(UNTAR_DIR):
            os.makedirs(UNTAR_DIR)
        tar = tarfile.open(TARLOC)
        tar.extractall(UNTAR_DIR)
        tar.close()
    except:
        print "\n[ERROR] TAR EXTRACTION FAILED"
    #Do Static Analysis on Data from Device
    xmlfiles=''
    SQLiteDB=''
    OtherFiles=''
    typ=''
    UNTAR_DIR = os.path.join(APKDIR,'DYNAMIC_DeviceData/')
    if not os.path.exists(UNTAR_DIR):
        os.makedirs(UNTAR_DIR)
    try:
        for dirName, subDir, files in os.walk(UNTAR_DIR):
            for jfile in files:
                file_path=os.path.join(UNTAR_DIR,dirName,jfile)
                if "+" in file_path:
                    shutil.move(file_path,file_path.replace("+","x"))
                    file_path=file_path.replace("+","x")
                fileparam=file_path.replace(UNTAR_DIR,'')
                if jfile=='lib':
                    pass
                else:
                    if jfile.endswith('.xml'):
                        typ='xml'
                        xmlfiles+="<tr><td><a href='../View/?file="+escape(fileparam)+"&md5="+MD5+"&type="+typ+"'>"+escape(fileparam)+"</a><td><tr>"
                    else:
                        with io.open(file_path, mode='r',encoding="utf8",errors="ignore") as f:
                            b=f.read(6)
                        if b=="SQLite":
                            typ='db'
                            SQLiteDB+="<tr><td><a href='../View/?file="+escape(fileparam)+"&md5="+MD5+"&type="+typ+"'>"+escape(fileparam)+"</a><td><tr>" 
                        elif not jfile.endswith('.DS_Store'):
                            typ='others'
                            OtherFiles+="<tr><td><a href='../View/?file="+escape(fileparam)+"&md5="+MD5+"&type="+typ+"'>"+escape(fileparam)+"</a><td><tr>"
    except:
        pass              
    return URLS,EMAILS,wb,xmlfiles,SQLiteDB,OtherFiles

def View(request):
    try:
        typ=''
        fil=''
        rtyp=''
        dat=''
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m:
            fil=request.GET['file']
            MD5=request.GET['md5']
            typ=request.GET['type']
            SRC=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/DYNAMIC_DeviceData/')
            sfile=os.path.join(SRC,fil)
            #Prevent Directory Traversal Attacks
            if (("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil)):
                return HttpResponseRedirect('/error/')
            else:
                with io.open(sfile,mode='r',encoding="utf8",errors="ignore") as f:
                    dat=f.read()
                if ((fil.endswith('.xml')) and (typ=='xml')):  
                    rtyp='xml'
                elif typ=='db':
                    dat=HandleSqlite(sfile)
                    dat=dat.decode("windows-1252").encode("utf8")
                    rtyp='plain'
                elif typ=='others':
                    rtyp='plain'
                else:
                    return HttpResponseRedirect('/error/')
                context = {'title': escape(ntpath.basename(fil)),'file': escape(ntpath.basename(fil)),'dat': dat,'type' : rtyp,}
                template="view.html"
                return render(request,template,context)

        else:
            return HttpResponseRedirect('/error/')
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print "\n[ERROR] Viewing File - "+str(e) + " Line: "+str(exc_tb.tb_lineno)
        return HttpResponseRedirect('/error/')    
    










