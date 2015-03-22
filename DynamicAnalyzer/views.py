from django.shortcuts import render
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
import subprocess,os,re,shutil,tarfile
from .forms import UploadFileForm
from django.http import HttpResponseRedirect
from django.utils.html import escape
import sqlite3 as sq

#This method is only exposed to internal network
@csrf_exempt
def InternalUpload(request):
    md5=''
    md5=request.META['HTTP_LOC']
    print md5
    m=re.match('[0-9a-f]{32}',md5)
    if m:
        print "Valid MD5" #remove
        if request.method == 'POST':
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                file_type =request.FILES['file'].content_type
                print file_type #remove
                if file_type=="application/octet-stream" and request.FILES['file'].name.endswith('.tar'):
                    DIR = settings.BASE_DIR
                    ANAL_DIR=os.path.join(DIR,'uploads/'+md5+'/')
                    if not os.path.exists(ANAL_DIR):
                        return HttpResponseRedirect('/') #Go Away ,Not a known LOC MD5
                    TARFILE=request.FILES['file'].name
                    TARLOC=os.path.join(ANAL_DIR,TARFILE)
                    with open(TARLOC, 'wb+') as destination:
                        for chunk in request.FILES['file'].chunks():
                            destination.write(chunk)
                    print "TAR Download Sucessful" 
                    UNTAR_DIR = os.path.join(ANAL_DIR,'DYNAMIC_DeviceData/')
                    if not os.path.exists(UNTAR_DIR):
                        os.makedirs(UNTAR_DIR)
                    tar = tarfile.open(TARLOC)
                    tar.extractall(UNTAR_DIR)
                    tar.close()
                    print "Untar Sucessful"
            else:
                print "Form is not Valid" #Remove
        else:
            form = UploadFileForm()
            print "Oops that's not a Valid LOC!" 
    
    return HttpResponseRedirect('/')
    
    

def DynamicAnalyzer(request):
    MD5=request.POST['md5']
    PKG=request.POST['pkg']
    LNCH=request.POST['lng']
    m=re.match('[0-9a-f]{32}',MD5)
    if m:
        DIR=settings.BASE_DIR
        VBOXEXE=settings.VBOX
        APP_DIR=os.path.join(DIR,'uploads/'+MD5+'/') #APP DIRECTORY
        APP_FILE=MD5 + '.apk'        #NEW FILENAME
        APP_PATH=APP_DIR+APP_FILE    #APP PATH
        TOOLS_DIR=os.path.join(DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR
        DWD_DIR=os.path.join(DIR,'static/downloads/')
        UUID=settings.UUID
        SUUID=settings.SUUID
        HOST_IP=settings.HOST_IP #Host IP
        PROXY_IP=settings.PROXY_IP #Proxy IP
        PORT=settings.PORT #Proxy Port
        UPSERVER=settings.UPSERVER #Local IP:PORT
        #Start DM
        RefreshVM(UUID,SUUID,VBOXEXE)
        WebProxy(TOOLS_DIR,APP_DIR,PROXY_IP,PORT,'10')
        ConnectInstallRun(TOOLS_DIR,APP_DIR,HOST_IP,APP_PATH,PKG,LNCH,True,UPSERVER,MD5)
        URL,EMAIL,HTTP,XML,SQLiteDB,OtherFiles=RunAnalysis(APP_DIR,MD5)
        Download(MD5,DWD_DIR,APP_DIR,PKG)
        context = {'emails' : EMAIL,
               'urls' : URL,
               'md5' : MD5,
               'http' : HTTP,
               'xml': XML,
               'sqlite' : SQLiteDB,
               'others' : OtherFiles,}
        template="dynamic_analysis.html"
        return render(request,template,context)
    else:
        return HttpResponseRedirect('/error/')


def RefreshVM(uuid,snapshot_uuid,vbox_exe):
    #Close VM
    args=[vbox_exe,'controlvm',uuid,'poweroff']
    subprocess.call(args)
    print "\nVM Closed"
    #Restore Snapshot
    args=[vbox_exe,'snapshot',uuid,'restore',snapshot_uuid]
    subprocess.call(args)
    print "\nVM Restore Snapshot"
    #Start Fresh VM
    args=[vbox_exe,'startvm',uuid]
    subprocess.call(args)
    print "\nVM Started"
def WebProxy(TOOLSDIR,APKDIR,ip,port,exectime):
    print "\nWeb Proxy Running for "+str(exectime)+" sec at " + str(ip) + ":" + str(port)+"\n"
    log=os.path.join(APKDIR,'Weblog.txt')
    exe=os.path.join(TOOLSDIR,'WebProxy/WebProxy.exe')
    args=[exe,ip,port,log,exectime]
    subprocess.Popen(args)
def ConnectInstallRun(TOOLSDIR,APKDIR,IP,APKPATH,PACKAGE,LAUNCH,isACT,UPSERVER,MD5):
    #-------check strace under monkeyrunner 
    adb=os.path.join(TOOLSDIR , 'adb/adb.exe')
    os.system(adb+" kill-server")
    os.system(adb+" start-server")
    print "\nADB Started"
    os.system("ping -n 3 127.0.0.1 > NULL")
    print "\nConnecting to VM"
    os.system(adb+" connect "+IP)
    #Specific for the ROM
    os.system(adb+" wait-for-device")
    print "\nMounting"
    os.system(adb+" shell mount -o rw,remount -t rfs /dev/block/sda6 /system")
    print "\nInstalling APK"
    os.system(adb+' install "' + APKPATH + '"')
    if isACT:
        runApp = PACKAGE + "/" + LAUNCH
        print "\nLaunching APK Main Activity"
        os.system(adb+" shell am start -n "+runApp)
    else:
        pass
    os.system("ping -n 11 127.0.0.1 > NULL")
    os.system(adb+" shell screencap -p /system/screen.png")
    os.system(adb+' pull /system/screen.png "'+APKDIR + 'screenshot.png"')
    print "\nScreenshot Taken"
    os.system(adb+' logcat -d dalvikvm:W ActivityManager:I > "'+APKDIR + 'logcat.txt"')
    print "\nDownloading Logcat logs"
    os.system(adb+' shell dumpsys > "'+APKDIR + 'dump.txt"');
    print "\nDownloading Dumpsys logs"
    os.system(adb+" shell am force-stop "+PACKAGE)
    os.system(adb+' shell am startservice -a '+PACKAGE+',http://'+UPSERVER+'/InternalUpload/,'+MD5+' opensecurity.ajin.datapusher/.GetPackageLocation')
    os.system("ping -n 7 127.0.0.1 > NULL")
    os.system(adb+" kill-server")
    print "\nStopping ADB"
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
def RunAnalysis(APKDIR,MD5):
    Web=os.path.join(APKDIR,'Weblog.txt')
    Logcat=os.path.join(APKDIR,'logcat.txt')
    traffic=''
    wb=''
    with open(Web,'r') as f:
        wb=f.read()
    wb=wb.replace("See http://www.iana.org/assignments/tls-parameters/", "")
    with open(Logcat,'r') as f:
        traffic=f.read()
    traffic+=wb
    #URLs John Gruber's regex to find URLs
    PAT = re.compile(ur'(?i)\b((?:(https?|ftp|file)://|www\d{0,3}[.]|data:|javascript:)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')
    URLS=[]
    for mgroups in PAT.findall(traffic.lower()):
        if mgroups[0] not in URLS:
            URLS.append(mgroups[0])
    #Email Etraction Regex
    regex = re.compile(("([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`"
                        "{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|"
                        "\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)"))
    EMAILS=[]
    for email in regex.findall(traffic.lower()):
        if ((email[0] not in EMAILS) and (not email[0].startswith('//'))):
            EMAILS.append(email[0])
    #Do Static Analysis on Data from Device
    xmlfiles=''
    SQLiteDB=''
    OtherFiles=''
    UNTAR_DIR = os.path.join(APP_DIR,'DYNAMIC_DeviceData/')
    if not os.path.exists(UNTAR_DIR):
        os.makedirs(UNTAR_DIR)
    for dirName, subDir, files in os.walk(UNTAR_DIR):
        for jfile in files:
            if jfile.endswith('.xml'):
                file_path=os.path.join(UNTAR_DIR,dirName,jfile)
                fileparam=file_path.replace(UNTAR_DIR,'')
                xmlfiles+="<tr><td><a href='../View/?file="+escape(fileparam)+"&md5="+MD5+"'>"+escape(fileparam)+"</a><td><tr>"
            else:
                f=open(file_path)
                with f:
                    b=f.read(6)
                if b=="SQLite":
                    SQLiteDB+="<tr><td><a href='../View/?file="+escape(fileparam)+"&md5="+MD5+"'>"+escape(fileparam)+"</a><td><tr>"
                else:
                    OtherFiles+="<tr><td><a href='../View/?file="+escape(fileparam)+"&md5="+MD5+"'>"+escape(fileparam)+"</a><td><tr>"

    return URLS,EMAILS,wb,XML,SQLiteDB,OtherFiles

def View(request):
    try:
        fil=''
        typ=''
        dat=''
        m=re.match('[0-9a-f]{32}',request.GET['md5'])
        if m:
            fil=request.GET['file']
            MD5=request.GET['md5']
            SRC=os.path.join(settings.BASE_DIR,'uploads/'+MD5+'/DYNAMIC_DeviceData/')
            sfile=SRC+fil #do we need to go for OS.path.join
            #Prevent Directory Traversal
            if (("../" in fil) or ("%2e%2e" in fil) or (".." in fil) or ("%252e" in fil)):
                return HttpResponseRedirect('/error/')
            else:
                with open(sfile,'r') as f:
                    dat=f.read()
                    dat=dat.decode("windows-1252").encode("utf8")
                    b=f.read(6)
                if fil.endswith('.xml'):  
                    typ='xml'
                elif b=="SQLite":
                    dat=HandleSqlite(sfile)
                    dat=dat.decode("windows-1252").encode("utf8")
                    typ='plain'
                else:
                    typ='plain'
                context = {'title': escape(ntpath.basename(fil)),'file': escape(ntpath.basename(fil)),'dat': dat,'type' : typ,}
                template="view.html"
                return render(request,template,context)

        else:
            return HttpResponseRedirect('/error/')
    except:
        return HttpResponseRedirect('/error/')
                
def Download(MD5,DWDDIR,APKDIR,PKG):
    Web=os.path.join(APKDIR,'Weblog.txt')
    Logcat=os.path.join(APKDIR,'logcat.txt')
    Dumpsys=os.path.join(APKDIR,'dump.txt')
    Sshot=os.path.join(APKDIR,'screenshot.png')

    DWeb=os.path.join(DWDDIR,MD5+'-Weblog.txt')
    DLogcat=os.path.join(DWDDIR,MD5+'-logcat.txt')
    DDumpsys=os.path.join(DWDDIR,MD5+'-dump.txt')
    DSshot=os.path.join(DWDDIR,MD5+'-screenshot.png')
    
  
    shutil.copyfile(Web,DWeb)
    shutil.copyfile(Logcat,DLogcat)
    shutil.copyfile(Dumpsys,DDumpsys)
    shutil.copyfile(Sshot,DSshot)

    try:
        Star=os.path.join(APKDIR, PKG+'.tar')
        DStar=os.path.join(DWDDIR,MD5+'-AppData.tar')
        shutil.copyfile(Star,DStar)
    except:
        pass  

    
    










