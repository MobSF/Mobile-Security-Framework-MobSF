from django.shortcuts import render
from django.conf import settings
import subprocess,os,re,shutil

#Create your views here.
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
        #Start DM
        RefreshVM(UUID,SUUID,VBOXEXE)
        WebProxy(TOOLS_DIR,APP_DIR,PROXY_IP,PORT,'10')
        ConnectInstallRun(TOOLS_DIR,APP_DIR,HOST_IP,APP_PATH,PKG,LNCH,True)
        URL,EMAIL,HTTP=RunAnalysis(APP_DIR)
        Download(MD5,DWD_DIR,APP_DIR)
    context = {'emails' : EMAIL,
               'urls' : URL,
               'md5' : MD5,
               'http' : HTTP,}
    template="dynamic_analysis.html"
    return render(request,template,context)

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
def ConnectInstallRun(TOOLSDIR,APKDIR,IP,APKPATH,PACKAGE,LAUNCH,isACT):
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
    print "\nStopping ADB"
def RunAnalysis(APKDIR):
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
    return URLS,EMAILS,wb
def Download(MD5,DWDDIR,APKDIR):
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

    
    










