# -*- coding: utf_8 -*-
import os,platform,subprocess
BASE_DIR=os.path.dirname(os.path.realpath(__file__))
TOOLSDIR=os.path.join(BASE_DIR, 'DynamicAnalyzer/tools/')  #TOOLS DIR


def ExecuteCMD(args,ret =False):
    try:
        print "\n[INFO] Executing Command - " + ' '.join(args)
        if ret:
            return subprocess.check_output(args)
        else:
            subprocess.call(args)
    except Exception as e:
        print ("\n[ERROR] Executing Command - " + str(e))

def getADB(TOOLSDIR):
    print ("\n[INFO] Getting ADB Location")
    try:
        adb='adb'
        if platform.system()=="Darwin":
            adb_dir=os.path.join(TOOLSDIR, 'adb/mac/')
            subprocess.call(["chmod", "777", adb_dir])
            adb=os.path.join(TOOLSDIR , 'adb/mac/adb')
        elif platform.system()=="Linux":
            adb_dir=os.path.join(TOOLSDIR, 'adb/linux/')
            subprocess.call(["chmod", "777", adb_dir])
            adb=os.path.join(TOOLSDIR , 'adb/linux/adb')
        elif platform.system()=="Windows":
            adb=os.path.join(TOOLSDIR , 'adb/windows/adb.exe')
        return adb
    except Exception as e:
        print ("\n[ERROR] Getting ADB Location - "+str(e))
        return "adb"

adb = getADB(TOOLSDIR)
raw_input("Remove your Android device if already connected and press [enter]:")
ExecuteCMD([adb, "kill-server"])
raw_input("Connect your Rooted Android Device and press [enter]:")
ExecuteCMD([adb, "wait-for-device"])
res = ExecuteCMD([adb, "devices"],True)
res = res.split("\n")
if "device" in res[1]:
    res = ExecuteCMD([adb, "shell", "netcfg"], True)
    res = res.split("\n")
    for line in res:
        if "wlan" in line:
            print line
    #ExecuteCMD([adb, "kill-server"])
    ExecuteCMD([adb, "tcpip", "5556"])

else:
    print "\n[INFO] Device is not connected or ADB cannot conect to your Device. Make sure that you have installed necessary USB drivers and enabled USB Debugging in Developer options."



