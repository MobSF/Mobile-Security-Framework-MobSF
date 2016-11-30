import os
import platform
import random
import subprocess
import re
import sys
import linecache
import time
import datetime
import ntpath
import hashlib
import urllib2
import io
import ast
import unicodedata
import httplib
import settings


def printMobSFverison():
    if platform.system() == "Windows":
        print '\n\nMobile Security Framework ' + settings.MOBSF_VER
    else:
        print '\n\n\033[1m\033[34mMobile Security Framework ' + settings.MOBSF_VER + '\033[0m'
    print settings.BANNER
    print "OS: " + platform.system()
    print "Platform: " + platform.platform()
    if platform.dist()[0]:
        print "Dist: " + str(platform.dist())
    check_update()

def check_update():
    try:
        print "\n[INFO] Checking for Update."
        github_url = "https://raw.githubusercontent.com/ajinabraham/Mobile-Security-Framework-MobSF/master/MobSF/settings.py"
        response = urllib2.urlopen(github_url)
        html = response.read().split("\n")
        for line in html:
            if line.startswith("MOBSF_VER"):
                line = line.replace("MOBSF_VER", "").replace('"', '')
                line = line.replace("=", "").strip()
                if line != settings.MOBSF_VER:
                    print """\n[WARN] A new version of MobSF is available,
Please update from master branch or check for new releases.\n"""
                else:
                    print "\n[INFO] No updates available."
    except (urllib2.HTTPError, httplib.HTTPException):
        print "\n[WARN] Cannot check for updates.. No Internet Connection Found."
        return
    except:
        PrintException("[ERROR] Cannot Check for updates.")

def createUserConfig(MobSF_HOME):
    try:
        CONFIG_PATH = os.path.join(MobSF_HOME, 'config.py')
        if isFileExists(CONFIG_PATH) == False:
            SAMPLE_CONF = os.path.join(settings.BASE_DIR, "MobSF/settings.py")
            with io.open(SAMPLE_CONF, mode='r', encoding="utf8", errors="ignore") as f:
                dat = f.readlines()
            CONFIG = list()
            add = False
            for line in dat:
                if "^CONFIG-START^" in line:
                    add = True
                if "^CONFIG-END^" in line:
                    break
                if add:
                    CONFIG.append(line.lstrip())
            CONFIG.pop(0)
            COMFIG_STR = ''.join(CONFIG)
            with io.open(CONFIG_PATH, mode='w', encoding="utf8", errors="ignore") as f:
                f.write(COMFIG_STR)
    except:
        PrintException("[ERROR] Cannot create config file")


def getMobSFHome(useHOME):
    try:
        MobSF_HOME = ""
        if useHOME:
            MobSF_HOME = os.path.join(os.path.expanduser('~'), ".MobSF")
            # MobSF Home Directory
            if not os.path.exists(MobSF_HOME):
                os.makedirs(MobSF_HOME)
            createUserConfig(MobSF_HOME)
        else:
            MobSF_HOME = settings.BASE_DIR
        # Logs Directory
        LOG_DIR = os.path.join(MobSF_HOME, 'logs/')
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
        # Certs Directory
        CERT_DIR = os.path.join(LOG_DIR, 'certs/')
        if not os.path.exists(CERT_DIR):
            os.makedirs(CERT_DIR)
        # Download Directory
        DWD_DIR = os.path.join(MobSF_HOME, 'downloads/')
        if not os.path.exists(DWD_DIR):
            os.makedirs(DWD_DIR)
        # Screenshot Directory
        SCREEN_DIR = os.path.join(DWD_DIR, 'screen/')
        if not os.path.exists(SCREEN_DIR):
            os.makedirs(SCREEN_DIR)
        # Upload Directory
        UPLD_DIR = os.path.join(MobSF_HOME, 'uploads/')
        if not os.path.exists(UPLD_DIR):
            os.makedirs(UPLD_DIR)
        return MobSF_HOME
    except:
        PrintException("[ERROR] Creating MobSF Home Directory")


def Migrate(BASE_DIR):
    try:
        manage = os.path.join(BASE_DIR, "manage.py")
        args = ["python", manage, "migrate"]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Cannot Migrate")


def kali_fix(BASE_DIR):
    try:
        if platform.system() == "Linux" and platform.dist()[0] == "Kali":
            fix_path = os.path.join(BASE_DIR, "MobSF/kali_fix.sh")
            subprocess.call(["chmod", "a+x", fix_path])
            subprocess.call([fix_path], shell=True)
    except:
        PrintException("[ERROR] Cannot run Kali Fix")


def FindVbox():
    try:
        if settings.REAL_DEVICE == False:
            if len(settings.VBOXMANAGE_BINARY) > 0 and isFileExists(settings.VBOXMANAGE_BINARY):
                return settings.VBOXMANAGE_BINARY
            if platform.system() == "Windows":
                # Path to VBoxManage.exe
                vbox_path = ["C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
                             "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"]
                for path in vbox_path:
                    if os.path.isfile(path):
                        return path
            else:
                # Path to VBoxManage in Linux/Mac
                vbox_path = ["/usr/bin/VBoxManage",
                             "/usr/local/bin/VBoxManage"]
                for path in vbox_path:
                    if os.path.isfile(path):
                        return path
            print "\n[WARNING] Could not find VirtualBox path."
    except:
        PrintException("[ERROR] Cannot find VirtualBox path.")

# Maintain JDK Version
JAVA_VER = '1.7|1.8|1.9|2.0|2.1|2.2|2.3'


def FindJava():
    try:
        if len(settings.JAVA_DIRECTORY) > 0 and isDirExists(settings.JAVA_DIRECTORY):
            return settings.JAVA_DIRECTORY
        if platform.system() == "Windows":
            print "\n[INFO] Finding JDK Location in Windows...."
            # JDK 7 jdk1.7.0_17/bin/
            WIN_JAVA_LIST = ["C:/Program Files/Java/",
                             "C:/Program Files (x86)/Java/"]
            for WIN_JAVA_BASE in WIN_JAVA_LIST:
                JDK = []
                for dirname in os.listdir(WIN_JAVA_BASE):
                    if "jdk" in dirname:
                        JDK.append(dirname)
                if len(JDK) == 1:
                    print "\n[INFO] Oracle JDK Identified. Looking for JDK 1.7 or above"
                    j = ''.join(JDK)
                    if re.findall(JAVA_VER, j):
                        WIN_JAVA = WIN_JAVA_BASE + j + "/bin/"
                        args = [WIN_JAVA + "java"]
                        dat = RunProcess(args)
                        if "oracle" in dat:
                            print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
                            return WIN_JAVA
                elif len(JDK) > 1:
                    print "\n[INFO] Multiple JDK Instances Identified. Looking for JDK 1.7 or above"
                    for j in JDK:
                        if re.findall(JAVA_VER, j):
                            WIN_JAVA = WIN_JAVA_BASE + j + "/bin/"
                            break
                        else:
                            WIN_JAVA = ""
                    if len(WIN_JAVA) > 1:
                        args = [WIN_JAVA + "java"]
                        dat = RunProcess(args)
                        if "oracle" in dat:
                            print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
                            return WIN_JAVA
            PrintException("[ERROR] Oracle JDK 1.7 or above is not found!")
            return ""
        else:
            print "\n[INFO] Finding JDK Location in Linux/MAC...."
            MAC_LINUX_JAVA = "/usr/bin/"
            args = [MAC_LINUX_JAVA + "java"]
            dat = RunProcess(args)
            if "oracle" in dat:
                print "\n[INFO] Oracle Java is installed!"
                args = [MAC_LINUX_JAVA + "java", '-version']
                dat = RunProcess(args)
                f_line = dat.split("\n")[0]
                if re.findall(JAVA_VER, f_line):
                    print "\n[INFO] JDK 1.7 or above is available"
                    return MAC_LINUX_JAVA
                else:
                    PrintException(
                        "[ERROR] Please install Oracle JDK 1.7 or above")
                    return ""
            else:
                PrintException(
                    "[ERROR] Oracle Java JDK 1.7 or above is not found!")
                return ""
    except:
        PrintException("[ERROR] Oracle Java (JDK >=1.7) is not found!")
        return ""


def RunProcess(args):
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,)
        dat = ''
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            dat += line
        return dat
    except:
        PrintException("[ERROR] Finding Java path - Cannot Run Process")
        return ""


class Color(object):
    GREEN = '\033[92m'
    ORANGE = '\033[33m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def PrintException(msg, web=False):
    try:
        LOGPATH = settings.LOG_DIR
    except:
        LOGPATH = os.path.join(settings.BASE_DIR, "logs/")
    if not os.path.exists(LOGPATH):
        os.makedirs(LOGPATH)
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    dat = '\n[' + st + ']\n' + msg + \
        ' ({0}, LINE {1} "{2}"): {3}'.format(
            filename, lineno, line.strip(), exc_obj)
    if platform.system() == "Windows":
        print dat
    else:
        if web:
            print Color.BOLD + Color.ORANGE + dat + Color.END
        else:
            print Color.BOLD + Color.RED + dat + Color.END
    with open(LOGPATH + 'MobSF.log', 'a') as f:
        f.write(dat)


def filename_from_path(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def getMD5(data):
    return hashlib.md5(data).hexdigest()


def findBetween(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    try:
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass
    return False


def python_list(value):
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)


def python_dict(value):
    if not value:
        value = {}
    if isinstance(value, dict):
        return value
    return ast.literal_eval(value)


def isBase64(str):
    return re.match('^[A-Za-z0-9+/]+[=]{0,2}$', str)


def isInternetAvailable():
    try:
        urllib2.urlopen('http://216.58.220.46', timeout=5)
        return True
    except urllib2.URLError as err:
        try:
            urllib2.urlopen('http://180.149.132.47', timeout=5)
            return True
        except urllib2.URLError as err1:
            return False
    return False


def sha256(file_path):
    BLOCKSIZE = 65536
    hasher = hashlib.sha256()
    with io.open(file_path, mode='rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while buf:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return (hasher.hexdigest())


def isFileExists(file_path):
    if os.path.isfile(file_path):
        return True
    else:
        return False


def isDirExists(dir_path):
    if os.path.isdir(dir_path):
        return True
    else:
        return False


def genRandom():
    return ''.join([random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)') for i in range(50)])


def zipdir(path, zip_file):
    """Zip a directory."""
    try:
        print "[INFO] Zipping"
        # pylint: disable=unused-variable
        # Needed by os.walk
        for root, _sub_dir, files in os.walk(path):
            for file_name in files:
                zip_file.write(os.path.join(root, file_name))
    except:
        PrintException("[ERROR] Zipping")
