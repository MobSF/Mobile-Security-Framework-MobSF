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

from django.shortcuts import render


class Color(object):
    GREEN = '\033[92m'
    ORANGE = '\033[33m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def api_key():
    """Print REST API Key"""
    secret_file = os.path.join(settings.MobSF_HOME, "secret")
    if isFileExists(secret_file):  
        try:
            api_key = open(secret_file).read().strip()
            return gen_sha256_hash(api_key)
        except:
            PrintException("[ERROR] Cannot Read API Key")

def printMobSFverison():
    """Print MobSF Version"""
    print settings.BANNER
    if platform.system() == "Windows":
        print '\n\nMobile Security Framework ' + settings.MOBSF_VER
        print "\nREST API Key: " + api_key()
    else:
        print '\n\n\033[1m\033[34mMobile Security Framework ' + settings.MOBSF_VER + '\033[0m'
        print "\nREST API Key: " + Color.BOLD +  api_key() + Color.END
    print "OS: " + platform.system()
    print "Platform: " + platform.platform()
    if platform.dist()[0]:
        print "Dist: " + str(platform.dist())
    FindJava(True)
    FindVbox(True)
    adb_binary_or32bit_support()
    check_update()


def check_update():
    try:
        print "\n[INFO] Checking for Update."
        github_url = "https://raw.githubusercontent.com/MobSF/Mobile-Security-Framework-MobSF/master/MobSF/settings.py"
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


def make_migrations(base_dir):
    """Create Database Migrations"""
    try:
        manage = os.path.join(base_dir, "manage.py")
        args = ["python", manage, "makemigrations"]
        subprocess.call(args)
        args = ["python", manage, "makemigrations", "StaticAnalyzer"]
        subprocess.call(args)
    except:
        PrintException("[ERROR] Cannot Make Migrations")


def migrate(BASE_DIR):
    """Migrate Database"""
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


def FindVbox(debug=False):
    try:
        if settings.ANDROID_DYNAMIC_ANALYZER == "MobSF_VM":
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
            if debug:
                print "\n[WARNING] Could not find VirtualBox path."
    except:
        if debug:
            PrintException("[ERROR] Cannot find VirtualBox path.")

# Maintain JDK Version
JAVA_VER = '1.7|1.8|1.9|2.0|2.1|2.2|2.3'


def FindJava(debug=False):
    try:
        err_msg1 = "[ERROR] Oracle JDK 1.7 or above is not found!"
        if len(settings.JAVA_DIRECTORY) > 0 and isDirExists(settings.JAVA_DIRECTORY):
            return settings.JAVA_DIRECTORY
        if platform.system() == "Windows":
            if debug:
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
                    j = ''.join(JDK)
                    if re.findall(JAVA_VER, j):
                        WIN_JAVA = WIN_JAVA_BASE + j + "/bin/"
                        args = [WIN_JAVA + "java"]
                        dat = RunProcess(args)
                        if "oracle" in dat:
                            if debug:
                                print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
                            return WIN_JAVA
                elif len(JDK) > 1:
                    if debug:
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
                            if debug:
                                print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
                            return WIN_JAVA
            for env in ["JDK_HOME", "JAVA_HOME"]:
                java_home = os.environ.get(env)
                if java_home and os.path.isdir(java_home):
                    j = os.path.basename(java_home)
                    if re.findall(JAVA_VER, j):
                        WIN_JAVA = java_home + "/bin/"
                        args = [WIN_JAVA + "java"]
                        dat = RunProcess(args)
                        if "oracle" in dat:
                            if debug:
                                print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
                            return WIN_JAVA

            if debug:
                print err_msg1
            return ""
        else:
            if debug:
                print "\n[INFO] Finding JDK Location in Linux/MAC...."
            MAC_LINUX_JAVA = "/usr/bin/"
            args = [MAC_LINUX_JAVA + "java"]
            dat = RunProcess(args)
            if "oracle" in dat:
                args = [MAC_LINUX_JAVA + "java", '-version']
                dat = RunProcess(args)
                f_line = dat.split("\n")[0]
                if re.findall(JAVA_VER, f_line):
                    if debug:
                        print "\n[INFO] JDK 1.7 or above is available"
                    return MAC_LINUX_JAVA
                else:
                    err_msg = "[ERROR] Please install Oracle JDK 1.7 or above"
                    if debug:
                        print Color.BOLD + Color.RED + err_msg + Color.END
                    return ""
            else:
                if debug:
                    print Color.BOLD + Color.RED + err_msg1 + Color.END
                return ""
    except:
        if debug:
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

def print_n_send_error_response(request, msg, api, exp='Error Description'):
    """Print and log errors"""
    print Color.BOLD + Color.RED + '[ERROR] ' + msg + Color.END
    time_stamp = time.time()
    formatted_tms = datetime.datetime.fromtimestamp(time_stamp).strftime('%Y-%m-%d %H:%M:%S')
    data = '\n[' + formatted_tms + ']\n[ERROR] ' + msg
    try:
        log_path = settings.LOG_DIR
    except:
        log_path = os.path.join(settings.BASE_DIR, "logs/")
    if not os.path.exists(log_path):
        os.makedirs(log_path)
    with open(os.path.join(log_path, 'MobSF.log'), 'a') as flip:
        flip.write(data)
    if api:
        api_response = {"error": msg}
        return api_response
    else:
        context = {
            'title': 'Error',
            'exp': exp,
            'doc': msg
        }
        template = "general/error.html"
        return render(request, template, context, status=500)


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

def gen_sha256_hash(msg):
    """Generate SHA 256 Hash of the message"""
    hash_object = hashlib.sha256(msg)
    return hash_object.hexdigest()

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


def getADB(TOOLSDIR):
    """Get ADB binary path"""
    try:
        if len(settings.ADB_BINARY) > 0 and isFileExists(settings.ADB_BINARY):
            return settings.ADB_BINARY
        else:
            adb = 'adb'
            if platform.system() == "Darwin":
                adb_dir = os.path.join(TOOLSDIR, 'adb/mac/')
                subprocess.call(["chmod", "777", adb_dir])
                adb = os.path.join(TOOLSDIR, 'adb/mac/adb')
            elif platform.system() == "Linux":
                adb_dir = os.path.join(TOOLSDIR, 'adb/linux/')
                subprocess.call(["chmod", "777", adb_dir])
                adb = os.path.join(TOOLSDIR, 'adb/linux/adb')
            elif platform.system() == "Windows":
                adb = os.path.join(TOOLSDIR, 'adb/windows/adb.exe')
            return adb
    except:
        PrintException("[ERROR] Getting ADB Location")
        return "adb"


def adb_binary_or32bit_support():
    """Check if 32bit is supported. Also if the binary works"""
    tools_dir = os.path.join(
        settings.BASE_DIR, 'DynamicAnalyzer/tools/')
    adb_path = getADB(tools_dir)
    try:
        fnull = open(os.devnull, 'w')
        subprocess.call([adb_path], stdout=fnull, stderr=fnull)
    except:
        msg = "\n[WARNING] You don't have 32 bit execution support enabled or MobSF shipped" \
            " ADB binary is not compatible with your OS."\
            "\nPlease set the 'ADB_BINARY' path in settings.py"
        if platform.system != "Windows":
            print Color.BOLD + Color.ORANGE + msg + Color.END
        else:
            print msg
