#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#          MOBSF USER CONFIGURATIONS
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

#==========SKIP CLASSES==========================
SKIP_CLASSES = ['android/support/','com/google/','android/content/','com/android/',
'com/facebook/','com/twitter/','twitter4j/','org/apache/','com/squareup/okhttp/',
'oauth/signpost/','org/chromium/']

#==============3rd Party Tools=================
'''
If you want to use a different version of 3rd party tools used by MobSF. 
You can do that by specifying the path here. If specified, MobSF will run
the tool from this location.
'''

#Android 3P Tools
DEX2JAR_BINARY = ""
BACKSMALI_BINARY = ""
AXMLPRINTER_BINARY = ""
CFR_DECOMPILER_BINARY = ""
JD_CORE_DECOMPILER_BINARY = ""
PROCYON_DECOMPILER_BINARY = ""
ADB_BINARY = ""
ENJARIFY_DIRECTORY = ""

#iOS 3P Tools
OTOOL_BINARY = ""
CLASSDUMPZ_BINARY = ""

#COMMON
JAVA_DIRECTORY = ""
VBOXMANAGE_BINARY = ""

'''
Examples:
JAVA_DIRECTORY = "C:/Program Files/Java/jdk1.7.0_17/bin/"
JAVA_DIRECTORY = "/usr/bin/"
DEX2JAR_BINARY = "/Users/ajin/dex2jar/d2j_invoke.sh"
ENJARIFY_DIRECTORY = "D:/enjarify/"
VBOXMANAGE_BINARY = "/usr/bin/VBoxManage"
CFR_DECOMPILER_BINARY = "/home/ajin/tools/cfr.jar"
'''
#==============================================

#=========Path Traversal - API Testing==========
CHECK_FILE = "/etc/passwd"
RESPONSE_REGEX = "root:|nobody:"
#===============================================

#=========Rate Limit Check - API Testing========
RATE_REGISTER = 20
RATE_LOGIN = 20
#===============================================

#===============MobSF Cloud Settings============
CLOUD_SERVER = 'http://opensecurity.in:8080'
'''
This server validates SSRF and XXE during Web API Testing
See the source code of the cloud server from APITester/cloud/cloud_server.py
You can also host the cloud server. Host it on a public IP and point CLOUD_SERVER to that IP.
'''

#===============DEVICE SETTINGS=================
REAL_DEVICE = False
DEVICE_IP = '192.168.1.18'
DEVICE_ADB_PORT = 5555
DEVICE_TIMEOUT = 300
#===============================================
#================VM SETTINGS ===================
#VM UUID
UUID='81c7edd3-6038-4024-9735-682bdbacab8b'
#Snapshot UUID
SUUID='434126a3-4966-42b8-9aa1-2c43028c6db5'
#IP of the MobSF VM
VM_IP='192.168.56.101'
VM_ADB_PORT = 5555
VM_TIMEOUT = 100
#==============================================

#================HOST/PROXY SETTINGS ==========
PROXY_IP='192.168.56.1' #Host/Server/Proxy IP
PORT=1337 #Proxy Port
ROOT_CA='0025aabb.0'
SCREEN_IP = PROXY_IP #ScreenCast IP
SCREEN_PORT = 9339 #ScreenCast Port
#==============================================

#========UPSTREAM PROXY SETTINGS ==============
#If you are behind a Proxy
UPSTREAM_PROXY_IP = None
UPSTREAM_PROXY_PORT = None
UPSTREAM_PROXY_USERNAME = None
UPSTREAM_PROXY_PASSWORD = None
#==============================================

#==========DECOMPILER SETTINGS=================

DECOMPILER = "jd-core"
#Two Decompilers are available 
#1. jd-core
#2. cfr
#3. procyon
#==============================================

#==========Dex to Jar Converter================
JAR_CONVERTER = "d2j"
#Two Dex to Jar converters are available 
#1. d2j
#2. enjarify

'''
enjarify requires python3. Install Python 3 and add the path to environment variable 
PATH or provide the Python 3 path to "PYTHON3_PATH" variable in settings.py
ex: PYTHON3_PATH = "C:/Users/Ajin/AppData/Local/Programs/Python/Python35-32/"
'''
PYTHON3_PATH = ""