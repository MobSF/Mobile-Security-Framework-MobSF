"""
Django settings for MobSF project.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""

import os,platform,imp
import utils

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       MOBSF FRAMEWORK CONFIGURATIONS
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#==============================================
MOBSF_VER = "v0.9.2 Beta"
utils.printMobSFverison(MOBSF_VER)
#==============================================

#==========MobSF Home Directory=================
USE_HOME = False

#True : All Uploads/Downloads will be stored in user's home directory
#False : All Uploads/Downloads will be stored in MobSF root directory
#If you need multiple users to share the scan results set this to False
#===============================================

MobSF_HOME = utils.getMobSFHome(USE_HOME)
#Logs Directory
LOG_DIR = os.path.join(MobSF_HOME, 'logs/')
#Download Directory
DWD_DIR = os.path.join(MobSF_HOME, 'downloads/')
#Screenshot Directory
SCREEN_DIR = os.path.join(MobSF_HOME, 'downloads/screen/')
#Upload Directory
UPLD_DIR = os.path.join(MobSF_HOME, 'uploads/')
#Database Directory
DB_DIR = os.path.join(MobSF_HOME, 'db.sqlite3')

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_DIR,
    }
}
#===============================================

#==========LOAD CONFIG FROM MobSF HOME==========
try:
    #Update Config from MobSF Home Directory
    if USE_HOME:
        USER_CONFIG = os.path.join(MobSF_HOME,'config.py')
        sett = imp.load_source('user_settings', USER_CONFIG)
        locals().update({k: v for k, v in sett.__dict__.items() if not k.startswith("__")})
        CONFIG_HOME = True
    else:
        CONFIG_HOME = False
except:
    utils.PrintException("[ERROR] Parsing Config") 
    CONFIG_HOME = False
#===============================================

#=============ALLOWED EXTENSIONS================
ALLOWED_EXTENSIONS = {
".txt":"text/plain",
".png":"image/png",
".zip":"application/zip",
".tar":"application/x-tar"
}
#===============================================

#=====MOBSF SECRET GENERATION AND MIGRATION=====
#Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py
try:
    SECRET_KEY
except NameError:
    SECRET_FILE = os.path.join(MobSF_HOME, "secret")
    try:
        SECRET_KEY = open(SECRET_FILE).read().strip()
    except IOError:
        try:
            SECRET_KEY = utils.genRandom()
            secret = file(SECRET_FILE, 'w')
            secret.write(SECRET_KEY)
            secret.close()
            utils.Migrate(BASE_DIR)
        except IOError:
            Exception('Please create a %s file with random characters \
            to generate your secret key!' % SECRET_FILE)
#=============================================

#============DJANGO SETTINGS =================

# SECURITY WARNING: don't run with debug turned on in production!
# ^ This is fine Do not turn it off until MobSF moves from Beta to Stable

DEBUG = True
TEMPLATE_DEBUG = True
ALLOWED_HOSTS = []
# Application definition
INSTALLED_APPS = (
    #'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'StaticAnalyzer',
    'DynamicAnalyzer',
    'MobSF',
    'APITester',
    'MalwareAnalyzer',
)
MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)
ROOT_URLCONF = 'MobSF.urls'
WSGI_APPLICATION = 'MobSF.wsgi.application'
# Internationalization
# https://docs.djangoproject.com/en/dev/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True
MEDIA_ROOT = os.path.join(BASE_DIR, 'uploads')
MEDIA_URL = '/uploads/'
TEMPLATE_DIRS = (
    os.path.join(BASE_DIR,'templates'),
    )
STATICFILES_DIRS = (
  os.path.join(BASE_DIR, 'static/'),
)
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/dev/howto/static-files/
STATIC_URL = '/static/'

#===============================================
if CONFIG_HOME:
    print "[INFO] Loading User config from: " + USER_CONFIG
else:
    '''
    IMPORTANT
    If 'USE_HOME' is set to True, then below user configuration settings are not considered.
    The user configuration will be loaded from config.py in MobSF Home directory.
    '''
    #^CONFIG-START^: Do not edit this line
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
    #==============================================
    #^CONFIG-END^: Do not edit this line

#The below code should be loaded last.
#============JAVA SETTINGS======================
JAVA_PATH=utils.FindJava()
#===============================================

#================VirtualBox Settings============
VBOX = utils.FindVbox()
#===============================================
