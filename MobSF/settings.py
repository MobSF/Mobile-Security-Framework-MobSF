"""
Django settings for MobSF project.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""

import os
import platform
import imp
from MobSF import utils

import install.windows.setup as windows_setup

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       MOBSF FRAMEWORK CONFIGURATIONS
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#==============================================

MOBSF_VER = "v0.9.3.9 Beta"
BANNER = """
  __  __       _    ____  _____        ___   ___   _____
 |  \/  | ___ | |__/ ___||  ___|_   __/ _ \ / _ \ |___ / 
 | |\/| |/ _ \| '_ \___ \| |_  \ \ / / | | | (_) |  |_ \ 
 | |  | | (_) | |_) |__) |  _|  \ V /| |_| |\__, | ___) |
 |_|  |_|\___/|_.__/____/|_|     \_/  \___(_) /_(_)____/ 

"""
#==============================================

#==========MobSF Home Directory=================
USE_HOME = False

# True : All Uploads/Downloads will be stored in user's home directory
# False : All Uploads/Downloads will be stored in MobSF root directory
# If you need multiple users to share the scan results set this to False
#===============================================

MobSF_HOME = utils.getMobSFHome(USE_HOME)
# Logs Directory
LOG_DIR = os.path.join(MobSF_HOME, 'logs/')
# Download Directory
DWD_DIR = os.path.join(MobSF_HOME, 'downloads/')
# Screenshot Directory
SCREEN_DIR = os.path.join(MobSF_HOME, 'downloads/screen/')
# Upload Directory
UPLD_DIR = os.path.join(MobSF_HOME, 'uploads/')
# Database Directory
DB_DIR = os.path.join(MobSF_HOME, 'db.sqlite3')

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_DIR,
    }
}
#Postgres DB - Install psycopg2
'''
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'mobsf',
        'USER': 'postgres',
        'PASSWORD': '',
        'HOST': 'localhost',
        'PORT': '',
    }
}
'''
#===============================================

#==========LOAD CONFIG FROM MobSF HOME==========
try:
    # Update Config from MobSF Home Directory
    if USE_HOME:
        USER_CONFIG = os.path.join(MobSF_HOME, 'config.py')
        sett = imp.load_source('user_settings', USER_CONFIG)
        locals().update(
            {k: v for k, v in sett.__dict__.items() if not k.startswith("__")})
        CONFIG_HOME = True
    else:
        CONFIG_HOME = False
except:
    utils.PrintException("[ERROR] Parsing Config")
    CONFIG_HOME = False
#===============================================

#=============ALLOWED EXTENSIONS================
ALLOWED_EXTENSIONS = {
    ".txt": "text/plain",
    ".png": "image/png",
    ".zip": "application/zip",
    ".tar": "application/x-tar"
}
#===============================================

#=============ALLOWED MIMETYPES=================

APK_MIME = [
    'application/octet-stream',
    'application/vnd.android.package-archive',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
IPA_MIME = [
    'application/iphone',
    'application/octet-stream',
    'application/x-itunes-ipa',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
ZIP_MIME = [
    'application/zip',
    'application/octet-stream',
    'application/x-zip-compressed',
    'binary/octet-stream',
]
APPX_MIME = [
    'application/octet-stream',
    'application/vns.ms-appx',
    'application/x-zip-compressed'
]

#===============================================

#=====MOBSF SECRET GENERATION AND MIGRATION=====
# Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py
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
        except IOError:
            Exception('Please create a %s file with random characters \
            to generate your secret key!' % SECRET_FILE)
        #Run Once
        utils.make_migrations(BASE_DIR)
        utils.migrate(BASE_DIR)
        utils.kali_fix(BASE_DIR)

#=============================================

#============DJANGO SETTINGS =================

# SECURITY WARNING: don't run with debug turned on in production!
# ^ This is fine Do not turn it off until MobSF moves from Beta to Stable

DEBUG = True
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
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'DIRS':
            [
                os.path.join(BASE_DIR, 'templates')
            ],
        'OPTIONS':
            {
                'debug': True,
            }
    },
]
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

    SKIP_CLASSES = [
        'android/support/', 'com/google/', 'android/content/',
        'com/android/', 'com/facebook/', 'com/twitter/',
        'twitter4j/', 'org/apache/', 'com/squareup/okhttp/',
        'oauth/signpost/', 'org/chromium/'
    ]

    #==============3rd Party Tools=================
    '''
    If you want to use a different version of 3rd party tools used by MobSF.
    You can do that by specifying the path here. If specified, MobSF will run
    the tool from this location.
    '''

    # Android 3P Tools
    DEX2JAR_BINARY = ""
    BACKSMALI_BINARY = ""
    AXMLPRINTER_BINARY = ""
    CFR_DECOMPILER_BINARY = ""
    JD_CORE_DECOMPILER_BINARY = ""
    PROCYON_DECOMPILER_BINARY = ""
    ADB_BINARY = ""
    ENJARIFY_DIRECTORY = ""

    # iOS 3P Tools
    OTOOL_BINARY = ""
    CLASSDUMPZ_BINARY = ""

    # COMMON
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
    #===============================================

    #==============RESPONSE VALIDATION==============
    XXE_VALIDATE_STRING = "m0bsfxx3"
    #===============================================

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

    # VM UUID
    UUID = '408e1874-759f-4417-9453-53ef21dc2ade'
    # Snapshot UUID
    SUUID = '5c9deb28-def6-49c0-9233-b5e03edd85c6'
    # IP of the MobSF VM
    VM_IP = '192.168.56.101'
    VM_ADB_PORT = 5555
    VM_TIMEOUT = 100
    #==============================================
    #================HOST/PROXY SETTINGS ==========

    PROXY_IP = '192.168.56.1'  # Host/Server/Proxy IP
    PORT = 1337  # Proxy Port
    ROOT_CA = '0025aabb.0'
    SCREEN_IP = PROXY_IP  # ScreenCast IP
    SCREEN_PORT = 9339  # ScreenCast Port

    #==============================================

    #========UPSTREAM PROXY SETTINGS ==============
    # If you are behind a Proxy
    UPSTREAM_PROXY_IP = None
    UPSTREAM_PROXY_PORT = None
    UPSTREAM_PROXY_USERNAME = None
    UPSTREAM_PROXY_PASSWORD = None
    #==============================================

    #==========DECOMPILER SETTINGS=================

    DECOMPILER = "cfr"

    # Three Decompilers are available
    # 1. jd-core
    # 2. cfr
    # 3. procyon

    #==============================================

    #==========Dex to Jar Converter================
    JAR_CONVERTER = "d2j"

    # Two Dex to Jar converters are available
    # 1. d2j
    # 2. enjarify

    '''
    enjarify requires python3. Install Python 3 and add the path to environment variable
    PATH or provide the Python 3 path to "PYTHON3_PATH" variable in settings.py
    ex: PYTHON3_PATH = "C:/Users/Ajin/AppData/Local/Programs/Python/Python35-32/"
    '''
    PYTHON3_PATH = ""
    #==============================================
    #================WINDOWS-Analysis-Settings ====
    # Get the OS MobSF is currently running on
    CURRENT_PLATFROM = platform.system()

    # Private key if rpc server is needed
    WINDOWS_VM_SECRET = 'MobSF/windows_vm_priv_key.asc'
    # IP and Port of the MobSF Windows VM
    # eg: WINDOWS_VM_IP = '127.0.0.1'
    WINDOWS_VM_IP = None
    WINDOWS_VM_PORT = '8000'

    # Configure here if you are on windows
    # Path to lock-file (so setup is only run once)
    PATH_TO_LOCK_FILE = os.path.join(MobSF_HOME, "setup_done.txt")
    if (os.path.isfile(PATH_TO_LOCK_FILE) is False) and CURRENT_PLATFROM == 'Windows':
        print "[INFO] Running first time setup for windows."
        # Setup is to-be-executed
        windows_setup.install_locally(MobSF_HOME)
    #==============================================
    #^CONFIG-END^: Do not edit this line

# The below code should be loaded last.
#============JAVA SETTINGS======================
JAVA_PATH = utils.FindJava(False)
#===============================================

#================VirtualBox Settings============
VBOX = utils.FindVbox(False)
#===============================================
