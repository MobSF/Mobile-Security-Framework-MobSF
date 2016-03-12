"""
Django settings for MobSF project.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os,platform
import java, vbox
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/dev/howto/deployment/checklist/

#Based on https://gist.github.com/ndarville/3452907#file-secret-key-gen-py
#SECRET_KEY = '#r$=rg*lit&!4nukg++@%k+n9#6fhkv_*a6)2t$n1b=*wpvptl'

try:
    SECRET_KEY
except NameError:
    SECRET_FILE = os.path.join(BASE_DIR, "MobSF/secret")
    try:
        SECRET_KEY = open(SECRET_FILE).read().strip()
    except IOError:
        try:
            import random
            SECRET_KEY = ''.join([random.SystemRandom().choice('abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)') for i in range(50)])
            secret = file(SECRET_FILE, 'w')
            secret.write(SECRET_KEY)
            secret.close()
        except IOError:
            Exception('Please create a %s file with random characters \
            to generate your secret key!' % SECRET_FILE)

# SECURITY WARNING: don't run with debug turned on in production!
# ^ This is fine Do not turn it off untill MobSF framework moves from Beta to Stable
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
MOBSF_VER = "v0.9.1 Beta"

print '\n\n\033[1m\033[34mMobile Security Framework '+ MOBSF_VER +'\033[0m'

# DO NOT EDIT ANYTHING ABOVE THIS
#xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
#Logs Directory
LOG_DIR=os.path.join(BASE_DIR,'logs/')
#Static Directory
STATIC_DIR=os.path.join(BASE_DIR,'static/')
#Download Directory
DWD_DIR=os.path.join(STATIC_DIR, 'downloads/')
#Upload Directory
UPLD_DIR=os.path.join(BASE_DIR,'uploads/')
#Database Directory
DB_DIR = os.path.join(BASE_DIR, 'db.sqlite3')

# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': DB_DIR,
    }
}

#==========DECOMPILER SETTINGS===============
DECOMPILER = "jd-core" 

#Two Decompilers are available 
#1. jd-core
#2. cfr
#============================================

#============JAVA SETTINGS=================== 

#JAVA_PATH='C:/Program Files/Java/jdk1.7.0_17/bin/'  # Use "/" instead of "\" for the path and the path should end with a "/".
#JAVA_PATH='/usr/bin/'

if platform.system()=="Windows":
    JAVA_PATH=java.FindJava()
    VBOX='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' #Path to VBoxManage.exe
else:
    #For OSX and Linux
    JAVA_PATH=java.FindJava()
    VBOX=vbox.FindVbox() #Path to VBoxManage in Linux/OSX

#===============DEVICE Settings=================
REAL_DEVICE = False
DEVICE_IP = '192.168.1.18'
DEVICE_ADB_PORT = 5555
DEVICE_TIMEOUT = 300
#===============================================

#================VM SETTINGS ==================
#VBoxManage showhdinfo "MobSF_VM_0.1-disk3.vdi"
#VM UUID
UUID='81c7edd3-6038-4024-9735-682bdbacab8b'
#Snapshot UUID
SUUID='434126a3-4966-42b8-9aa1-2c43028c6db5'
#IP of the MobSF VM
VM_IP='192.168.56.101'
VM_ADB_PORT = 5555
VM_TIMEOUT = 100
#=============================================

#================HOST/PROXY SETTINGS ===========
PROXY_IP='192.168.56.1' #Host/Server/Proxy IP
PORT=1337 #Proxy Port
ROOT_CA='0025aabb.0'

SCREEN_IP = PROXY_IP #ScreenCast IP
SCREEN_PORT = 9339 #ScreenCast Port
#===============================================

#===============UPSTREAM PROXY==================
#If you are behind a Proxy
UPSTREAM_PROXY_IP = None
UPSTREAM_PROXY_PORT = None
UPSTREAM_PROXY_USERNAME = None
UPSTREAM_PROXY_PASSWORD = None
#===============================================

#===============MobSF Cloud Settings============

CLOUD_SERVER = 'http://opensecurity.in:8080'
#This server validates SSRF and XXE during Web API Testing
#See the source code of the cloud server from APITester/cloud/cloud_server.py
#You can also host the cloud server. Host it on a public IP and point CLOUD_SERVER to that IP.

#===============================================

#=========Path Traversal - API Testing==========
CHECK_FILE = "/etc/passwd"
RESPONSE_REGEX = "root:|nobody:"
#===============================================

#=========Rate Limit Check - API Testing========
RATE_REGISTER = 20
RATE_LOGIN = 20
#===============================================

