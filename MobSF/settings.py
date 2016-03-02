"""
Django settings for MobSF project.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os,platform
import java
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/dev/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '#r$=rg*lit&!4nukg++@%k+n9#6fhkv_*a6)2t$n1b=*wpvptl'

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
if platform.system()=="Windows":
    JAVA_PATH=java.FindJava()
    #JAVA_PATH='C:/Program Files/Java/jdk1.7.0_17/bin/'  # Use "/" instead of "\" for the path and the path should end with a "/".
    VBOX='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe' #Path to VBoxManage.exe
else:
    #For OSX and Linux
    #JAVA_PATH='/usr/bin/'
    JAVA_PATH=java.FindJava()
    VBOX='/usr/bin/VBoxManage'
#==============================================

#================VM SETTINGS ==================
#VBoxManage showhdinfo "MobSF_VM_0.1-disk3.vdi"
#VM UUID
UUID='d2736249-7394-4dc6-8d6e-154aa99460b0'
#Snapshot UUID
SUUID='957de995-41c6-4f50-b260-73c530165ab6'
#VM/Device IP
VM_IP='192.168.56.101'
#=============================================

#================HOST/PROXY SETTINGS ===========
PROXY_IP='192.168.56.1' #Host/Server/Proxy IP
PORT=1337 #Proxy Port

SCREEN_IP = PROXY_IP #ScreenCast IP
SCREEN_PORT = 9339 #ScreenCast Port
#===============================================

#===============MobSF Cloud Settings============

CLOUD_SERVER = 'http://opensecurity.in:8080'
#This server validates SSRF and XXE during Web API Testing
#See the source code of the cloud server from APITester/cloud/cloud_server.py
#You can also host the cloud server. Host it on a public IP and point CLOUD_SERVER to that IP.

#===============================================

#===============UPSTREAM PROXY==================
#If you are behind any Proxy
UPSTREAM_PROXY_IP = None
UPSTREAM_PROXY_PORT =None
UPSTREAM_PROXY_USERNAME = None
UPSTREAM_PROXY_PASSWORD = None
#===============================================

#=========Path Traversal - API Testing==========
CHECK_FILE = "/etc/passwd"
RESPONSE_REGEX = "root:|nobody:"
#===============================================
#=========Rate Limit Check - API Testing========
RATE_REGISTER = 20
RATE_LOGIN = 10
#===============================================
