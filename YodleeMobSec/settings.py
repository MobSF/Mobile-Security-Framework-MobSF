"""
Django settings for YodleeMobSec project.

For more information on this file, see
https://docs.djangoproject.com/en/dev/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/dev/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/dev/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '#r$=rg*lit&!4nukg++@%k+n9#6fhkv_*a6)2t$n1b=*wpvptl'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'StaticAnalyzer',
    'DynamicAnalyzer',
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

ROOT_URLCONF = 'YodleeMobSec.urls'

WSGI_APPLICATION = 'YodleeMobSec.wsgi.application'


# Database
# https://docs.djangoproject.com/en/dev/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

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

#CUSTOM SETTINGS
#Static Analysis
#===============


JAVA_PATH='C:/Program Files/Java/jdk1.7.0_17/bin/' # remember about the /  ( not \)
#JAVA_PATH='/usr/bin/'
#Dynamic Analysis
#================
#VM SPECIFIC
VBOX='C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
#c:\Program Files\Oracle\VirtualBox>VBoxManage.exe showhdinfo "d:\YSOMobSec\DynamicAnalyzer\tools\VM\sdcard.vdi"
UUID='a4a3b417-c8f1-41ba-9d00-9d6ab88d15d3'
SUUID='6be5be25-931e-4b22-a119-739a4a39630b' #This Can Change 
#VM IP
VM_IP='192.168.0.25' #VM/Device IP
PROXY_IP='192.168.0.8' #Host/Server/Proxy IP
PORT='1337' #Proxy Port
