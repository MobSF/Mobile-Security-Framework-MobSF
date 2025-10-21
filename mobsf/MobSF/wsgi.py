"""
WSGI config for MobSF project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/
"""

import os
import warnings

from whitenoise import WhiteNoise

from django.core.wsgi import get_wsgi_application

from mobsf.MobSF import settings

warnings.filterwarnings('ignore', category=UserWarning, module='cffi')

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')

static = os.path.join(settings.BASE_DIR, 'static')
application = WhiteNoise(get_wsgi_application(), root=static, prefix='static/')
