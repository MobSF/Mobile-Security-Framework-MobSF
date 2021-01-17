"""
WSGI config for MobSF project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/
"""
import os
import warnings

from django.core.wsgi import get_wsgi_application

from whitenoise import WhiteNoise


warnings.filterwarnings('ignore', category=UserWarning, module='cffi')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mobsf.MobSF.settings')

application = WhiteNoise(get_wsgi_application(),
                         root='mobsf/static', prefix='static/')
