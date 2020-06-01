#!/bin/bash
# Dev Server
#. venv/bin/activate && python manage.py runserver
# Prod Server
. venv/bin/activate && gunicorn -b 127.0.0.1:8000 MobSF.wsgi:application --workers=1 --threads=10 --timeout=1800
