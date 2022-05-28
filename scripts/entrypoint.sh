#!/bin/bash
set -e 

python3 manage.py makemigrations && \
python3 manage.py makemigrations StaticAnalyzer && \
python3 manage.py migrate

gunicorn -b $1 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600
