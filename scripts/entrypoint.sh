#!/bin/bash
set -e 

pipenv run python3 manage.py makemigrations && \
pipenv run python3 manage.py makemigrations StaticAnalyzer && \
pipenv run python3 manage.py migrate

pipenv run gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600
