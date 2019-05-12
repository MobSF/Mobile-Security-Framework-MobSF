@echo off
.\venv\Scripts\activate && gunicorn -b 0.0.0.0:8000 MobSF.wsgi:application --workers=1 --timeout=1800
