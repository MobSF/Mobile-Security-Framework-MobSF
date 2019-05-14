@echo off
.\venv\Scripts\activate && waitress-serve --listen=*:8000 MobSF.wsgi:application --channel-timeout=1800
