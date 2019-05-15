@echo off
.\venv\Scripts\activate && waitress-serve --listen=*:8000  --channel-timeout=1800 MobSF.wsgi:application
