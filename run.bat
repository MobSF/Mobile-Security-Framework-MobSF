@echo off
.\venv\Scripts\activate && waitress-serve --listen=127.0.0.1:8000 --threads=10 --channel-timeout=1800 MobSF.wsgi:application
