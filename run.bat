@echo off

if [%1]==[] goto usage
SET conf=%1
goto :run
:usage
SET conf="0.0.0.0:8000"
:run
.\venv\Scripts\activate && waitress-serve --listen=%conf% --threads=10 --channel-timeout=3600 MobSF.wsgi:application
