@echo off

if [%1]==[] goto usage
SET conf=%1
goto :run
:usage
SET conf="0.0.0.0:8000 [::]:8000"
:run
echo Running MobSF on %conf%
call poetry run waitress-serve --listen=%conf% --threads=10 --channel-timeout=3600 mobsf.MobSF.wsgi:application
set "MOBSF_EXIT_CODE=%ERRORLEVEL%"
call poetry run python manage.py cleanup_android
exit /b %MOBSF_EXIT_CODE%
