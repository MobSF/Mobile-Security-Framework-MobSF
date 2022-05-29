@echo off
waitress-serve.exe --listen=0.0.0.0:8000 --threads=10 --channel-timeout=3600 mobsf.MobSF.wsgi:application
