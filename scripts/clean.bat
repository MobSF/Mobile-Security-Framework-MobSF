@echo off 
echo =======================MobSF Clean Script for Windows=======================
echo Running this script will delete the Scan database, all files uploaded and generated.
SET mypath=%~dp0
echo %mypath:~0,-1%
IF "%~1"=="y" (
echo Deleting all Uploads
rmdir "uploads" /q /s >nul 2>&1
echo Deleting all Downloads
rmdir "downloads" /q /s >nul 2>&1
echo Deleting Static Analyzer Migrations
rmdir "StaticAnalyzer\migrations" /q /s >nul 2>&1
echo Deleting Dynamic Analyzer Migrations
rmdir "DynamicAnalyzer\migrations" /q /s >nul 2>&1
echo Deleting MobSF Migrations
rmdir "MobSF\migrations" /q /s >nul 2>&1
echo Deleting temp and log files
rmdir "logs" /q /s >nul 2>&1
del /f "classes*" >nul 2>&1
echo Deleting DB
del /f "db.sqlite3" >nul 2>&1
echo Deleting Secret File
del /f "secret" >nul 2>&1
echo Deleting Previous Setup files
rmdir "%UserProfile%\MobSF" /q /s >nul 2>&1
del /f "setup_done.txt" >nul 2>&1
echo Done
) ELSE ( 
echo Please run script from MobSF directory
echo 'scripts/clean.bat y
)