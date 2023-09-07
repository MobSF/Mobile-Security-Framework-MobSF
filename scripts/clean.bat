@echo off 
echo =======================MobSF Clean Script for Windows=======================
echo Running this script will delete the Scan database, all files uploaded and generated.
SET mobsf_home="%userprofile%\.MobSF"
SET mypath=%~dp0
echo %mypath:~0,-1%
IF "%~1"=="y" (
echo Deleting all uploads
rmdir "mobsf\uploads" /q /s >nul 2>&1
echo Deleting all downloads
rmdir "mobsf\downloads" /q /s >nul 2>&1
echo Deleting Static Analyzer migrations
rmdir "mobsf\StaticAnalyzer\migrations" /q /s >nul 2>&1
echo Deleting Dynamic Analyzer migrations
rmdir "mobsf\DynamicAnalyzer\migrations" /q /s >nul 2>&1
echo Deleting MobSF migrations
rmdir "mobsf\MobSF\migrations" /q /s >nul 2>&1
echo Deleting temp and log files
del /f "mobsf\debug.log" >nul 2>&1
del /f "classes*" >nul 2>&1
echo Deleting Scan database
del /f "mobsf\db.sqlite3" >nul 2>&1
echo Deleting Secret file
del /f "mobsf\secret" >nul 2>&1
echo Deleting Previous setup files
rmdir "%UserProfile%\MobSF" /q /s >nul 2>&1
del /f "mobsf\setup_done.txt" >nul 2>&1
echo Deleting MobSF data directory: %mobsf_home%
del /f "%mobsf_home%" /q /s >nul 2>&1
echo Done
) ELSE ( 
echo Please run script from mobsf.MobSF directory
echo 'scripts/clean.bat y
)
