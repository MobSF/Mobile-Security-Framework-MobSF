@echo off
rem Copyright (C) 2010 The Android Open Source Project
rem
rem Licensed under the Apache License, Version 2.0 (the "License");
rem you may not use this file except in compliance with the License.
rem You may obtain a copy of the License at
rem
rem      http://www.apache.org/licenses/LICENSE-2.0
rem
rem Unless required by applicable law or agreed to in writing, software
rem distributed under the License is distributed on an "AS IS" BASIS,
rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem See the License for the specific language governing permissions and
rem limitations under the License.

rem don't modify the caller's environment
setlocal

rem Set up prog to be the path of this script, including following symlinks,
rem and set up progdir to be the fully-qualified pathname of its directory.
set prog=%~f0

rem Change current directory and drive to where the script is, to avoid
rem issues with directories containing whitespaces.
cd /d %~dp0

rem Check we have a valid Java.exe in the path.
set java_exe=
call lib\find_java.bat
if not defined java_exe goto :EOF

set jarfile=monkeyrunner.jar
set frameworkdir=
set libdir=

if exist %frameworkdir%%jarfile% goto JarFileOk
    set frameworkdir=lib\

if exist %frameworkdir%%jarfile% goto JarFileOk
    set frameworkdir=..\framework\

:JarFileOk

set jarpath=%frameworkdir%%jarfile%

if not defined ANDROID_SWT goto QueryArch
    set swt_path=%ANDROID_SWT%
    goto SwtDone

:QueryArch

    for /f %%a in ('%java_exe% -jar %frameworkdir%archquery.jar') do set swt_path=%frameworkdir%%%a

:SwtDone

if exist %swt_path% goto SetPath
    echo SWT folder '%swt_path%' does not exist.
    echo Please set ANDROID_SWT to point to the folder containing swt.jar for your platform.
    exit /B

:SetPath

call %java_exe% -Xmx512m -Djava.ext.dirs=%frameworkdir%;%swt_path% -Dcom.android.monkeyrunner.bindir=..\framework -jar %jarpath% %*
