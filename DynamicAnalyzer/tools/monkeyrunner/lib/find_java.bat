@echo off
rem Copyright (C) 2007 The Android Open Source Project
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

rem This script is called by the other batch files to find a suitable Java.exe
rem to use. The script changes the "java_exe" env variable. The variable
rem is left unset if Java.exe was not found.

rem Useful links:
rem Command-line reference:
rem   http://technet.microsoft.com/en-us/library/bb490890.aspx

rem Check we have a valid Java.exe in the path. The return code will
rem be 0 if the command worked or 1 if the exec failed (program not found).
for /f %%a in ('%~dps0\find_java.exe -s') do set java_exe=%%a
if not defined java_exe goto :CheckFailed

:SearchJavaW
rem Check if we can find a javaw.exe at the same location than java.exe.
rem If that doesn't work, just fall back on the java.exe we just found.
for /f %%a in ('%~dps0\find_java.exe -s -w') do set javaw_exe=%%a
if not exist %javaw_exe% set javaw_exe=%java_exe%
goto :EOF


:CheckFailed
echo.
echo ERROR: No suitable Java found. In order to properly use the Android Developer
echo Tools, you need a suitable version of Java JDK installed on your system.
echo We recommend that you install the JDK version of JavaSE, available here:
echo   http://www.oracle.com/technetwork/java/javase/downloads
echo.
echo If you already have Java installed, you can define the JAVA_HOME environment
echo variable in Control Panel / System / Avanced System Settings to point to the
echo JDK folder.
echo.
echo You can find the complete Android SDK requirements here:
echo   http://developer.android.com/sdk/requirements.html
echo.
goto :EOF
