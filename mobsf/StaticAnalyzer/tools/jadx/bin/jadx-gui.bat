@rem
@rem Copyright 2015 the original author or authors.
@rem
@rem Licensed under the Apache License, Version 2.0 (the "License");
@rem you may not use this file except in compliance with the License.
@rem You may obtain a copy of the License at
@rem
@rem      https://www.apache.org/licenses/LICENSE-2.0
@rem
@rem Unless required by applicable law or agreed to in writing, software
@rem distributed under the License is distributed on an "AS IS" BASIS,
@rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@rem See the License for the specific language governing permissions and
@rem limitations under the License.
@rem

@if "%DEBUG%"=="" @echo off
@rem ##########################################################################
@rem
@rem  jadx-gui startup script for Windows
@rem
@rem ##########################################################################

@rem Set local scope for the variables with windows NT shell
if "%OS%"=="Windows_NT" setlocal

set DIRNAME=%~dp0
if "%DIRNAME%"=="" set DIRNAME=.
set APP_BASE_NAME=%~n0
set APP_HOME=%DIRNAME%..

@rem Resolve any "." and ".." in APP_HOME to make it shorter.
for %%i in ("%APP_HOME%") do set APP_HOME=%%~fi

@rem Add default JVM options here. You can also use JAVA_OPTS and JADX_GUI_OPTS to pass JVM options to this script.
set DEFAULT_JVM_OPTS="-Xms128M" "-XX:MaxRAMPercentage=70.0" "-XX:+UseG1GC" "-Dawt.useSystemAAFontSettings=lcd" "-Dswing.aatext=true" "-Djava.util.Arrays.useLegacyMergeSort=true"

@rem Find javaw.exe
if defined JAVA_HOME goto findJavaFromJavaHome

set JAVA_EXE=javaw.exe
%JAVA_EXE% -version >NUL 2>&1
if %ERRORLEVEL% equ 0 goto execute

echo.
echo ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:findJavaFromJavaHome
set JAVA_HOME=%JAVA_HOME:"=%
set JAVA_EXE=%JAVA_HOME%/bin/javaw.exe

if exist "%JAVA_EXE%" goto execute

echo.
echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
echo.
echo Please set the JAVA_HOME variable in your environment to match the
echo location of your Java installation.

goto fail

:execute
@rem Setup the command line

set CLASSPATH=%APP_HOME%\lib\jadx-gui-1.4.5.jar;%APP_HOME%\lib\jfontchooser-1.0.5.jar;%APP_HOME%\lib\mapping-io-0.4.0-SNAPSHOT.jar;%APP_HOME%\lib\jadx-cli-1.4.5.jar;%APP_HOME%\lib\jadx-core-1.4.5.jar;%APP_HOME%\lib\logback-classic-1.3.4.jar;%APP_HOME%\lib\jadx-java-convert-1.4.5.jar;%APP_HOME%\lib\jadx-smali-input-1.4.5.jar;%APP_HOME%\lib\jadx-dex-input-1.4.5.jar;%APP_HOME%\lib\jadx-java-input-1.4.5.jar;%APP_HOME%\lib\jadx-plugins-api-1.4.5.jar;%APP_HOME%\lib\raung-disasm-0.0.2.jar;%APP_HOME%\lib\raung-common-0.0.2.jar;%APP_HOME%\lib\slf4j-api-2.0.3.jar;%APP_HOME%\lib\baksmali-2.5.2.jar;%APP_HOME%\lib\smali-2.5.2.jar;%APP_HOME%\lib\util-2.5.2.jar;%APP_HOME%\lib\jcommander-1.82.jar;%APP_HOME%\lib\rsyntaxtextarea-3.3.0.jar;%APP_HOME%\lib\image-viewer-1.2.3.jar;%APP_HOME%\lib\flatlaf-intellij-themes-2.6.jar;%APP_HOME%\lib\flatlaf-extras-2.6.jar;%APP_HOME%\lib\flatlaf-2.6.jar;%APP_HOME%\lib\svgSalamander-1.1.4.jar;%APP_HOME%\lib\gson-2.9.1.jar;%APP_HOME%\lib\commons-text-1.10.0.jar;%APP_HOME%\lib\commons-lang3-3.12.0.jar;%APP_HOME%\lib\rxjava2-swing-0.3.7.jar;%APP_HOME%\lib\rxjava-2.2.21.jar;%APP_HOME%\lib\apksig-7.3.1.jar;%APP_HOME%\lib\jdwp-2.0.0.jar;%APP_HOME%\lib\aapt2-proto-7.3.1-8691043.jar;%APP_HOME%\lib\protobuf-java-3.21.8.jar;%APP_HOME%\lib\logback-core-1.3.4.jar;%APP_HOME%\lib\javax.mail-1.6.2.jar;%APP_HOME%\lib\reactive-streams-1.0.3.jar;%APP_HOME%\lib\dexlib2-2.5.2.jar;%APP_HOME%\lib\guava-30.1.1-jre.jar;%APP_HOME%\lib\dalvik-dx-11.0.0_r3.jar;%APP_HOME%\lib\r8-3.3.75.jar;%APP_HOME%\lib\asm-9.4.jar;%APP_HOME%\lib\activation-1.1.jar;%APP_HOME%\lib\antlr-3.5.2.jar;%APP_HOME%\lib\ST4-4.0.8.jar;%APP_HOME%\lib\antlr-runtime-3.5.2.jar;%APP_HOME%\lib\stringtemplate-3.2.1.jar;%APP_HOME%\lib\jsr305-3.0.2.jar;%APP_HOME%\lib\failureaccess-1.0.1.jar;%APP_HOME%\lib\listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar;%APP_HOME%\lib\checker-qual-3.8.0.jar;%APP_HOME%\lib\error_prone_annotations-2.5.1.jar;%APP_HOME%\lib\j2objc-annotations-1.3.jar;%APP_HOME%\lib\antlr-2.7.7.jar


@rem Execute jadx-gui
start "jadx-gui" /B "%JAVA_EXE%" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %JADX_GUI_OPTS%  -classpath "%CLASSPATH%" jadx.gui.JadxGUI %*

:end
@rem End local scope for the variables with windows NT shell
if %ERRORLEVEL% equ 0 goto mainEnd

:fail
rem Set variable JADX_GUI_EXIT_CONSOLE if you need the _script_ return code instead of
rem the _cmd.exe /c_ return code!
set EXIT_CODE=%ERRORLEVEL%
if %EXIT_CODE% equ 0 set EXIT_CODE=1
if not ""=="%JADX_GUI_EXIT_CONSOLE%" exit %EXIT_CODE%
exit /b %EXIT_CODE%

:mainEnd
if "%OS%"=="Windows_NT" endlocal

:omega
