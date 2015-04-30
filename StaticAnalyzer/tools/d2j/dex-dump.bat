@echo off
set CLASSPATH=

FOR %%i IN ("%~dp0lib\*.jar") DO CALL "%~dp0setclasspath.bat" %%i

java -Xms512m -Xmx1024m -cp "%CLASSPATH%" com.googlecode.dex2jar.util.Dump %*
