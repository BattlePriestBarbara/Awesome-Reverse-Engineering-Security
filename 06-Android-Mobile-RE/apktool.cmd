@echo off
rem Apktool 3.0.3 - decode / rebuild / sign Android APKs.
rem Runs on the toolkit's own JDK (04-Runtimes\jdk25), no system Java required.
rem usage:
rem   apktool.cmd d app.apk -o out_dir        (decode to smali + resources)
rem   apktool.cmd b out_dir -o patched.apk    (rebuild)
rem   apktool.cmd if app.apk                  (print framework/apktool info)
"%~dp0..\04-Runtimes\jdk25\bin\java.exe" -jar "%~dp0Apktool\apktool_3.0.3.jar" %*
