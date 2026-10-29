@echo off
rem  Put the frida venv + Android platform-tools on PATH for the current shell:
rem      call <this folder>\env.cmd
rem  Then you can just run:  adb devices | frida-ps -U | frida -U -f <pkg> -l <script.js>
set "PATH=%~dp0.venv\Scripts;%~dp0platform-tools;%PATH%"
echo [frida] PATH ready:
echo    frida / frida-ps / frida-trace  -^> %~dp0.venv\Scripts
echo    adb                            -^> %~dp0platform-tools