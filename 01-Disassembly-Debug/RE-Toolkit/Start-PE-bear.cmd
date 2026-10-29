@echo off
rem PE-bear 0.7.2 - PE header/section/resource viewer and hex editor (Qt6 x64).
rem GUI only; the bundled SIG.txt is the malware-signature database.
start "" "%~dp0..\PE-bear\PE-bear.exe" %*
