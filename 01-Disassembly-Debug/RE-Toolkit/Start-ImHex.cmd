@echo off
rem ImHex 1.38.1 - hex editor + pattern-language (`.hexpat`) file parser IDE.
rem Portable build ships two entry points: imhex-gui.exe (GUI, launched here) and
rem imhex.exe, which is the same app with the CLI switch (`imhex.exe --version-short`,
rem `imhex.exe --plugins`, `imhex.exe -o file.bin`); there is no ImHex.exe/imhex-cli.exe.
start "" "%~dp0..\ImHex\imhex-gui.exe" %*
