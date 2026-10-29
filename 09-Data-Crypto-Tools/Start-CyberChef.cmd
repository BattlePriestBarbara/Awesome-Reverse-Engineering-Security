@echo off
rem CyberChef 11.5.0 - offline "cyber swiss army knife" (encode/decode/crypto/parse).
rem The zip only ships index.html.gz / .br, so index.html was restored from the .gz;
rem its web workers refuse to start from file://, hence the loopback HTTP server.
rem Uses the toolkit's own venv python (08-Python-RE-Toolchain\.venv) - no PATH setup.
setlocal
set "CCDIR=%~dp0CyberChef"
set "PORT=8765"
start "" /min "%~dp0..\08-Python-RE-Toolchain\.venv\Scripts\python.exe" -m http.server %PORT% --bind 127.0.0.1 --directory "%CCDIR%"
timeout /t 2 >nul
start "" "http://127.0.0.1:%PORT%/index.html"
endlocal
