@echo off
setlocal
cd /d "%~dp0"

set "PY=C:\Users\Anand\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"

title GhostDrive
echo Starting GhostDrive...
echo The browser will open automatically.
echo Close this window or press Ctrl+C to stop the server.
echo.

"%PY%" -m ghostdrive

echo.
echo GhostDrive has stopped.
pause
