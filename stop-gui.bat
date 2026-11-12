@echo off
setlocal
where py >nul 2>nul
if errorlevel 1 (set "PYTHON=python") else (set "PYTHON=py -3")
%PYTHON% "%~dp0tools\stop_gui.py" --root "%~dp0." %*
exit /b %errorlevel%