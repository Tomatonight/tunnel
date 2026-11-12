@echo off
setlocal
where py >nul 2>nul
if errorlevel 1 (set "PYTHON=python") else (set "PYTHON=py -3")
call "%~dp0stop-gui.bat" --quiet
%PYTHON% "%~dp0tools\launch_gui.py" %*
exit /b %errorlevel%
