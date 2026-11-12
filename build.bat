@echo off
setlocal
where py >nul 2>nul
if errorlevel 1 (set "PYTHON=python") else (set "PYTHON=py -3")
%PYTHON% "%~dp0scripts\build.py" %*
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)
exit /b 0
