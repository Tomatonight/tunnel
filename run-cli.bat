@echo off
setlocal
where py >nul 2>nul
if errorlevel 1 (set "PYTHON=python") else (set "PYTHON=py -3")
if "%~1"=="" (
    %PYTHON% "%~dp0tools\tunnel_cli.py" --help
) else (
    %PYTHON% "%~dp0tools\tunnel_cli.py" --binary "%~dp0build\tunnel.exe" %*
)
exit /b %errorlevel%
