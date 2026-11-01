@echo off
setlocal
where py >nul 2>nul
if %errorlevel%==0 (set "PYTHON=py -3") else (set "PYTHON=python")
if "%~1"=="" (
    %PYTHON% "%~dp0tools\tunnel_cli.py" --help
) else (
    %PYTHON% "%~dp0tools\tunnel_cli.py" --binary "%~dp0build\tunnel.exe" %*
)
