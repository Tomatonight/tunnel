@echo off
setlocal
where py >nul 2>nul
if %errorlevel%==0 (set "PYTHON=py -3") else (set "PYTHON=python")
if exist "%~dp0build\gui\TunnelUI\TunnelUI.exe" (
    "%~dp0build\gui\TunnelUI\TunnelUI.exe" %*
) else (
    %PYTHON% "%~dp0gui\main.py" --binary "%~dp0build\tunnel.exe" %*
)
