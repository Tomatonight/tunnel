@echo off
setlocal
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 "%~dp0scripts\build.py" %*
) else (
    python "%~dp0scripts\build.py" %*
)
if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)
echo.
echo Build succeeded. Use build\tunnel.exe or build\gui\TunnelUI\TunnelUI.exe.
pause
