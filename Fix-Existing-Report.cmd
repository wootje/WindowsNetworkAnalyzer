@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Apply-Responsive-Layout.ps1"
) else (
  powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Apply-Responsive-Layout.ps1" -InputHtml "%~1"
)
set "Result=%ERRORLEVEL%"
echo.
pause
exit /b %Result%
