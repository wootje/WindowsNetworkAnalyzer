@echo off
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-Network-Analyzer.ps1" -Interactive
if errorlevel 1 (
  echo.
  echo An error occurred. Please keep the error message above.
  pause
)
endlocal
