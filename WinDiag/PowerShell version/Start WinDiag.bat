@echo off
rem WinDiag launcher - double-click to start. Asks for admin rights automatically.
cd /d "%~dp0"
if not exist "%~dp0WinDiag.ps1" (
  echo WinDiag.ps1 was not found next to this file.
  pause
  exit /b 1
)
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0WinDiag.ps1"
exit /b 0
