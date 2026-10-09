@echo off
rem Runs WinDiag with a visible console so any errors can be seen.
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -NoExit -File "%~dp0WinDiag.ps1" -NoElevate
