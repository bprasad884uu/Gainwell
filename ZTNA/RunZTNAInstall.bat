@echo off
setlocal
cd /d "%~dp0"

echo Running PowerShell script...
powershell.exe -ExecutionPolicy Bypass -NoProfile -File ".\Uninstall_Forti_Install_ZTNA.ps1"

endlocal
exit /b 0
