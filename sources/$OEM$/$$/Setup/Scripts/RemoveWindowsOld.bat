@echo off

schtasks /create /tn "DeleteWindowsOld" /tr "cmd /c rd /s /q C:\Windows.old & call schtasks /delete /tn DeleteWindowsOld /f" /sc onlogon /ru System /rl highest /f

:: Delete the script itself after execution
del /f /q "%~f0"
exit