@echo off
cd "C:\Program Files\Microsoft Office\Office16"
ospprearm.exe

:: Delete the script itself after execution
del /f /q "%~f0"
exit