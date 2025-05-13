@echo off
call C:\Windows\Setup\Scripts\RearmOffice.bat

:: Delete the script itself after execution
rd /s /q C:\Windows.old
del /f /q "%~f0"
exit