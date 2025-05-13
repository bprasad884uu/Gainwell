@echo off
call C:\Windows\Setup\Scripts\RearmOffice.bat

call C:\Windows\Setup\Scripts\RemoveWindowsOld.bat

:: Delete the script itself after execution
rd /s /q C:\Windows.old
del /f /q "%~f0"
exit