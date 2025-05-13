@echo off

setlocal ENABLEEXTENSIONS
for /f "tokens=3" %%a in ('reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI /v SelectedUserSID ^| findstr SelectedUserSID') do set SID=%%a

REM Set the SelectedTheme value
reg add "HKEY_USERS\%SID%\Software\SAP\General\Appearance" /v "SelectedTheme" /t REG_DWORD /d 1 /f

REM Set the Customize values
reg add "HKEY_USERS\%SID%\Software\SAP\SAPGUI Front\SAP Frontend Server\Customize" /v "CustomFont.Facename" /t REG_SZ /d "Courier New" /f
reg add "HKEY_USERS\%SID%\Software\SAP\SAPGUI Front\SAP Frontend Server\Customize" /v "Font.Facename" /t REG_SZ /d "Courier New" /f
reg add "HKEY_USERS\%SID%\Software\SAP\SAPGUI Front\SAP Frontend Server\Customize" /v "Font.Height" /t REG_DWORD /d 13 /f

REM Applying Security Level to Allow
reg add "HKEY_USERS\%SID%\Software\SAP\SAPGUI Front\SAP Frontend Server\Security" /v "SecurityLevel" /t REG_DWORD /d 0 /f

echo SAP Signature Theme and Security Level Applied.
