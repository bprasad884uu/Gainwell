@echo off
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION" /v "Outlook.exe" /t REG_DWORD /d 0x2AF9 /f
echo Registry key added successfully.
pause
