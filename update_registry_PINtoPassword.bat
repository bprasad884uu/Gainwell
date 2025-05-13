@echo off
setlocal enabledelayedexpansion

set "key=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile"
set "newValue={60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"

for /f "tokens=*" %%a in ('reg query "%key%" ^| findstr /r /c:"REG_"') do (
    set "value=%%a"
    reg add "%key%" /v "!value!" /t REG_SZ /d "%newValue%" /f
)

echo Password Login Activated.
