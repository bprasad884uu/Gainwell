@echo off
setlocal enabledelayedexpansion

REM Define the password policy settings
echo.
echo Setting MinimumPasswordLength.........
echo.
net accounts /MINPWLEN:0
echo.
echo Setting MinimumPasswordAge.........
echo.
net accounts /MINPWAGE:0
echo.
echo Setting MaximumPasswordAge.........
echo.
net accounts /MAXPWAGE:UNLIMITED
echo.
echo Setting PasswordHistorySize.........
echo.
net accounts /UNIQUEPW:0

echo.
echo Removing PasswordComplexity.........
echo.
@REM Powershell.exe -executionpolicy @REMotesigned -File  setPasswordComplexity.ps1

powershell.exe "secedit /export /cfg .\secpol.cfg"
powershell.exe "(gc .\secpol.cfg).replace('PasswordComplexity = 1', 'PasswordComplexity = 0') | Out-File .\secpol.cfg"
powershell.exe "secedit /configure /db $env:SystemDrive\windows\security\local.sdb /cfg .\secpol.cfg /areas SECURITYPOLICY"
powershell.exe "rm -force .\secpol.cfg -confirm:$false"

REM Get the list of active user accounts
for /f "delims=' tokens=1*" %%i in ('dir C:\Users\ /B') do (

REM Skip Administrator user
if "%%i" == "Administrator" (

REM Do nothing
echo =================================================

) else (

REM Disable "Password Never Expires" option
		echo.
		echo Disable "Password Never Expires" option.........
		echo.
        wmic useraccount where name='%%i' set PasswordExpires=False

        REM Enable "User must change password at next login" option
		echo.
		echo Enable "User must change password at next login" option.........
		echo.
        wmic useraccount where name='%%i' set PasswordChangeable=False
		net user "%%i" /logonpasswordchg:no
		net user "%%i" /passwordchg:no
		net user "%%i" /passwordreq:no
		)
)

echo Password complexity has been removed.

echo.
echo =================================================