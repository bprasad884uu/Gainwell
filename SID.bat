@echo off
setlocal enabledelayedexpansion

for /d %%j in (C:\Users\*) do (
    set "username=%%~nxj"  REM Extract only the username part without the full path

    for /f "tokens=2 delims==" %%a in ('wmic useraccount where name^="%username%" get sid /value ^| find "="') do (
        set "sid=%%a"
    )

    echo SID for !username! is: !sid!
)

endlocal
pause
