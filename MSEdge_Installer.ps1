
#requires -Version 5.1

$ErrorActionPreference = "Stop"

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

$PackageId = "Microsoft.Edge"
$EdgeAppGuid = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"

# --------------------------------------------------
# FIND WINGET
# --------------------------------------------------

$Winget = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller*\winget.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if (!$Winget) {
    Write-Host "WinGet not found."
    exit 1
}

$WingetPath = $Winget.FullName

# --------------------------------------------------
# FIND EDGE INSTALLATION
# --------------------------------------------------

$EdgePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
)

$EdgeExe = $EdgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (!$EdgeExe) {
    Write-Host "Microsoft Edge installation not found."
    exit 1
}

# --------------------------------------------------
# GET INSTALLED VERSION FROM WINGET
# --------------------------------------------------

$ListOutput = & $WingetPath list --id $PackageId --exact --accept-source-agreements --disable-interactivity 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "Unable to detect installed Edge version using WinGet."
    exit 1
}

$ListText = $ListOutput -join "`n"

$InstalledMatch = [regex]::Match($ListText, '(?im)^.*?\bMicrosoft\.Edge\s+([0-9][^\s]*)')

if (!$InstalledMatch.Success) {
    Write-Host "Installed Edge version not found in WinGet."
    exit 1
}

$InstalledVersion = $InstalledMatch.Groups[1].Value

# --------------------------------------------------
# CHECK AVAILABLE VERSION
# --------------------------------------------------

$ShowOutput = & $WingetPath show --id $PackageId --exact --source winget --accept-source-agreements --disable-interactivity 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "Unable to check available Edge version."
    exit 1
}

$ShowText = $ShowOutput -join "`n"

$VersionMatch = [regex]::Match($ShowText, '(?im)^\s*Version\s*:\s*(\S+)')

if (!$VersionMatch.Success) {
    Write-Host "Unable to identify available Edge version."
    exit 1
}

$AvailableVersion = $VersionMatch.Groups[1].Value

# --------------------------------------------------
# COMPARE VERSIONS
# --------------------------------------------------

try {
    $Installed = [version]($InstalledVersion -split '-')[0]
    $Available = [version]($AvailableVersion -split '-')[0]
    $ExecutableVersion = (Get-Item $EdgeExe).VersionInfo.ProductVersion
    $Executable = [version]($ExecutableVersion -split '-')[0]
}
catch {
    Write-Host "Version comparison failed."
    exit 1
}

# --------------------------------------------------
# CHECK UPDATE REQUIREMENT
# --------------------------------------------------

if (($Installed -ge $Available) -and ($Executable -ge $Available)) {
    Write-Host "No update required. Microsoft Edge is already up-to-date."
    exit 0
}

# --------------------------------------------------
# UPDATE EDGE WITHOUT CLOSING BROWSER
# --------------------------------------------------

Write-Host "Updating Microsoft Edge..."

$EdgeUpdatePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
    "$env:ProgramFiles\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
)

$EdgeUpdate = $EdgeUpdatePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (!$EdgeUpdate) {
    Write-Host "Microsoft Edge Updater not found."
    exit 1
}

try {
    $Arguments = "/silent /install appguid=$EdgeAppGuid&appname=Microsoft%20Edge&needsadmin=True"
    $Process = Start-Process -FilePath $EdgeUpdate -ArgumentList $Arguments -Wait -PassThru
}
catch {
    Write-Host "Microsoft Edge update failed."
    exit 1
}

# --------------------------------------------------
# VERIFY UPDATED VERSION
# --------------------------------------------------

$NewVersion = $null
$FinalVersion = $null

for ($i = 1; $i -le 12; $i++) {

    Start-Sleep -Seconds 5

    if (Test-Path $EdgeExe) {
        try {
            $NewVersion = (Get-Item $EdgeExe).VersionInfo.ProductVersion
            $FinalVersion = [version]($NewVersion -split '-')[0]
        }
        catch {
            $FinalVersion = $null
        }

        if ($FinalVersion -and $FinalVersion -ge $Available) {
            break
        }
    }
}

# --------------------------------------------------
# FINAL RESULT
# --------------------------------------------------

$RegistryKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$EdgeAppGuid"

$RegistryVersion = (Get-ItemProperty $RegistryKey -ErrorAction SilentlyContinue).pv

if ($RegistryVersion) {
    Write-Host "Microsoft Edge Update Successful."
    Write-Host "Updated to version: $RegistryVersion"

    if (!$FinalVersion -or $FinalVersion -lt $Available) {
        Write-Host "Browser restart required for final update."
    }
}
else {
    Write-Host "Unable to verify Microsoft Edge Registry version."
    exit 1
}

exit 0