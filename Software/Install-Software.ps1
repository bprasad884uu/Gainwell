# Path setup
$basePath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$softwarePath = Join-Path $basePath "Software"
$officePath = Join-Path $softwarePath "Office"

# Office version selector
$officeOptions = @{
    "1" = "2016"
    "2" = "2019"
    "3" = "O365"
}

Write-Host "Select the MS Office version to install:"
Write-Host "1. Office 2016"
Write-Host "2. Office 2019"
Write-Host "3. Office 365"
Write-Host "Press Enter to skip Office installation."
$selection = Read-Host "Enter the number corresponding to your choice"

if ([string]::IsNullOrWhiteSpace($selection)) {
    Write-Output "No selection made. Skipping Office installation."
    $officeVersion = ""
} elseif ($officeOptions.ContainsKey($selection)) {
    $officeVersion = $officeOptions[$selection]
    Write-Output "You selected Office $officeVersion."
} else {
    Write-Warning "Invalid selection. Skipping Office installation."
    $officeVersion = ""
}

# Office installer
if ($officeVersion) {
    try {
        $officeFolder = Join-Path $officePath $officeVersion
        $isoFile = Get-ChildItem -Path $officeFolder -Filter *.iso | Select-Object -First 1
        if (-not $isoFile) { throw "No ISO found for Office $officeVersion." }

        $mount = Mount-DiskImage -ImagePath $isoFile.FullName -PassThru
        $driveLetter = ($mount | Get-Volume).DriveLetter + ":"

        $setupBat = Join-Path "$driveLetter\" "setup.bat"
        if (-not (Test-Path $setupBat)) { throw "setup.bat not found in mounted ISO." }

        Write-Host "Running Office installer from: $setupBat"
        Push-Location $driveLetter
        & $setupBat
        Pop-Location

        Dismount-DiskImage -ImagePath $isoFile.FullName
    } catch {
        Write-Error "Failed to mount or run Office ${officeVersion}: $($_.Exception.Message)"
    }
}

# Install Other Software
function Install-SoftwareFromFolder {
    param (
        [string]$name
    )

    $folder = Join-Path $softwarePath $name
    if (!(Test-Path $folder)) {
        Write-Warning "Folder not found: $folder"
        return
    }

    $installers = Get-ChildItem -Path $folder -Include *.exe, *.msi -File -Recurse
    if ($installers.Count -eq 0) {
        Write-Warning "No EXE or MSI installers found in $folder"
        return
    }

    foreach ($installer in $installers) {
        Write-Output "Installing $($installer.Name)..."

        if ($name -eq "Adobe") {
            Start-Process -FilePath $installer.FullName -ArgumentList "/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES" -Wait
        }
        elseif ($name -eq "7zip") {
            if ($installer.Extension -eq ".msi") {
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($installer.FullName)`" /qn /norestart" -Wait
            } else {
                Start-Process -FilePath $installer.FullName -ArgumentList "/S" -Wait
            }
        }
        elseif ($installer.Extension -eq ".msi") {
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$($installer.FullName)`" /quiet /norestart" -Wait
        }
        else {
            Start-Process -FilePath $installer.FullName -ArgumentList "/silent", "/s", "/quiet", "/qn" -Wait
        }

        Write-Output "$($installer.Name) installation complete."
    }
}

Write-Output "Starting software installations..."

Install-SoftwareFromFolder -name "7zip"
Install-SoftwareFromFolder -name "Adobe"
Install-SoftwareFromFolder -name "Chrome"

Write-Host "`nAll done!"
