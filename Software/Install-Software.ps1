# Get the folder where the script is located
#$basePath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$softwarePath = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Prompt for Office version
$officeVersion = Read-Host "Enter MS Office version to install (2016, 2019, O365). Press Enter to skip"

if ([string]::IsNullOrWhiteSpace($officeVersion)) {
    Write-Output "No Office version entered. Skipping Office installation."
} else {
    Install-MSOffice -version $officeVersion
}

# Function to mount and install Office from ISO
function Install-MSOffice {
    param (
        [string]$version
    )

    $officeFolder = Join-Path $softwarePath "Office\$version"
    if (!(Test-Path $officeFolder)) {
        Write-Warning "Office folder not found: $officeFolder"
        return
    }

    $isoFile = Get-ChildItem -Path $officeFolder -Filter *.iso -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $isoFile) {
        Write-Warning "No ISO found in $officeFolder"
        return
    }

    Write-Output "Mounting ISO: $($isoFile.FullName)"
    $mountResult = Mount-DiskImage -ImagePath $isoFile.FullName -PassThru
    $mountedDrive = ($mountResult | Get-Volume).DriveLetter + ":"
    Start-Sleep -Seconds 3

    # Find setup.exe recursively
    $setupExe = Get-ChildItem -Path "$mountedDrive\" -Recurse -Filter setup.exe -File -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($setupExe) {
        Write-Output "Installing MS Office $version..."
        switch ($version) {
            "2016" {
                $mspFile = Join-Path $setupExe.DirectoryName "setup.msp"
                if (Test-Path $mspFile) {
                    Start-Process -FilePath $setupExe.FullName -ArgumentList "/adminfile setup.msp" -Wait
                    Write-Output "MS Office 2016 installed using setup.msp."
                } else {
                    Start-Process -FilePath $setupExe.FullName -Wait
                    Write-Output "MS Office 2016 installed without setup.msp."
                }
            }
            default {
                Start-Process -FilePath $setupExe.FullName -Wait
                Write-Output "MS Office $version installed."
            }
        }
    } else {
        Write-Warning "setup.exe not found in mounted ISO."
    }

    Dismount-DiskImage -ImagePath $isoFile.FullName
}

# Function to install EXE/MSI from specific folders
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

# --- Main Execution ---
Write-Output "Starting software installations..."

Install-SoftwareFromFolder -name "7zip"
Install-SoftwareFromFolder -name "Adobe"
Install-SoftwareFromFolder -name "Chrome"

Write-Output "All installations completed."
