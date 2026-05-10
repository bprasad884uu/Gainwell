# Force TLS 1.2 for GitHub API
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Function to get installed Notepad++ version
function Get-NotepadPPVersion {

    $exePaths = @(
        "$env:ProgramFiles\Notepad++\notepad++.exe",
        "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"
    )

    foreach ($exe in $exePaths) {
        if (Test-Path $exe) {
            return (Get-Item $exe).VersionInfo.ProductVersion
        }
    }

    return $null
}

# Display current version
$CurrentVersion = Get-NotepadPPVersion

if ($CurrentVersion) {
    Write-Host "Installed Notepad++ Version : $CurrentVersion"
}
else {
    Write-Host "Notepad++ is not installed."
	return
}

# Temp folder
$TempFolder = "$env:TEMP\NotepadPP"
New-Item -ItemType Directory -Path $TempFolder -Force | Out-Null

# Installer path
$InstallerPath = "$TempFolder\npp_installer.exe"

try {

    # Get latest release info
    $ReleaseInfo = Invoke-RestMethod `
        -Uri "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"

    # Latest version
    $LatestVersion = $ReleaseInfo.tag_name.TrimStart("v")

    Write-Host "Latest Available Version     : $LatestVersion"

    # Check if update required
    if ($CurrentVersion -eq $LatestVersion) {
        Write-Host "Notepad++ is already up to date."
    }
    else {

        # Force close Notepad++ if running
        $NppProcess = Get-Process -Name "notepad++" -ErrorAction SilentlyContinue

        if ($NppProcess) {
            Write-Host "Notepad++ is currently running."
            Write-Host "Closing Notepad++ forcefully..."

            Stop-Process -Name "notepad++" -Force

            Start-Sleep -Seconds 2

            Write-Host "Notepad++ closed successfully."
        }

        # Get x64 installer URL
        $DownloadUrl = $ReleaseInfo.assets |
            Where-Object { $_.name -match "Installer.x64.exe$" } |
            Select-Object -ExpandProperty browser_download_url -First 1

        if ($DownloadUrl) {

            # Download installer
            Write-Host "Downloading latest Notepad++..."
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath

            # Install silently
            Write-Host "Installing update silently..."
            Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait

            # Display updated version
            $UpdatedVersion = Get-NotepadPPVersion

            Write-Host "Updated Installed Version    : $UpdatedVersion"
        }
        else {
            Write-Host "Unable to locate installer download URL."
        }
    }
}
catch {
    Write-Host "Error occurred:"
    Write-Host $_.Exception.Message
}
finally {

    # Cleanup
    if (Test-Path $TempFolder) {
        Remove-Item $TempFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "Script execution completed."
}