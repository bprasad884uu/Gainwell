# Define both registry paths and value name
$regPaths = @(
    "HKLM:\SOFTWARE\TeamViewer",
    "HKLM:\SOFTWARE\Wow6432Node\TeamViewer"
)
$valueName = "InstallationDirectory"
$teamViewerInstalled = $false

foreach ($regPath in $regPaths) {
    # Check if the registry key exists
    if (Test-Path $regPath) {
        # Get the value of InstallationDirectory
        $installationDirectory = Get-ItemProperty -Path $regPath -Name $valueName | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue

        # Check if the value exists and the directory exists
        if ($installationDirectory -and (Test-Path $installationDirectory)) {
            $uninstallExePath = Join-Path $installationDirectory "uninstall.exe"

            # Check if uninstall.exe exists in the directory
            if (Test-Path $uninstallExePath) {
                Write-Host "Removing TeamViewer...."
                Start-Process $uninstallExePath -ArgumentList "/S" -Wait
                $teamViewerInstalled = $true

                # Check if the installation directory still exists after uninstallation
                if (-not (Test-Path $installationDirectory)) {
                    # If uninstallation was successful, remove the registry key
                    if (Test-Path $regPath) {
                        Remove-Item -Path $regPath -Recurse -Force
                    }
                    Write-Host "TeamViewer successfully removed."
                }
                break
            }
        }
    }
}

# If TeamViewer was not found in any of the registry locations or directories
if (-not $teamViewerInstalled) {
    Write-Host "TeamViewer not installed."
}
