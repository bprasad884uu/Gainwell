# Title:      UninstallRealVNC.ps1
# Date:       6/21/2024
# Author:     Bishnu Prasad Panigrahi
#
# Purpose:    Script to remove RealVNC Server, RealVNC Viewer, and VNC Printer Driver from a computer without user intervention.
#
#             This script should remove the following:
#                 RealVNC Server
#                 RealVNC Viewer
#                 VNC Printer Driver
#
#
# Requires Administrative Privileges

Write-Host "Removing RealVNC Installations..."
Clear-Host

# Stop Any RealVNC Services
Write-Host "Stopping Services."
Stop-Service -Name VNCServer -ErrorAction SilentlyContinue
Stop-Service -Name VNCViewer -ErrorAction SilentlyContinue

# Kill Any Possible Left Over RealVNC Processes
Write-Host "Killing any possibly left over RealVNC processes."
Stop-Process -Name VNCServer -Force -ErrorAction SilentlyContinue
Stop-Process -Name VNCViewer -Force -ErrorAction SilentlyContinue

# Delete Any RealVNC Services
Write-Host "Deleting Services."
sc.exe delete VNCServer
sc.exe delete VNCViewer

# Removes Any RealVNC Registry Keys
Write-Host "Removing HKEY_CLASSES_ROOT RealVNC Keys."
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\VNC.ConnectionInfo" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\VncViewer.Config" -Force -Recurse -ErrorAction SilentlyContinue

Write-Host "Removing HKEY_LOCAL_MACHINE RealVNC Keys."
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\{RealVNC-Product-ID}" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\{RealVNC-Product-ID}" -Force -Recurse -ErrorAction SilentlyContinue

# Attempt to call the RealVNC uninstaller if it's still installed.
Write-Host "Calling RealVNC Uninstaller."
$uninstallerPaths = @(
    "C:\Program Files\RealVNC\VNC Server\unins000.exe",
    "C:\Program Files (x86)\RealVNC\VNC Server\unins000.exe",
    "C:\Program Files\RealVNC\VNC Viewer\unins000.exe",
    "C:\Program Files (x86)\RealVNC\VNC Viewer\unins000.exe"
	"C:\Program Files\RealVNC\VNC Server\Printer Driver\unins000.exe"
	"C:\Program Files (x86)\RealVNC\VNC Server\Printer Driver\unins000.exe"
)
foreach ($path in $uninstallerPaths) {
    if (Test-Path $path) {
        & $path /SILENT /NORESTART
    }
}

# Remove Any Straggling Files
Write-Host "Removing any straggling files."
Remove-Item -Path "C:\Program Files\RealVNC" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Program Files (x86)\RealVNC" -Force -Recurse -ErrorAction SilentlyContinue

# Remove VNC Printer Driver
Write-Host "Removing VNC Printer Driver."
$printerDrivers = Get-WmiObject Win32_PrinterDriver | Where-Object {$_.Name -like "*VNC Printer Driver*"}
foreach ($driver in $printerDrivers) {
    $driver.Remove()
}

# Remove RealVNC Printer Driver
Write-Host "Removing RealVNC Printer Driver."
$printerDrivers = Get-WmiObject Win32_PrinterDriver | Where-Object {$_.Name -like "*RealVNC Printer Driver*"}
foreach ($driver in $printerDrivers) {
    $driver.Remove()
}

Write-Host "All done!"
