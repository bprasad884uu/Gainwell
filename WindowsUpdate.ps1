try {
    Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Set-ExecutionPolicy Bypass -Scope Process -Force
} catch {
    # Do nothing; suppress the error
}

# Check if PSWindowsUpdate module is installed
if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable -ErrorAction SilentlyContinue)) {
    Write-Host "PSWindowsUpdate module not found. Installing module..."
    Install-Module PSWindowsUpdate -Force
    Import-Module PSWindowsUpdate -Force
    Write-Host "Module installed and imported."
} else {
    Write-Host "PSWindowsUpdate module found. Importing module..."
    Import-Module PSWindowsUpdate -Force
    Write-Host "Module imported."
}

# Run the specified commands
Write-Host "Getting Windows Update..."
Get-WindowsUpdate
Get-WindowsUpdate -MicrosoftUpdate

Write-Host "Installing Windows Updates..."
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll

#Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -AutoReboot

Get-WUHistory -Last 20