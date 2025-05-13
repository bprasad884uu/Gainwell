# Specify the registry key path
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\UserTile"
$passwordLess = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device"
$newValue = "{60B78E88-EAD8-445C-9CFD-0B87F74EA6CD}"
$passName = "DevicePasswordLessBuildVersion"
$newValueData = 0

# Check if the registry key exists
if (Test-Path $registryPath) {
    # Get all properties under the registry key
    $registryProperties = Get-ItemProperty -LiteralPath $registryPath

    # Display properties starting with "S-1-"
    Write-Host "Properties with names starting with 'S-1-':"
    $registryProperties.PSObject.Properties | Where-Object { $_.Name -like 'S-1-*' } | ForEach-Object {
		Set-ItemProperty -Path $registryPath -Name $($_.Name) -Value $newValue
    }
}

Write-Host "Disable the PIN sign-in option for both Microsoft and local accounts:"
Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\System -Name "AllowDomainPINLogon" -Value 0
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions -Name "value" -Value 0

Write-Host "Clearing PIN"
Start-Process cmd -ArgumentList '/s,/c,takeown /f C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /r /d y & icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC /grant administrators:F /t & RD /S /Q C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc  & MD C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc & icacls C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc /T /Q /C /RESET' -Verb runAs
	
# Check if the registry path exists, create it if not
if (-not (Test-Path $passName)) {
    New-Item -Path $passName -Force
}
	Set-ItemProperty -Path $passwordLess -Name $passName -Value $newValueData
	Write-Host "Password set as Default"
	
# Check if Temp file exists
if (Test-Path $passName) {
    # Delete the file
    Remove-Item -Path $passName -Force
    Write-Host "$fileName deleted"
} else {
    Write-Host "$fileName not generated"
}