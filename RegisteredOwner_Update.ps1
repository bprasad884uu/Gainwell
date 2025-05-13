# Ask the user for the IP address
$ipAddress = Read-Host "Please enter the IP address"

Invoke-Command -ComputerName $ipAddress -ScriptBlock {
    # Define the registry paths
$sourceKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
$destinationKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# Get the value of LastLoggedOnDisplayName
try {
    $lastLoggedOnDisplayName = Get-ItemProperty -Path $sourceKey -Name LastLoggedOnDisplayName -ErrorAction Stop
    $valueToWrite = $lastLoggedOnDisplayName.LastLoggedOnDisplayName

    # Write the value to RegisteredOwner in the destination key
    Set-ItemProperty -Path $destinationKey -Name RegisteredOwner -Value $valueToWrite -Force
    Write-Host "Value successfully copied to RegisteredOwner!"

    # Display the RegisteredOwner value
    $registeredOwner = Get-ItemProperty -Path $destinationKey -Name RegisteredOwner
    Write-Host "RegisteredOwner: $($registeredOwner.RegisteredOwner)"
} catch {
    Write-Error "An error occurred: $_"
}

} -Credential (Get-Credential)