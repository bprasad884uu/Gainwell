# Function to check if the system is domain-joined
function Is-DomainJoined {
    $computerInfo = Get-WmiObject Win32_ComputerSystem
    return ($computerInfo.PartOfDomain)
}

# Prompt user for a new hostname
$newHostname = Read-Host "Enter the new hostname"

# Validate if the entered hostname is not empty
if ($newHostname -ne "") {
    # Check if the system is domain-joined
    if (Is-DomainJoined) {
        # Prompt for domain username and password
        $username = Read-Host "Enter your domain username"
        $pass = Read-Host "Enter your domain password=" -AsSecureString
		$Password = ConvertTo-SecureString $pass -AsPlainText -Force

		# Convert the SecureString to BSTR and then to a plain text string
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
		$DomainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        # Create a PSCredential object
        $credential = New-Object System.Management.Automation.PSCredential($username, $DomainPassword)

        # Set the new hostname with domain credentials
        $computerInfo = Get-WmiObject Win32_ComputerSystem
        $computerInfo.Rename($newHostname, $credential.GetNetworkCredential().Password, $credential.UserName.Split('\')[0])

        Write-Host "Hostname updated successfully with domain credentials."
    } else {
        # Set the new hostname without domain credentials
        $computerInfo = Get-WmiObject Win32_ComputerSystem
        $computerInfo.Rename($newHostname)

        Write-Host "Hostname updated successfully."
    }

    # Ask the user if they want to restart the computer
    $restartChoice = Read-Host "Do you want to restart the computer? (Y/N)"
    
    if ($restartChoice -eq 'Y' -or $restartChoice -eq 'y') {
        Write-Host "Restarting the computer..."
        Restart-Computer -Force
    } else {
        Write-Host "You chose not to restart the computer. Please restart manually for changes to take effect."
    }
} else {
    Write-Host "Invalid hostname. Please enter a non-empty hostname."
}
