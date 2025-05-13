# Initialize a flag for successful domain join
$domainJoined = $false

while (-not $domainJoined) {
    # Prompt user for domain join
    $joinDomain = Read-Host "Do you want to join a domain? (Y/N)"

    if ($joinDomain -eq 'Y' -or $joinDomain -eq 'y') {
        # Ask for domain name
        $domainName = Read-Host "Enter the domain name"

        # Ask for domain username
        $domainUsername = Read-Host "Enter the domain username"

        # Ask for domain password
        $pass = Read-Host "Enter the domain password" -AsSecureString
	$Password = ConvertTo-SecureString $pass -AsPlainText -Force
	# Convert the SecureString to BSTR and then to a plain text string
	$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
	$domainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        try {
            # Join the domain
            Add-Computer -DomainName $domainName -Credential (New-Object System.Management.Automation.PSCredential ("$env:USERDOMAIN\$env:USERNAME", $domainPassword)) -Force

            # Set the flag to indicate successful domain join
            $domainJoined = $true

            # Display success message
            Write-Host "Domain join successful."

            # Ask if user wants to restart
            $restartChoice = Read-Host "Do you want to restart the computer? (Y/N)"
            if ($restartChoice -eq 'Y' -or $restartChoice -eq 'y') {
                Write-Host "Restarting the computer..."
                Restart-Computer -Force
            } else {
                Write-Host "You chose not to restart the computer. Please restart manually for changes to take effect."
            }
        } catch {
            Write-Host "Error joining the domain. Please check domain name and credentials."
        }
    } else {
        Write-Host "Domain join skipped."
        break  # Exit the loop if user chooses not to join the domain
    }
}
