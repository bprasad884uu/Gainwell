# Initialize a flag for successful domain join
$domainJoined = $false

while (-not $domainJoined) {
    # Ask for domain name
    $domainName = Read-Host "Enter the domain name"

    # Prompt for domain credentials
    $credentials = Get-Credential -Message "Enter domain credentials for $domainName"

    try {
        # Join the domain
        Add-Computer -DomainName $domainName -Credential $credentials -Force

        # Set the flag to indicate successful domain join
        $domainJoined = $true

        # Display success message
        Write-Host "Domain join successful."

        # Ask if user wants to restart
        do {
            $restartChoice = Read-Host "Do you want to restart the computer? (Y/N)"
        } while ($restartChoice -notin 'Y', 'y', 'N', 'n')

        if ($restartChoice -eq 'Y' -or $restartChoice -eq 'y') {
            Write-Host "Restarting the computer..."
            Restart-Computer -Force
        } else {
            Write-Host "You chose not to restart the computer. Please restart manually for changes to take effect."
        }
    } catch {
        Write-Host "Error joining the domain. Please check domain name and credentials."
    }
}
