# Prompt user for a new hostname
$newHostname = Read-Host "Enter the new hostname"

# Validate if the entered hostname is not empty
if ($newHostname -ne "") {
    # Set the new hostname
    $computerInfo = Get-WmiObject Win32_ComputerSystem
    $computerInfo.Rename($newHostname)

    # Display a message with the updated hostname
    Write-Host "Hostname updated successfully."

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
