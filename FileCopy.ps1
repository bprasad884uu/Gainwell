$sourcePath = "\\10.131.76.6\Software\OS\Win10_22H2_EnglishInternational_x64v1.iso"
$destinationPath = "$env:temp\Win10_22H2_EnglishInternational_x64v1.iso"

# Get file size in MB
$sourceFileInfo = Get-Item -Path $sourcePath
$totalBytes = $sourceFileInfo.Length
$totalMB = [math]::Round($totalBytes / 1MB, 2)

# Open source and destination file streams
$sourceStream = [System.IO.File]::OpenRead($sourcePath)
$destinationStream = [System.IO.File]::Create($destinationPath)

# Buffer for copying (1MB)
$buffer = New-Object byte[] 1MB
$bytesRead = 0
$totalCopied = 0

# Copy process
while (($bytesRead = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
    $destinationStream.Write($buffer, 0, $bytesRead)
    $totalCopied += $bytesRead
    $copiedMB = [math]::Round($totalCopied / 1MB, 2)

    # Calculate percentage complete
    $percentComplete = [math]::Round(($totalCopied / $totalBytes) * 100, 2)

    # Display progress in percentage and MB
    $statusMessage = "{0} MB copied of {1} MB ({2}% Complete)" -f $copiedMB, $totalMB, $percentComplete
    Write-Progress -Activity "Copying File" -Status $statusMessage -PercentComplete $percentComplete
}

# Close streams
$sourceStream.Close()
$destinationStream.Close()

Write-Host "File copy complete: $copiedMB MB of $totalMB MB to ""$env:temp""."
