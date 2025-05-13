Add-Type -AssemblyName System.Windows.Forms

# Function to create an OpenFileDialog for multiple files
function Show-OpenFileDialog {
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "All files (*.*)|*.*"
    $OpenFileDialog.Multiselect = $true
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $OpenFileDialog.FileNames
    }
    return $null
}

# Function to create a FolderBrowserDialog
function Show-FolderBrowserDialog {
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($FolderBrowserDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $FolderBrowserDialog.SelectedPath
    }
    return $null
}

# Prompt the user for the file paths
$inputFilePaths = Show-OpenFileDialog
if (-not $inputFilePaths) {
    Write-Host "No files selected. Exiting script."
    exit
}

# Prompt the user for the output directory
$outputDirectory = Show-FolderBrowserDialog
if (-not $outputDirectory) {
    Write-Host "No output directory selected. Exiting script."
    exit
}

foreach ($inputFilePath in $inputFilePaths) {
    # Validate the path
    if (-not (Test-Path $inputFilePath)) {
        Write-Host "Invalid file path: $inputFilePath. Skipping this file."
        continue
    }

    # Read the file into a byte array and convert to Base64
    $fileBytes = [System.IO.File]::ReadAllBytes($inputFilePath)
    $base64String = [Convert]::ToBase64String($fileBytes)

    # Generate the output file path
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($inputFilePath)
    $outputFilePath = [System.IO.Path]::Combine($outputDirectory, "$fileName.txt")

    # Output the Base64 string to the specified text file
    [System.IO.File]::WriteAllText($outputFilePath, $base64String)

    <# Print the Base64 string to the console (optional)
    Write-Host "Base64 String for ${inputFilePath}:"
    Write-Host $base64String#>

    Write-Host "Base64 string has been written to $outputFilePath"
}
