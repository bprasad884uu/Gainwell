Add-Type -AssemblyName System.Windows.Forms

# Function to create an OpenFileDialog for multiple files
function Show-OpenFileDialog {
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.Filter = "All files (*.*)|*.*"
    $OpenFileDialog.Multiselect = $true
    $OpenFileDialog.Title = "Select files to convert to Base64"
    if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $OpenFileDialog.FileNames
    }
    return $null
}

# Function to create a FolderBrowserDialog
function Show-FolderBrowserDialog {
    $FolderBrowserDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowserDialog.Description = "Select output directory for Base64 text files"
    if ($FolderBrowserDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $FolderBrowserDialog.SelectedPath
    }
    return $null
}

# Prompt the user for the file paths
$inputFilePaths = Show-OpenFileDialog
if (-not $inputFilePaths) {
    [System.Windows.Forms.MessageBox]::Show("No files selected. Exiting script.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

# Prompt the user for the output directory
$outputDirectory = Show-FolderBrowserDialog
if (-not $outputDirectory) {
    [System.Windows.Forms.MessageBox]::Show("No output directory selected. Exiting script.", "Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    exit
}

foreach ($inputFilePath in $inputFilePaths) {
    if (-not (Test-Path $inputFilePath)) {
        Write-Host "Invalid file path: $inputFilePath. Skipping this file."
        continue
    }

    try {
        # Read the file into a byte array and convert to Base64
        $fileBytes = [System.IO.File]::ReadAllBytes($inputFilePath)
        $base64String = [Convert]::ToBase64String($fileBytes)

        # Generate the output file path (overwriting if exists)
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($inputFilePath)
        $outputFilePath = [System.IO.Path]::Combine($outputDirectory, "$fileName.txt")

        # Write Base64 string to output file (overwrite enabled)
        [System.IO.File]::WriteAllText($outputFilePath, $base64String)
        Write-Host "Base64 string has been written to $outputFilePath"
    }
    catch {
        Write-Host "Error processing file: $inputFilePath. $_"
    }
}

# Notify the user that processing is complete
#[System.Windows.Forms.MessageBox]::Show("All files have been converted and saved to:`n$outputDirectory", "Conversion Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
Write-Host "OK"