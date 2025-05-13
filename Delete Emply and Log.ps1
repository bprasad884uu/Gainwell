# Specify junk file extensions
$junkExtensions = @('*.tmp', '*.log', '*.etl', '*.bak', '*.old', '~*', '*.chk', '*.dmp', '*.pf')

# Initialize counters for deleted items
$totalFilesDeleted = 0
$totalFoldersDeleted = 0

# Function to grant temporary full control permission
function Grant-FullControl {
    param (
        [string]$path
    )
    $acl = Get-Acl $path
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $path $acl
}

# Remove junk files from C: drive
foreach ($extension in $junkExtensions) {
    try {
        $junkFiles = Get-ChildItem -Path C:\ -Recurse -Force -Filter $extension -ErrorAction SilentlyContinue
        foreach ($file in $junkFiles) {
            try {
                Write-Host "Currently deleting junk file: $($file.FullName)"
                Remove-Item -Path $file.FullName -Force -Recurse -ErrorAction Stop
                Write-Host "Deleted junk file: $($file.FullName)"
                $totalFilesDeleted++
            } catch {
                if ($_.Exception.Message -like "*Access to the path is denied*") {
                    Write-Host "Unable to delete: $($file.FullName) - Access to the path is denied."
                } else {
                    Write-Host "Failed to delete junk file: $($file.FullName) - $($_.Exception.Message)"
                }
            }
        }
    } catch {
        Write-Host "Failed to get junk files for extension $extension - $($_.Exception.Message)"
    }
}

# Get all directories recursively from C: drive
try {
    $folders = Get-ChildItem -Path C:\ -Directory -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($folder in $folders) {
        try {
            # Check if the folder is empty
            if (-not (Get-ChildItem -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Currently deleting empty folder: $($folder.FullName)"
                    Remove-Item -Path $folder.FullName -Force -Recurse -ErrorAction Stop
                    Write-Host "Deleted empty folder: $($folder.FullName)"
                    $totalFoldersDeleted++
                } catch {
                    Write-Host "Permission issue with: $($folder.FullName). Granting permissions..."
                    Grant-FullControl -path $folder.FullName
                    try {
                        Write-Host "Currently deleting folder after granting permissions: $($folder.FullName)"
                        Remove-Item -Path $folder.FullName -Force -Recurse -ErrorAction Stop
                        Write-Host "Deleted folder after granting permissions: $($folder.FullName)"
                        $totalFoldersDeleted++
                    } catch {
                        if ($_.Exception.Message -like "*Access to the path is denied*") {
                            Write-Host "Unable to delete: $($folder.FullName) - Access to the path is denied."
                        } else {
                            Write-Host "Failed to delete folder even after granting permissions: $($folder.FullName) - $($_.Exception.Message)"
                        }
                    }
                }
            }
        } catch {
            Write-Host "Access denied to folder: $($folder.FullName) - $($_.Exception.Message)"
        }
    }
} catch {
    Write-Host "Failed to get folders - $($_.Exception.Message)"
}

# Output summary of deleted files and folders
Write-Host "Total junk files deleted: $totalFilesDeleted"
Write-Host "Total empty folders deleted: $totalFoldersDeleted"
