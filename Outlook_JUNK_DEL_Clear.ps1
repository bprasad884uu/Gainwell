# Load Outlook COM object
$Outlook = New-Object -ComObject Outlook.Application
$Namespace = $Outlook.GetNamespace("MAPI")

# Function to get folder size in MB
function Get-OutlookFolderSizeMB {
    param ([object]$Folder)

    $totalSize = 0
    if ($null -ne $Folder) {
        foreach ($item in $Folder.Items) {
            try {
                # PR_MESSAGE_SIZE property (size in bytes)
                $size = $item.PropertyAccessor.GetProperty("http://schemas.microsoft.com/mapi/proptag/0x0E080003")
                $totalSize += $size
            } catch {
                # some items may not expose size
            }
        }
    }
    return [math]::Round($totalSize / 1MB, 2)
}

# Function to empty a given folder
function Clear-OutlookFolder {
    param (
        [object]$Folder,
        [string]$DisplayName
    )

    if ($null -ne $Folder) {
        $itemCount = $Folder.Items.Count
        $folderSize = Get-OutlookFolderSizeMB -Folder $Folder

        if ($itemCount -gt 0) {
            Write-Host "`n  -> $DisplayName ($itemCount items, $folderSize MB)"
            for ($i = $itemCount; $i -ge 1; $i--) {
                try {
                    $Folder.Items.Item($i).Delete()
                } catch {
                    Write-Warning "`nFailed to delete item in $DisplayName"
                }
            }
            Write-Host "`n     $DisplayName cleared."
        } else {
            Write-Host "`n  -> $DisplayName already empty."
        }
    }
}

# Loop through all mailboxes
foreach ($Mailbox in $Namespace.Folders) {
    try {
        $mailboxName = $Mailbox.Name
        if ($mailboxName -notmatch "@") { continue } # skip non-mailbox folders

        Write-Host "`n=== Processing mailbox: $mailboxName ==="

        # --- Inbox Cleanup (Happy Birthday mails) ---
        $Inbox = $Mailbox.Folders.Item("Inbox")
        if ($null -ne $Inbox) {
            Write-Host "`nChecking Inbox of $mailboxName..."
            $items = $Inbox.Items
            $items.Sort("[ReceivedTime]", $true)

            $toDelete = @()
            foreach ($item in @($items)) {
                try {
                    if ($item.Class -eq 43) { # MailItem
                        if (($item.SenderEmailAddress -match "happybirthday@gainwellindia.com")) {
                            $toDelete += $item
                        }
                    }
                } catch {
                    # skip corrupt item
                }
            }

            if ($toDelete.Count -gt 0) {
                Write-Host "  -> Found $($toDelete.Count) Happy Birthday mails. Deleting..."
                foreach ($mail in $toDelete) {
                    try { $mail.Delete() } catch { Write-Warning "Failed to delete one mail." }
                }
                Write-Host "`n     Inbox cleanup done for $mailboxName."
            } else {
                Write-Host "`n  -> No Happy Birthday mails found."
            }
        }

        # --- Junk Cleanup ---
        $JunkFolder = $Mailbox.Folders | Where-Object { $_.Name -eq "Junk Email" }
        if ($null -ne $JunkFolder) {
            Clear-OutlookFolder -Folder $JunkFolder -DisplayName "Junk Email"
        }

        # --- Deleted Items Cleanup ---
        $DeletedFolder = $Mailbox.Folders | Where-Object { $_.Name -eq "Deleted Items" }
        if ($null -ne $DeletedFolder) {
            Clear-OutlookFolder -Folder $DeletedFolder -DisplayName "Deleted Items"
        }

    } catch {
        Write-Warning "`nCould not process $($Mailbox.Name)"
    }
}
