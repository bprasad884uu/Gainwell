$OSType = (Get-WmiObject Win32_OperatingSystem).ProductType
$AdminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-21-*-500" } | Select-Object -ExpandProperty Name
$WinOSAdmin = "gcpladmusr"
$ServerOSAdmin = "gcpladmwusr"

if ($AdminUser) {
    try {
        if ($OSType -eq 2 -or $OSType -eq 3) {
            #Rename-LocalUser -Name $AdminUser -NewName "$ServerOSAdmin"
            #Write-Host "Administrator account renamed from $AdminUser to $ServerOSAdmin!"
			exit
        } else {
            Rename-LocalUser -Name $AdminUser -NewName "$WinOSAdmin"
            Write-Host "Administrator account renamed from $AdminUser to $WinOSAdmin!"
        }
    } catch {
        Write-Host "Error: Unable to rename Administrator account. $_"
    }
} else {
    Write-Host "Administrator account not found!"
}