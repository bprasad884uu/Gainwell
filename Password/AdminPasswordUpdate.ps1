# Detect OS type: "WinNT" = Workstation, "LanmanNT" = Domain Controller, "ServerNT" = Server
$OSType = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions").ProductType

if ($OSType -eq "WinNT") {
	# Find built-in Administrator account (RID 500)
	$AdminUser = Get-LocalUser | Where-Object { $_.SID -like "S-1-5-21-*-500" } | Select-Object -ExpandProperty Name

	# Desired admin name for client OS
	$WinOSAdmin = "gcpladmusr"
	#$ServerOSAdmin = "gcpladmwusr"

	if ($AdminUser) {
		try {
			if ($AdminUser -ne $WinOSAdmin) {
				Rename-LocalUser -Name $AdminUser -NewName "$WinOSAdmin"
				Write-Host "Administrator account renamed!"
			} else {
				#Write-Host "Administrator account already named '$WinOSAdmin'. No changes made."
			}
		} catch {
			Write-Host "Error: Unable to rename Administrator account. $_"
		}
	} else {
		Write-Host "Administrator account not found!"
	}

	# AES Decryption Script

	# Input the encrypted text
	$EncryptedText = "/VUVh8SnruKH1mJNSpoFvA=="
	#$EncryptedText = $args[0]
	# Desired full name
	$desiredFullName = "Gainwell Administrator"

	# Define encryption (Base64 format)
	$KeyBase64 = "9IJWXVERkspUYB7SsoaBZtNrQ50BxB8o31HSx6Xl3/k="
	$IVBase64  = "MqLxTnWcAeuPLUOSdSKFGw=="

	# Decode Base64 strings to byte arrays
	$Key = [Convert]::FromBase64String($KeyBase64)
	$IV  = [Convert]::FromBase64String($IVBase64)

	# Create AES object
	$AES = [System.Security.Cryptography.Aes]::Create()
	$AES.KeySize = 256
	$AES.Key = $Key
	$AES.IV = $IV
	$AES.Padding = "PKCS7"

	# Decrypt
	try {
		$Decryptor = $AES.CreateDecryptor()
		$EncryptedBytes = [Convert]::FromBase64String($EncryptedText)
		$DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)
		$Password = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)
	} catch {
		Write-Error "Decryption failed: $($_.Exception.Message)"
	}

	# Check if the Administrator account is already active
	$adminUser = Get-LocalUser -Name $WinOSAdmin
	if ($adminUser.Enabled -eq $false) {
		# Activate the Administrator account if it's not already active
		Enable-LocalUser -Name $WinOSAdmin
		Write-Host "Administrator Account Activated."
	} else {
		#Write-Host "Administrator Account is already active."
	}

	# Check if the full name is correct
	if ($adminUser.FullName -ne $desiredFullName) {
		# Update the full name if it doesn't match
		Set-LocalUser -Name $WinOSAdmin -FullName $desiredFullName
		Write-Host "Full name has been updated for the Administrator account."
	} else {
		#Write-Host "Full name is already set to '$desiredFullName'."
	}

	# Set the new password for the Administrator account
	Set-LocalUser -Name $WinOSAdmin -Password (ConvertTo-SecureString -String $Password -AsPlainText -Force)
	Write-Host "Password has been updated for Administrator account."
} else {
    Write-Host "Non-client OS detected. Rename skipped."
}