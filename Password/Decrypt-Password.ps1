# AES Decryption Script

# Prompt for password
$Password = Read-Host -AsSecureString "Enter the password to Decrypt:"

# Convert SecureString to plaintext
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$EncryptedText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Define the same AES key and IV used during encryption (Base64 format)
$KeyBase64 = "9IJWXVERkspUYB7SsoaBZtNrQ50BxB8o31HSx6Xl3/k="   	# 32 bytes = AES-256
$IVBase64  = "MqLxTnWcAeuPLUOSdSKFGw=="                    		# 16 bytes = Block size

# Decode Base64 strings to byte arrays
$Key = [Convert]::FromBase64String($KeyBase64)
$IV  = [Convert]::FromBase64String($IVBase64)

# Create AES object
$AES = [System.Security.Cryptography.Aes]::Create()
$AES.KeySize = 256
$AES.Key = $Key
$AES.IV = $IV
$AES.Padding = "PKCS7"  # Default but explicit

# Decrypt
try {
    $Decryptor = $AES.CreateDecryptor()
    $EncryptedBytes = [Convert]::FromBase64String($EncryptedText)
    $DecryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 0, $EncryptedBytes.Length)
    $DecryptedPassword = [System.Text.Encoding]::UTF8.GetString($DecryptedBytes)

    Write-Host "`n🔓 Decrypted Password:"
    Write-Host $DecryptedPassword
} catch {
    Write-Error "❌ Decryption failed: $($_.Exception.Message)"
}
