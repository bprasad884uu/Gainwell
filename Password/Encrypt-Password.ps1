# AES Encryption Script (Fixed)

# Prompt for password
$Password = Read-Host -AsSecureString "Enter the password to encrypt"

# Convert SecureString to plaintext
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# --- FIXED PART: Decode Base64 to Byte Arrays ---
# Use Base64-decoded values (AES-256 key = 32 bytes, IV = 16 bytes)
$KeyBase64 = "9IJWXVERkspUYB7SsoaBZtNrQ50BxB8o31HSx6Xl3/k="
$IVBase64  = "MqLxTnWcAeuPLUOSdSKFGw=="

$Key = [Convert]::FromBase64String($KeyBase64)
$IV  = [Convert]::FromBase64String($IVBase64)

# Create AES object
$AES = [System.Security.Cryptography.Aes]::Create()
$AES.Key = $Key
$AES.IV  = $IV

# Encrypt
$Encryptor = $AES.CreateEncryptor()
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainTextPassword)
$EncryptedBytes = $Encryptor.TransformFinalBlock($Bytes, 0, $Bytes.Length)
$EncryptedText = [Convert]::ToBase64String($EncryptedBytes)

Write-Host "`nEncrypted Password (Save this safely):"
Write-Host $EncryptedText
