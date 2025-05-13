# Generate a random AES-256 key and 16-byte IV

# Create AES object
$AES = [System.Security.Cryptography.Aes]::Create()
$AES.KeySize = 256
$AES.GenerateKey()
$AES.GenerateIV()

# Convert to Base64 strings for easy use and storage
$KeyBase64 = [Convert]::ToBase64String($AES.Key)
$IVBase64  = [Convert]::ToBase64String($AES.IV)

Write-Host "🔐 AES-256 Key (Base64):"
Write-Host $KeyBase64

Write-Host "`n🔁 Initialization Vector (IV, Base64):"
Write-Host $IVBase64
