# Define variables
$wifiName = "GCPL_WIFI"
$wifiPassword = "Gcpl#2022"
$tempXml = "$env:TEMP\WiFiProfile.xml"

# Wi-Fi profile XML template
$xml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$wifiName</name>
    <SSIDConfig>
        <SSID>
            <name>$wifiName</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$wifiPassword</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@

# Save XML to temp file
$xml | Set-Content -Path $tempXml -Encoding UTF8

# Add profile to Windows
netsh wlan add profile filename="$tempXml" user=all

# Connect to WiFi
netsh wlan connect name="$wifiName" ssid="$wifiName"

# Cleanup
Remove-Item $tempXml -Force
