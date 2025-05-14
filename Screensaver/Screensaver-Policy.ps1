# Check if the type PIDLEncoder is already defined
if (-not ("PIDLEncoder" -as [type])) {
    $CSharpCode = @"
using System;
using System.Runtime.InteropServices;

public class PIDLEncoder
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr ILCreateFromPathW(string pszPath);

    [DllImport("shell32.dll")]
    private static extern void ILFree(IntPtr pidl);

    public static byte[] GetEncryptedPIDL(string folderPath)
    {
        IntPtr pidl = ILCreateFromPathW(folderPath);
        if (pidl == IntPtr.Zero)
            return null;

        // Compute the size of the PIDL by iterating over each ITEMID.
        int size = 0;
        while (true)
        {
            // Each ITEMID starts with a USHORT (2 bytes) length field.
            ushort cb = (ushort)Marshal.ReadInt16(pidl, size);
            if (cb == 0)
                break;
            size += cb;
        }
        size += 2; // Include the final null terminator (two zero bytes)

        byte[] pidlBytes = new byte[size];
        Marshal.Copy(pidl, pidlBytes, 0, size);
        ILFree(pidl);
        return pidlBytes;
    }
}
"@
    Add-Type -TypeDefinition $CSharpCode -Language CSharp
}

# Define the Screensaver folder path
$folderPath = "C:\Windows\Web\Screensaver"

# Check if the folder exists
if (!(Test-Path -Path $folderPath)) {
    try {
        # Create the folder forcefully
        New-Item -Path $folderPath -ItemType Directory -Force -ErrorAction Stop
        Write-Output "Folder created successfully: $folderPath"
    } catch {
        Write-Output "Failed to create folder: $_"
    }
} else {
    Write-Output "Folder already exists: $folderPath"
}

# Get the EncryptedPIDL (as a byte array)
$encryptedPIDL = [PIDLEncoder]::GetEncryptedPIDL($folderPath)

if ($encryptedPIDL -eq $null) {
    Write-Output "❌ Failed to encode the path."
} else {
    # Convert the byte array to a Base64 string
    $base64EncodedPIDL = [Convert]::ToBase64String($encryptedPIDL)

    # Format the Base64 string into 64-character chunks to match Registry output
    function Format-EncodedPIDL {
        param (
            [string]$encodedPIDL,
            [int]$chunkSize = 64
        )
        $formatted = ""
        for ($i = 0; $i -lt $encodedPIDL.Length; $i += $chunkSize) {
            $formatted += $encodedPIDL.Substring($i, [Math]::Min($chunkSize, $encodedPIDL.Length - $i)) + "`r`n"
        }
        return $formatted.TrimEnd("`r`n")
    }

    $formattedEncodedPIDL = Format-EncodedPIDL -encodedPIDL $base64EncodedPIDL
    #Write-Output "✅ Formatted Encoded PIDL:`n$formattedEncodedPIDL"
}

# Specify the registry path
$registryPath = "Registry::HKEY_USERS"

# Get all keys under the specified path
$keys = Get-ChildItem -Path $registryPath

# Filter to include only users and exclude _Classes
$filteredKeys = $keys | Where-Object { $_.PSChildName -notlike "*_Classes" }

# Get user profiles to map SID to Username
$UserProfiles = Get-WmiObject Win32_UserProfile | Select-Object LocalPath, SID

# Check screensaver path (ensure correct architecture)
$screensaverPath = "C:\Windows\System32\PhotoScreensaver.scr"

foreach ($key in $filteredKeys) {
    $SID_Value = $key.PSChildName
    $subKey = "Registry::HKEY_USERS\$SID_Value"

    # Get the corresponding username from user profile
    $UserProfile = $UserProfiles | Where-Object { $_.SID -eq $SID_Value }
    $UserName = if ($UserProfile) {
    ($UserProfile.LocalPath -split "\\")[-1] 
		} else { 
			"Unknown" 
		}

    # Check if registry path exists
    if (Test-Path $subKey) {
        try {
            # Define registry paths
            $photoViewerPath = "$subKey\Software\Microsoft\Windows Photo Viewer\Slideshow\Screensaver"
            $desktopPath = "$subKey\Control Panel\Desktop"
            $policyPath = "$subKey\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
            $policy = "$subKey\Software\Microsoft\Windows\CurrentVersion\Policies\System"

            # Create registry keys if they don't exist
            foreach ($path in @($photoViewerPath, $policyPath, $policy)) {
                if (-not (Test-Path $path)) {
                    New-Item -Path $path -Force | Out-Null
                }
            }
			
			 # Set the EncryptedPIDL value (Ensure $formattedEncodedPIDL is defined)
            if ($formattedEncodedPIDL) {
                Set-ItemProperty -Path $photoViewerPath -Name "EncryptedPIDL" -Value $formattedEncodedPIDL
            }

            # Set screensaver settings
            Set-ItemProperty -Path $photoViewerPath -Name "Speed" -Value 0
            Set-ItemProperty -Path $desktopPath -Name "ScreenSaveTimeOut" -Value 300 -Type String
            Set-ItemProperty -Path $desktopPath -Name "ScreenSaveActive" -Value 1 -Type String
            Set-ItemProperty -Path $desktopPath -Name "ScreenSaverIsSecure" -Value 1 -Type String
            Set-ItemProperty -Path $desktopPath -Name "SCRNSAVE.EXE" -Value $screensaverPath

            # Prevent users from changing screensaver settings
            Set-ItemProperty -Path $policyPath -Name "ScreenSaveActive" -Value 1 -Type String
            Set-ItemProperty -Path $policyPath -Name "SCRNSAVE.EXE" -Value $screensaverPath
            Set-ItemProperty -Path $policyPath -Name "ScreenSaverIsSecure" -Value 1 -Type String
            Set-ItemProperty -Path $policyPath -Name "ScreenSaveTimeOut" -Value 300 -Type String
            Set-ItemProperty -Path $policyPath -Name "NoChangingScreenSaver" -Value 1 -Type String

            # Disable the entire Screensaver settings dialog box
            Set-ItemProperty -Path $policy -Name "NoDispScrSavPage" -Value 1 -Type DWord

            # Prevent users from changing screensaver settings (this disables the "Settings" button)
            Set-ItemProperty -Path $policyPath -Name "ScreenSaverSettingsPage" -Value 1 -Type DWord

            Write-Output "✅ Screensaver settings applied successfully for user: $UserName"
        } catch {
            Write-Output "❌ Failed to apply settings for user: $UserName - Error: $_"
        }
    }
}

# Apply changes to user settings
RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters ,1 ,True

# Set Turn Off Display Timeout (in seconds)
powercfg /change monitor-timeout-dc 10		# 10 minutes on battery
powercfg /change monitor-timeout-ac 20		# 20 minutes when plugged in

# Set Sleep Timeout (in seconds)
powercfg /change standby-timeout-dc 60		# 1 hour on battery
powercfg /change standby-timeout-ac 0		# Never when plugged in

Write-Output "✅ Power settings updated successfully!"

# Apply Group Policy
gpupdate /force

Write-Output "✅ Screensaver settings applied successfully for all users!"