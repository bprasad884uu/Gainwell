Dim objShell
Set objShell = WScript.CreateObject("WScript.Shell")

' Specify the PowerShell script content with proper escaping
' Create a FileSystemObject
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Specify the file path and name
Const ForWriting = 2
strFilePath = "C:\Temp\"
strFileName = "TempScript.ps1"
strFile = objFSO.BuildPath(strFilePath, strFileName)

' Create the directory if it doesn't exist
If Not objFSO.FolderExists(strFilePath) Then
    objFSO.CreateFolder strFilePath
End If

' Create the file
Set objFile = objFSO.CreateTextFile(strFile)

' Write the powershell script to the file
objFile.WriteLine "Set-ExecutionPolicy unrestricted -Force"
objFile.WriteLine "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
objFile.WriteLine ""
objFile.WriteLine "# Function to set a new wallpaper for a user profile and regenerate TranscodedWallpaper"
objFile.WriteLine "# wallpaper path"
objFile.WriteLine "$wallpaper = ""C:\Windows\web\Wallpaper\Windows\wallpaper.jpg"""
objFile.WriteLine "	# Get a list of user profiles"
objFile.WriteLine "	$userProfile = Get-ChildItem -Path C:\Users -Directory"
objFile.WriteLine ""
objFile.WriteLine "function Set-Wallpaper {"
objFile.WriteLine "    param("
objFile.WriteLine "        [string]$UserProfile,"
objFile.WriteLine "        [string]$wallpaper"
objFile.WriteLine "    )"
objFile.WriteLine ""
objFile.WriteLine "    try {"
objFile.WriteLine "        # Specify the path to the TranscodedWallpaper file for the specific user profile"
objFile.WriteLine "        $transcodedWallpaperPath = [System.IO.Path]::Combine($UserProfile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Themes', 'TranscodedWallpaper')"
objFile.WriteLine ""
objFile.WriteLine "        # Check if the file exists, and if so, delete it"
objFile.WriteLine "        if (Test-Path $transcodedWallpaperPath) {"
objFile.WriteLine "            Remove-Item -Path $transcodedWallpaperPath -Force"
objFile.WriteLine "            Write-Host ""TranscodedWallpaper for $UserProfile deleted successfully."""
objFile.WriteLine "        }"
objFile.WriteLine ""
objFile.WriteLine "        # Check if the Wallpaper type is already defined"
objFile.WriteLine "        if (-not ([System.Management.Automation.PSTypeName]'Wallpaper').Type) {"
objFile.WriteLine "            # Define the SystemParametersInfo function structure"
objFile.WriteLine "            Add-Type @"" "
objFile.WriteLine "                using System;"
objFile.WriteLine "                using System.Runtime.InteropServices;"
objFile.WriteLine "                public class Wallpaper {"
objFile.WriteLine "                    [DllImport(""user32.dll"", CharSet = CharSet.Auto)]"
objFile.WriteLine "                    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);"
objFile.WriteLine "                }"
objFile.WriteLine """@"
objFile.WriteLine "        }"
objFile.WriteLine ""
objFile.WriteLine "        # Set the new wallpaper using the defined SystemParametersInfo function"
objFile.WriteLine "        [Wallpaper]::SystemParametersInfo(20, 0, $wallpaper, 3)"
objFile.WriteLine ""
objFile.WriteLine "        Write-Host ""TranscodedWallpaper for $UserProfile regenerated and new wallpaper set successfully."""
objFile.WriteLine "    }"
objFile.WriteLine "    catch {"
objFile.WriteLine "        Write-Host ""Error: $_"""
objFile.WriteLine "    }"
objFile.WriteLine "}"
objFile.WriteLine ""
objFile.WriteLine "# Get all user profiles"
objFile.WriteLine "$UserProfiles = Get-WmiObject Win32_UserProfile | Where-Object { $_.Special -eq $false }"
objFile.WriteLine ""
objFile.WriteLine "# Regenerate TranscodedWallpaper for each user profile"
objFile.WriteLine "foreach ($UserProfile in $UserProfiles) {"
objFile.WriteLine "    Set-Wallpaper -UserProfile $UserProfile.LocalPath -WallpaperPath $wallpaper"
objFile.WriteLine "}"
objFile.WriteLine ""
objFile.WriteLine "Write-Host ""TranscodedWallpaper regenerated and new wallpaper set for all user profiles."""

' Close the file
objFile.Close

' Build the PowerShell command to run the temporary script file
Dim psCommand
psCommand = "powershell.exe -ExecutionPolicy Bypass -File """ & strFile & """"

' Run the PowerShell script
objShell.Run psCommand, 0, True

' Clean up
objFSO.DeleteFile strFile

Set objShell = Nothing
Set objFSO = Nothing