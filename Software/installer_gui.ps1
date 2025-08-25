Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Base paths
$basePath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$softwarePath = Join-Path $basePath "Software"
$officePath   = Join-Path $softwarePath "Office"

# Create the form
$form                  = New-Object System.Windows.Forms.Form
$form.Text             = "Software Installer"
$form.Size             = New-Object System.Drawing.Size(500,380)
$form.StartPosition    = "CenterScreen"

# Office Selection Label
$labelOffice           = New-Object System.Windows.Forms.Label
$labelOffice.Text      = "Select MS Office Version:"
$labelOffice.Location  = New-Object System.Drawing.Point(20,20)
$labelOffice.Size      = New-Object System.Drawing.Size(200,20)
$form.Controls.Add($labelOffice)

# Office Dropdown
$comboOffice               = New-Object System.Windows.Forms.ComboBox
$comboOffice.Location      = New-Object System.Drawing.Point(220,18)
$comboOffice.Size          = New-Object System.Drawing.Size(200,20)
$comboOffice.DropDownStyle = "DropDownList"
$comboOffice.Items.AddRange(@("Skip","2016","2019","O365"))
$comboOffice.SelectedIndex = 0
$form.Controls.Add($comboOffice)

# Checkboxes for other software
$chk7zip         = New-Object System.Windows.Forms.CheckBox
$chk7zip.Text    = "Install 7zip"
$chk7zip.Location= New-Object System.Drawing.Point(20,60)
$form.Controls.Add($chk7zip)

$chkAdobe        = New-Object System.Windows.Forms.CheckBox
$chkAdobe.Text   = "Install Adobe"
$chkAdobe.Location= New-Object System.Drawing.Point(20,90)
$form.Controls.Add($chkAdobe)

$chkChrome       = New-Object System.Windows.Forms.CheckBox
$chkChrome.Text  = "Install Chrome"
$chkChrome.Location= New-Object System.Drawing.Point(20,120)
$form.Controls.Add($chkChrome)

# Output box
$outputBox               = New-Object System.Windows.Forms.TextBox
$outputBox.Multiline     = $true
$outputBox.ScrollBars    = "Vertical"
$outputBox.Location      = New-Object System.Drawing.Point(20,160)
$outputBox.Size          = New-Object System.Drawing.Size(440,140)
$outputBox.ReadOnly      = $true
$form.Controls.Add($outputBox)

function Write-Log($msg) {
    $outputBox.AppendText("$(Get-Date -Format 'HH:mm:ss') - $msg`r`n")
}

# Install software function
function Install-SoftwareFromFolder {
    param ([string]$name)

    $folder = Join-Path $softwarePath $name
    if (!(Test-Path $folder)) { Write-Log "Folder not found: $folder"; return }
    $installers = Get-ChildItem -Path $folder -Include *.exe, *.msi -File -Recurse
    if ($installers.Count -eq 0) { Write-Log "No installers found in $folder"; return }

    foreach ($installer in $installers) {
        Write-Log "Installing $($installer.Name)..."
        if ($name -eq "Adobe") {
            Start-Process -FilePath $installer.FullName -ArgumentList "/sAll /rs /rps /msi /norestart /quiet EULA_ACCEPT=YES" -Wait
        } elseif ($name -eq "7zip") {
            if ($installer.Extension -eq ".msi") {
                Start-Process "msiexec.exe" -ArgumentList "/i `"$($installer.FullName)`" /qn /norestart" -Wait
            } else {
                Start-Process $installer.FullName -ArgumentList "/S" -Wait
            }
        } elseif ($installer.Extension -eq ".msi") {
            Start-Process "msiexec.exe" -ArgumentList "/i `"$($installer.FullName)`" /quiet /norestart" -Wait
        } else {
            Start-Process $installer.FullName -ArgumentList "/silent","/s","/quiet","/qn" -Wait
        }
        Write-Log "$($installer.Name) installation complete."
    }
}

# Install Button
$btnInstall              = New-Object System.Windows.Forms.Button
$btnInstall.Text         = "Start Installation"
$btnInstall.Location     = New-Object System.Drawing.Point(20,310)
$btnInstall.Size         = New-Object System.Drawing.Size(150,30)
$btnInstall.Add_Click({
    $officeVersion = $comboOffice.SelectedItem
    if ($officeVersion -and $officeVersion -ne "Skip") {
        try {
            $officeFolder = Join-Path $officePath $officeVersion
            if ($officeVersion -eq "O365") {
                $setupExe = Join-Path $officeFolder "OfficeSetup.exe"
                if (-not (Test-Path $setupExe)) { throw "OfficeSetup.exe not found for Office 365." }
                Write-Log "Installing Office 365..."
                Start-Process -FilePath $setupExe -ArgumentList "/configure configuration.xml" -Wait
            } else {
                $isoFile = Get-ChildItem -Path $officeFolder -Filter *.iso | Select-Object -First 1
                if (-not $isoFile) { throw "No ISO found for Office $officeVersion." }
                $mount = Mount-DiskImage -ImagePath $isoFile.FullName -PassThru
                $driveLetter = ($mount | Get-Volume).DriveLetter + ":"
                $setupBat = Join-Path "$driveLetter\" "setup.bat"
                if (-not (Test-Path $setupBat)) { throw "setup.bat not found in mounted ISO." }
                Write-Log "Installing $officeVersion..."
                Push-Location $driveLetter
                & $setupBat
                Pop-Location
                Dismount-DiskImage -ImagePath $isoFile.FullName
            }
            Write-Log "Office $officeVersion installation complete."
        } catch {
            Write-Log "Failed to install Office: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Skipping Office installation."
    }

    if ($chk7zip.Checked) { Install-SoftwareFromFolder "7zip" }
    if ($chkAdobe.Checked) { Install-SoftwareFromFolder "Adobe" }
    if ($chkChrome.Checked){ Install-SoftwareFromFolder "Chrome" }

    # Always run Winget updates
    if (-not (Get-Command "winget" -ErrorAction SilentlyContinue)) {
        Write-Log "winget is not available. Please install App Installer."
    } else {
        Write-Log "Updating all apps with winget..."
        Start-Process "winget" -ArgumentList "upgrade --all --accept-source-agreements --accept-package-agreements" -Wait
        Write-Log "Winget updates completed."
    }

    Write-Log "All done!"
})
$form.Controls.Add($btnInstall)

$form.ShowDialog()
