Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "AD Tool"
$form.Size = New-Object System.Drawing.Size(500,500)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.SystemColors]::Control  # system theme

# Tooltip
$tooltip = New-Object System.Windows.Forms.ToolTip
$tooltip.AutoPopDelay = 5000
$tooltip.InitialDelay = 500
$tooltip.ReshowDelay = 200
$tooltip.ShowAlways = $true

# Mail ID
$lblMail = New-Object System.Windows.Forms.Label
$lblMail.Text = "Enter User Mail ID:"
$lblMail.Location = '20,20'
$lblMail.AutoSize = $true
$form.Controls.Add($lblMail)

$txtMail = New-Object System.Windows.Forms.TextBox
$txtMail.Location = '20,45'
$txtMail.Width = 440
$txtMail.Font = New-Object System.Drawing.Font("Segoe UI",10)
$form.Controls.Add($txtMail)

# Password
$lblPass = New-Object System.Windows.Forms.Label
$lblPass.Text = "Enter New Password:"
$lblPass.Location = '20,75'
$lblPass.AutoSize = $true
$form.Controls.Add($lblPass)

$txtPassword = New-Object System.Windows.Forms.TextBox
$txtPassword.Location = '20,100'
$txtPassword.Width = 440
$txtPassword.UseSystemPasswordChar = $true
$txtPassword.Font = New-Object System.Drawing.Font("Segoe UI",10)
$form.Controls.Add($txtPassword)

# Password Rules Labels
$lblRule1 = New-Object System.Windows.Forms.Label
$lblRule1.Text = "• Minimum 8 characters"
$lblRule1.Location = '40,130'
$lblRule1.AutoSize = $true
$form.Controls.Add($lblRule1)

$lblRule2 = New-Object System.Windows.Forms.Label
$lblRule2.Text = "• Cannot contain username"
$lblRule2.Location = '40,150'
$lblRule2.AutoSize = $true
$form.Controls.Add($lblRule2)

$lblRule3 = New-Object System.Windows.Forms.Label
$lblRule3.Text = "• Must include 1 letter, 1 number, 1 symbol"
$lblRule3.Location = '40,170'
$lblRule3.AutoSize = $true
$form.Controls.Add($lblRule3)

# Checkboxes
$chkReset = New-Object System.Windows.Forms.CheckBox
$chkReset.Text = "Reset AD Password"
$chkReset.Location = '20,200'
$chkReset.Width = 280
$chkReset.Font = New-Object System.Drawing.Font("Segoe UI",10)
$form.Controls.Add($chkReset)
$tooltip.SetToolTip($chkReset, "Resets the user's AD password. Password entry is required when checked.")

$chkUnlock = New-Object System.Windows.Forms.CheckBox
$chkUnlock.Text = "Unlock AD Account"
$chkUnlock.Location = '20,225'
$chkUnlock.Width = 280
$chkUnlock.Font = New-Object System.Drawing.Font("Segoe UI",10)
$form.Controls.Add($chkUnlock)
$tooltip.SetToolTip($chkUnlock, "Unlocks the user's AD account if it is locked.")

$chkExtend = New-Object System.Windows.Forms.CheckBox
$chkExtend.Text = "Extend Password Expiry (90 Days)"
$chkExtend.Location = '20,250'
$chkExtend.Width = 280
$chkExtend.Font = New-Object System.Drawing.Font("Segoe UI",10)
$form.Controls.Add($chkExtend)
$tooltip.SetToolTip($chkExtend, "Extends the user's password expiry date by 90 days.")

# Output textbox
$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = '20,280'
$txtOutput.Width = 440
$txtOutput.Height = 120
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.BackColor = [System.Drawing.Color]::White
$txtOutput.Font = New-Object System.Drawing.Font("Consolas",10)
$txtOutput.BorderStyle = "FixedSingle"
$form.Controls.Add($txtOutput)

# Logging function
function Write-Log($msg) {
    $txtOutput.AppendText("$msg`r`n")
    $txtOutput.SelectionStart = $txtOutput.Text.Length
    $txtOutput.ScrollToCaret()
}

# Rounded 3D Button Function
function New-Rounded3DButton {
    param (
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 100,
        [int]$Height = 35,
        [System.Drawing.Color]$BaseColor = [System.Drawing.Color]::FromArgb(0,120,215),
        [System.Drawing.Color]$TextColor = [System.Drawing.Color]::White
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Size = New-Object System.Drawing.Size($Width,$Height)
    $button.Location = New-Object System.Drawing.Point($X,$Y)
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderSize = 0
    $button.ForeColor = $TextColor
    $button.Font = New-Object System.Drawing.Font("Segoe UI",10)
    $button.BackColor = [System.Drawing.Color]::Transparent

    # Custom properties
    $button | Add-Member -MemberType NoteProperty -Name IsDisabled -Value $false
    $button | Add-Member -MemberType NoteProperty -Name Hover -Value $false

    # Mouse events
    $button.Add_MouseEnter({
        param($sender,$e)
        if (-not $sender.IsDisabled) { $sender.Hover = $true; $sender.Invalidate() }
    })
    $button.Add_MouseLeave({
        param($sender,$e)
        if (-not $sender.IsDisabled) { $sender.Hover = $false; $sender.Invalidate() }
    })

    # Paint event
    $button.Add_Paint({
        param($sender,$e)
        $rectF = New-Object System.Drawing.RectangleF(0,0,[float]$sender.Width,[float]$sender.Height)
        $radius = 10
        if ($sender.IsDisabled) {
            $topColor = [System.Drawing.Color]::LightGray
            $bottomColor = [System.Drawing.Color]::Gray
            $textBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::WhiteSmoke)
        } else {
            if ($sender.Hover) {
                $topColor = [System.Drawing.Color]::FromArgb(0,180,255)
                $bottomColor = [System.Drawing.Color]::FromArgb(0,140,235)
            } else {
                $topColor = [System.Drawing.Color]::FromArgb(0,150,255)
                $bottomColor = [System.Drawing.Color]::FromArgb(0,120,215)
            }
            $textBrush = [System.Drawing.SolidBrush]::new($sender.ForeColor)
        }
        $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rectF,$topColor,$bottomColor,[System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $path.AddArc(0,0,$radius,$radius,180,90)
        $path.AddArc($sender.Width-$radius-1,0,$radius,$radius,270,90)
        $path.AddArc($sender.Width-$radius-1,$sender.Height-$radius-1,$radius,$radius,0,90)
        $path.AddArc(0,$sender.Height-$radius-1,$radius,$radius,90,90)
        $path.CloseFigure()
        $e.Graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $e.Graphics.FillPath($brush,$path)
        $sf = New-Object System.Drawing.StringFormat
        $sf.Alignment = [System.Drawing.StringAlignment]::Center
        $sf.LineAlignment = [System.Drawing.StringAlignment]::Center
        $e.Graphics.DrawString($sender.Text,$sender.Font,$textBrush,$rectF,$sf)
    })

    return $button
}

# Buttons
$btnSubmit = New-Rounded3DButton -Text "Submit" -X 150 -Y 420
$btnClose  = New-Rounded3DButton -Text "Close"  -X 270 -Y 420 -BaseColor ([System.Drawing.Color]::FromArgb(168,0,0))
$form.Controls.Add($btnSubmit)
$form.Controls.Add($btnClose)

# Validate password rules
function ValidatePasswordRules {
    $pwd = $txtPassword.Text
    $username = $txtMail.Text.Trim()

    if ($chkReset.Checked) {
        # Show rules
        $lblRule1.Visible = $true
        $lblRule2.Visible = $true
        $lblRule3.Visible = $true

        # Rule 1: Minimum 8 characters
        if ($pwd.Length -ge 8) { 
            $lblRule1.ForeColor = [System.Drawing.Color]::Green 
        } else { 
            $lblRule1.ForeColor = [System.Drawing.Color]::Red 
        }

        # Rule 2: Cannot contain username parts ≥3 characters
        if ([string]::IsNullOrWhiteSpace($pwd)) {
            $lblRule2.ForeColor = [System.Drawing.Color]::Red
        } else {
            $containsUsernamePart = $false
            for ($i = 0; $i -le $username.Length - 3; $i++) {
                for ($len = 3; $len -le $username.Length - $i; $len++) {
                    $substr = $username.Substring($i,$len)
                    if ($pwd.ToLower().Contains($substr.ToLower())) { 
                        $containsUsernamePart = $true
                        break
                    }
                }
                if ($containsUsernamePart) { break }
            }

            if ($containsUsernamePart) {
                $lblRule2.ForeColor = [System.Drawing.Color]::Red
            } else {
                $lblRule2.ForeColor = [System.Drawing.Color]::Green
            }
        }

        # Rule 3: Must contain 1 letter, 1 number, 1 symbol
        if ($pwd -match '[A-Za-z]' -and $pwd -match '\d' -and $pwd -match '[^A-Za-z0-9]') { 
            $lblRule3.ForeColor = [System.Drawing.Color]::Green 
        } else { 
            $lblRule3.ForeColor = [System.Drawing.Color]::Red 
        }

        # Disable Submit if any rule fails
        if ($lblRule1.ForeColor -eq [System.Drawing.Color]::Red -or
            $lblRule2.ForeColor -eq [System.Drawing.Color]::Red -or
            $lblRule3.ForeColor -eq [System.Drawing.Color]::Red) {
            $btnSubmit.IsDisabled = $true
        } else {
            $btnSubmit.IsDisabled = $false
        }
    } else {
        # Hide rules and enable Submit
        $lblRule1.Visible = $false
        $lblRule2.Visible = $false
        $lblRule3.Visible = $false
        $btnSubmit.IsDisabled = $false
    }

    $btnSubmit.Invalidate()
}

$chkReset.Add_CheckedChanged({ ValidatePasswordRules })
$txtPassword.Add_TextChanged({ ValidatePasswordRules })
$txtMail.Add_TextChanged({ ValidatePasswordRules })
ValidatePasswordRules

# Button Actions
$btnSubmit.Add_Click({
    if ($btnSubmit.IsDisabled) { return }
    $txtOutput.Clear()
    $User = $txtMail.Text.Trim()
    $CustomPassword = $txtPassword.Text.Trim()

    if (-not $User) { Write-Log "❌ Please enter a Mail ID."; return }
    if ($chkReset.Checked -and -not $CustomPassword) { Write-Log "❌ Password is required."; return }

    Try {
    $ADUser = Get-ADUser -Filter {
        (Mail -eq $User) -or
        (UserPrincipalName -eq $User) -or
        (SamAccountName -eq $User)
    } -Properties Mail,UserPrincipalName -ErrorAction Stop

    Write-Log "✅ Found AD User: $($ADUser.SamAccountName)"
	}
	Catch {
		Write-Log "❌ User [$User] not found in AD (tried Mail, UPN, and SamAccountName)."
		return
	}

    if ($chkReset.Checked) {
        $NewPassword = ConvertTo-SecureString $CustomPassword -AsPlainText -Force
        Try { Set-ADAccountPassword -Identity $ADUser.SamAccountName -NewPassword $NewPassword -Reset; Write-Log "🔑 Password reset successful." } Catch { Write-Log "❌ Password reset failed: $_" }
    }
    if ($chkUnlock.Checked) { Try { Unlock-ADAccount -Identity $ADUser.SamAccountName; Write-Log "🔓 Account unlocked." } Catch { Write-Log "❌ Unlock failed: $_" } }
    if ($chkExtend.Checked) {
    Try {
        # Set password last set to now
        Set-ADUser -Identity $ADUser.SamAccountName -Replace @{pwdLastSet=-1}

        # Fetch new expiry date
        $expDate = (Get-ADUser $ADUser.SamAccountName -Properties msDS-UserPasswordExpiryTimeComputed |
                    Select-Object -ExpandProperty msDS-UserPasswordExpiryTimeComputed |
                    ForEach-Object { [datetime]::FromFileTime($_) })

        Write-Log "📅 Password expiry extended. Next expiry: $expDate"
    }
    Catch {
        Write-Log "❌ Extend failed: $_"
		}
	}
})

$btnClose.Add_Click({ $form.Close() })

# Show Form
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
