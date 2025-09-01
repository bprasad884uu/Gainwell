# Create an Outlook application object
$outlook = New-Object -ComObject Outlook.Application

# Create a new mail item
$mail = $outlook.CreateItem(0)  # 0 = olMailItem

# Display the mail temporarily to load the default signature
$mail.Display()

# Specify the account to send from (leave empty to use default)
$mailID = ""  

# Set the account to send from
if (![string]::IsNullOrWhiteSpace($mailID)) {
    $accountToUse = $outlook.Session.Accounts | Where-Object { $_.SmtpAddress -eq $mailID }
    if ($accountToUse) {
        $mail.SendUsingAccount = $accountToUse
    } else {
        Write-Output "Specified account not found. Using default account."
    }
}

# Set the email properties
$mail.To = "servicedesk@acceleronsolutions.io"
$mail.Subject = "Subject"

# Prepend your message above the signature
$mail.HTMLBody = @"
<p>Dear Team,</p>
<p>Email Body.</p>
"@ + $mail.HTMLBody

# Send the email
$mail.Send()

Write-Output "Email sent successfully!"
