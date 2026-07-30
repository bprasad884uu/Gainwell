# ============================================
# EDIT THESE VALUES BEFORE RUNNING
# ============================================
$To      = "servicedesk@acceleronsolutions.io"
$CC      = ""
$BCC     = ""
$Subject = "Subject here"
$Body    = "Your mail body text here.
Second line if needed."
# ============================================

$Outlook   = $null
$Namespace = $null
$Mail      = $null

try {
    $Outlook   = New-Object -ComObject Outlook.Application
    $Namespace = $Outlook.GetNamespace("MAPI")

    $Mail = $Outlook.CreateItem(0)   # 0 = olMailItem

    # Outlook auto-fills HTMLBody with the default "New Message" signature
    # at item creation time, IF one is configured in Outlook Options.
    $DefaultSignatureHtml = $Mail.HTMLBody

    $Mail.To      = $To
    $Mail.Subject = $Subject

    if ($CC)  { $Mail.CC  = $CC }
    if ($BCC) { $Mail.BCC = $BCC }

    # Convert plain text body to HTML, preserving line breaks
    $BodyHtml = ($Body -replace "`r`n", "<br>" -replace "`n", "<br>")

    # Check if a real signature exists (not just empty/whitespace HTML shell)
    $SignatureText = $DefaultSignatureHtml -replace '<[^>]+>', '' -replace '&nbsp;', ' '
    $HasSignature  = -not [string]::IsNullOrWhiteSpace($SignatureText)

    if ($HasSignature) {
        # Signature exists -> body + signature
        $Mail.HTMLBody = "<div style='font-family:Calibri,Arial,sans-serif;font-size:11pt'>$BodyHtml</div><br>" + $DefaultSignatureHtml
        Write-Host "Signature found and included." -ForegroundColor Cyan
    }
    else {
        # No signature configured -> just the body, nothing appended
        $Mail.HTMLBody = "<div style='font-family:Calibri,Arial,sans-serif;font-size:11pt'>$BodyHtml</div>"
        Write-Host "No default signature found - skipped." -ForegroundColor Yellow
    }

    # SendUsingAccount is intentionally NOT set.
    # Outlook will use whichever account is marked DEFAULT under
    # File > Account Settings > "Always send from default account".

    $Mail.Send()
    Write-Host "Mail sent successfully to $To" -ForegroundColor Green
}
catch {
    Write-Host "Failed to send mail: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($Mail)      { [Runtime.InteropServices.Marshal]::ReleaseComObject($Mail)      | Out-Null }
    if ($Namespace) { [Runtime.InteropServices.Marshal]::ReleaseComObject($Namespace) | Out-Null }
    if ($Outlook)   { [Runtime.InteropServices.Marshal]::ReleaseComObject($Outlook)   | Out-Null }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}