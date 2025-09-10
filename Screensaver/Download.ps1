[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PAT   = "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"   # <-- put your token here
$Owner = "bprasad884uu"
$Repo  = "Gainwell"
$Path  = "App-Block`/Block-Installations.ps1"
$Ref   = "main"

$headers = @{
    Authorization = "token $PAT"
    "User-Agent"  = "ScriptRunner"
    Accept        = "application/vnd.github.v3+json"
}

$encoded = [System.Web.HttpUtility]::UrlEncode($Path).Replace("+","%20")
$apiUrl  = "https://api.github.com/repos/$Owner/$Repo/contents/$encoded`?ref=$Ref"

Write-Host "Requesting: $apiUrl"

try {
    $resp = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get -ErrorAction Stop
    $bytes = [System.Convert]::FromBase64String($resp.content)
    $out   = Join-Path $env:TEMP $resp.name
    [System.IO.File]::WriteAllBytes($out, $bytes)
    Write-Host "Saved file to: $out"

    # Run it
    & powershell -NoProfile -ExecutionPolicy Bypass -File $out
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
}
