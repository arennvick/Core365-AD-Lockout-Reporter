<#
  Get-LockoutCaller_v1.7.4.ps1

  AD lockout HTML report (Event ID 4740) from the PDC Emulator.

  Output:
  - Always writes an HTML report to disk (default: same folder as the script).
  - Optionally emails the report INLINE in the email body using Microsoft Graph (no attachment)
    when -SendEmail is supplied.

#>

param(
    [int]$HoursBack = 12,
    [string]$OutputPath,
    [switch]$LatestPerUser,

    # Email (Graph)
    [switch]$SendEmail,
    [string]$TenantId = "<TENANT-ID-GUID>",
    [string]$ClientId = "<APP-CLIENT-ID-GUID>",
    [string]$CertificateThumbprint = "<CERT-THUMBPRINT>",

    [string]$FromAddress = "sender@domain.com",
    [string[]]$ToRecipients = @("recipient@domain.com"),
    [string[]]$CcRecipients = @(),
    [string]$SubjectPrefix = "AD Lockout Report",
    [switch]$SaveToSentItems
)

# ---------------------------
# Helpers
# ---------------------------
function Normalize-EmailList {
    param([string[]]$List)

    if (-not $List) { return @() }

    $expanded = foreach ($item in $List) {
        if ($null -eq $item) { continue }
        $item.ToString().Split(",") | ForEach-Object { $_.Trim() }
    }

    $clean = $expanded |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique

    return @($clean)
}

function Get-EventDataValue {
    param([xml]$EventXml, [string]$Name)
    (($EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text')
}

function Get-RegexValue {
    param([string]$Text, [string]$Pattern)
    $m = [regex]::Match($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $null
}

function Clean-CallerComputer {
    param([string]$CallerRaw)

    if ([string]::IsNullOrWhiteSpace($CallerRaw)) { return $null }

    $c = $CallerRaw.Trim()
    $c = ($c -replace '\s*-\s*S-\d-\d+(-\d+){1,}\s*$', '').Trim()   # strip trailing SID
    if ($c -match '^S-\d-\d+(-\d+){1,}$') { return $null }

    $tokens = $c -split '\s+'
    foreach ($t in $tokens) {
        $t2 = $t.Trim()
        if ($t2 -match '^[A-Za-z0-9][A-Za-z0-9\-_\.]{1,}$') { return $t2 }
    }

    if ($c -eq '-') { return $null }
    return $c
}

# ---------------------------
# Output path (script folder by default)
# ---------------------------
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $basePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path -Path $basePath -ChildPath "AD-Lockout-Report.html"
}

# ---------------------------
# AD / Event collection
# ---------------------------
Import-Module ActiveDirectory -ErrorAction Stop

$PDC = (Get-ADDomain).PDCEmulator
$startTime = (Get-Date).AddHours(-$HoursBack)

Write-Host "Querying Event ID 4740 on PDC: $PDC (since $startTime)" -ForegroundColor Cyan

$events = Get-WinEvent -ComputerName $PDC -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4740
    StartTime = $startTime
} -ErrorAction Stop

if (-not $events) {
    Write-Host "No lockout events found in the last $HoursBack hours on $PDC." -ForegroundColor Yellow
    return
}

# ---------------------------
# Build rows
# ---------------------------
$rows = foreach ($e in $events) {

    $targetUser   = $null
    $targetDomain = $null
    $caller       = $null

    # XML extraction
    try {
        $xml = [xml]$e.ToXml()
        $targetUser   = Get-EventDataValue -EventXml $xml -Name 'TargetUserName'
        $targetDomain = Get-EventDataValue -EventXml $xml -Name 'TargetDomainName'
        $caller       = Get-EventDataValue -EventXml $xml -Name 'CallerComputerName'
        if ([string]::IsNullOrWhiteSpace($caller)) {
            $caller = Get-EventDataValue -EventXml $xml -Name 'WorkstationName'
        }
    } catch {}

    # Message fallback
    $msg = $e.Message

    if ([string]::IsNullOrWhiteSpace($targetUser)) {
        $targetUser = Get-RegexValue -Text $msg -Pattern 'Account That Was Locked Out:\s*(?:.|\r|\n)*?Account Name:\s*([^\r\n]+)'
        if ([string]::IsNullOrWhiteSpace($targetUser)) {
            $targetUser = Get-RegexValue -Text $msg -Pattern 'Account Name:\s*([^\r\n]+)'
        }
    }

    if ([string]::IsNullOrWhiteSpace($targetDomain)) {
        $targetDomain = Get-RegexValue -Text $msg -Pattern 'Account That Was Locked Out:\s*(?:.|\r|\n)*?Account Domain:\s*([^\r\n]+)'
        if ([string]::IsNullOrWhiteSpace($targetDomain)) {
            $targetDomain = Get-RegexValue -Text $msg -Pattern 'Account Domain:\s*([^\r\n]+)'
        }
    }

    if ([string]::IsNullOrWhiteSpace($caller)) {
        $caller = Get-RegexValue -Text $msg -Pattern 'Caller Computer Name:\s*([^\r\n]+)'
    }

    if ([string]::IsNullOrWhiteSpace($targetUser)) { continue }

    $targetUser = $targetUser.Trim()
    if ($targetDomain) { $targetDomain = $targetDomain.Trim() }

    $caller = Clean-CallerComputer -CallerRaw $caller

    # FIX: if domain == caller, do NOT show twice
    $domainCaller =
        if (-not [string]::IsNullOrWhiteSpace($caller) -and -not [string]::IsNullOrWhiteSpace($targetDomain) -and ($caller -ieq $targetDomain)) {
            $caller
        } elseif (-not [string]::IsNullOrWhiteSpace($targetDomain) -and -not [string]::IsNullOrWhiteSpace($caller)) {
            "$targetDomain - $caller"
        } elseif (-not [string]::IsNullOrWhiteSpace($targetDomain)) {
            "$targetDomain"
        } elseif (-not [string]::IsNullOrWhiteSpace($caller)) {
            "$caller"
        } else {
            ""
        }

    [PSCustomObject]@{
        TimeCreated          = $e.TimeCreated
        SamAccountName       = $targetUser
        DomainCallerCombined = $domainCaller
        DomainController     = $PDC
        EventRecordId        = $e.RecordId
    }
}

if ($LatestPerUser) {
    $rows = $rows |
        Sort-Object TimeCreated -Descending |
        Group-Object SamAccountName |
        ForEach-Object { $_.Group | Select-Object -First 1 }
}

$rows = $rows | Sort-Object SamAccountName, @{ Expression = 'TimeCreated'; Descending = $true }

# ---------------------------
# Build HTML (browser report - modern light theme)
# ---------------------------
$generated = Get-Date

# Theme colors
$Mint = "#66CC99"
$Teal = "#005566"
$Navy = "#000066"

$styleBrowser = @"
<style>
  :root{
    --mint: $Mint;
    --teal: $Teal;
    --navy: $Navy;
    --bg: #f6fbf8;
    --card: #ffffff;
    --line: #dfeee6;
    --text: #17333a;
    --muted: #4b6a72;
    --shadow: 0 8px 22px rgba(0,0,0,.06);
  }
  html, body { padding: 0; margin: 0; }
  body{ font-family: "Segoe UI", Arial, sans-serif; background: var(--bg); color: var(--text); }
  .container{ max-width: 1100px; margin: 20px auto; padding: 0 14px; }
  .headerCard{
    background: var(--card); border: 1px solid var(--line); border-radius: 14px;
    box-shadow: var(--shadow); padding: 16px 16px 10px 16px; position: relative; overflow: hidden;
  }
  .headerCard:before{ content:""; position:absolute; left:0; top:0; height:6px; width:100%;
    background: linear-gradient(90deg, var(--mint), rgba(102,204,153,.35));
  }
  h1{ margin:0; font-size:18px; color: var(--navy); letter-spacing:.2px; }
  .meta{ margin-top:10px; display:flex; flex-wrap:wrap; gap:8px; color: var(--muted); font-size:12px; }
  .pill{ display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius:999px;
    border:1px solid var(--line); background:#fbfffd; white-space:nowrap;
  }
  .pill b{ color: var(--teal); font-weight:600; }
  .tableCard{ margin-top:12px; background: var(--card); border:1px solid var(--line); border-radius:14px;
    box-shadow: var(--shadow); overflow:hidden;
  }
  .tableTopbar{ padding:10px 14px; border-bottom:1px solid var(--line); background:#fbfffd; color: var(--muted); font-size:12px; }
  .tableWrap{ overflow-x:auto; }
  table.reportTable{ width:100%; border-collapse:separate; border-spacing:0; font-size:12px; }
  thead th{ text-align:left; padding:10px 12px; background: rgba(102,204,153,.32);
    color: var(--navy); border-bottom:1px solid var(--line); font-weight:600;
  }
  tbody td{ padding:9px 12px; border-bottom:1px solid var(--line); background:#fff; }
  tbody tr:nth-child(even) td{ background:#f9fefb; }
  tbody tr:hover td{ background: rgba(102,204,153,.14); }
  th:nth-child(1), td:nth-child(1){ width:170px; white-space:nowrap; }
  th:nth-child(2), td:nth-child(2){ width:150px; font-weight:600; color: var(--teal); }
  th:nth-child(4), td:nth-child(4){ width:280px; }
  th:nth-child(5), td:nth-child(5){ width:120px; white-space:nowrap; font-variant-numeric: tabular-nums; }
  th:nth-child(3), td:nth-child(3){ min-width:260px; overflow-wrap:anywhere; }

  /* Footer */
  .footer{
    margin: 14px 0 24px 0;
    text-align: center;
    font-size: 12px;
    color: var(--muted);
  }
  .footer a{
    color: var(--teal);
    text-decoration: none;
    font-weight: 600;
  }
  .footer a:hover{ text-decoration: underline; }
</style>
"@

$metaBrowser = @"
<div class="container">
  <div class="headerCard">
    <h1>AD Account Lockout Report (Event ID 4740)</h1>
    <div class="meta">
      <div class="pill">PDC Emulator: <b>$PDC</b></div>
      <div class="pill">Time window: <b>Last $HoursBack hour(s)</b> (since <b>$startTime</b>)</div>
      <div class="pill">Generated: <b>$generated</b></div>
      <div class="pill">Rows: <b>$($rows.Count)</b> $(if($LatestPerUser){"(latest per user)"}else{"(all lockouts)"})</div>
    </div>
  </div>
"@

$htmlTable = $rows |
    Select-Object TimeCreated, SamAccountName,
        @{ Name = 'Domain - Caller Computer'; Expression = { $_.DomainCallerCombined } },
        DomainController, EventRecordId |
    ConvertTo-Html -Fragment

# Wrap table in cards and add class (NO theme line)
$htmlTable = $htmlTable -replace '<table>', '<div class="tableCard"><div class="tableTopbar">Details</div><div class="tableWrap"><table class="reportTable">' `
                     -replace '</table>', '</table></div></div>'

# Footer (browser)
$footerBrowser = @"
  <div class="footer">
    Script by <b>core365.cloud</b> — <a href="https://blog.core365.cloud">blog.core365.cloud</a>
  </div>
"@

$finalHtmlBrowser = @"
<html>
<head>
<meta charset="utf-8">
<title>AD Lockout Report</title>
$styleBrowser
</head>
<body>
$metaBrowser
$htmlTable
$footerBrowser
</div>
</body>
</html>
"@

# Save report to disk
$folder = Split-Path $OutputPath -Parent
if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
$finalHtmlBrowser | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "Report saved to: $OutputPath" -ForegroundColor Green

# ---------------------------
# Build EMAIL HTML (INLINE CSS for email clients)
# ---------------------------
$emailHeader = @"
<div style="font-family:Segoe UI,Arial,sans-serif;color:#17333a;">
  <div style="border:1px solid #dfeee6;border-radius:12px;background:#ffffff;padding:14px 14px 10px 14px;">
    <div style="height:5px;border-radius:10px 10px 0 0;background:#66CC99;margin:-14px -14px 12px -14px;"></div>
    <div style="font-size:16px;font-weight:700;color:#000066;margin:0 0 10px 0;">AD Account Lockout Report (Event ID 4740)</div>
    <div style="font-size:12px;color:#4b6a72;line-height:1.4;">
      <div><b style="color:#005566;">PDC Emulator:</b> $PDC</div>
      <div><b style="color:#005566;">Time window:</b> Last $HoursBack hour(s) (since $startTime)</div>
      <div><b style="color:#005566;">Generated:</b> $generated</div>
      <div><b style="color:#005566;">Rows:</b> $($rows.Count) $(if($LatestPerUser){"(latest per user)"}else{"(all lockouts)"})</div>
    </div>
  </div>
</div>
"@

$emailTableRows = foreach ($r in $rows) {
    $t  = ($r.TimeCreated).ToString("M/d/yyyy h:mm:ss tt")
    $u  = $r.SamAccountName
    $dc = $r.DomainCallerCombined
    $dchost = $r.DomainController
    $rid = $r.EventRecordId

@"
<tr>
  <td style="padding:8px 10px;border-bottom:1px solid #dfeee6;white-space:nowrap;">$t</td>
  <td style="padding:8px 10px;border-bottom:1px solid #dfeee6;font-weight:700;color:#005566;white-space:nowrap;">$u</td>
  <td style="padding:8px 10px;border-bottom:1px solid #dfeee6;">$dc</td>
  <td style="padding:8px 10px;border-bottom:1px solid #dfeee6;">$dchost</td>
  <td style="padding:8px 10px;border-bottom:1px solid #dfeee6;white-space:nowrap;">$rid</td>
</tr>
"@
}

$emailTable = @"
<div style="font-family:Segoe UI,Arial,sans-serif;margin-top:12px;">
  <div style="border:1px solid #dfeee6;border-radius:12px;background:#ffffff;overflow:hidden;">
    <div style="padding:10px 12px;border-bottom:1px solid #dfeee6;background:#fbfffd;color:#4b6a72;font-size:12px;">
      Details
    </div>
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead>
        <tr>
          <th align="left" style="padding:9px 10px;background:#d9f2e6;color:#000066;border-bottom:1px solid #dfeee6;">TimeCreated</th>
          <th align="left" style="padding:9px 10px;background:#d9f2e6;color:#000066;border-bottom:1px solid #dfeee6;">SamAccountName</th>
          <th align="left" style="padding:9px 10px;background:#d9f2e6;color:#000066;border-bottom:1px solid #dfeee6;">Domain - Caller Computer</th>
          <th align="left" style="padding:9px 10px;background:#d9f2e6;color:#000066;border-bottom:1px solid #dfeee6;">DomainController</th>
          <th align="left" style="padding:9px 10px;background:#d9f2e6;color:#000066;border-bottom:1px solid #dfeee6;">EventRecordId</th>
        </tr>
      </thead>
      <tbody>
        $($emailTableRows -join "`r`n")
      </tbody>
    </table>
  </div>
</div>
"@

# Footer (email) — inline and clickable
$emailFooter = @"
<div style="font-family:Segoe UI,Arial,sans-serif;text-align:center;margin-top:14px;font-size:12px;color:#4b6a72;">
  Script by <b>core365.cloud</b> — <a href="https://blog.core365.cloud" style="color:#005566;font-weight:600;text-decoration:none;">blog.core365.cloud</a>
</div>
"@

$finalEmailHtml = $emailHeader + $emailTable + $emailFooter

# ---------------------------
# OPTIONAL: Send Email via Graph (inline body)
# ---------------------------
if ($SendEmail) {

    if ($TenantId -like "<*>" -or [string]::IsNullOrWhiteSpace($TenantId)) { throw "TenantId is not configured." }
    if ($ClientId -like "<*>" -or [string]::IsNullOrWhiteSpace($ClientId)) { throw "ClientId is not configured." }
    if ($CertificateThumbprint -like "<*>" -or [string]::IsNullOrWhiteSpace($CertificateThumbprint)) { throw "CertificateThumbprint is not configured." }
    if ([string]::IsNullOrWhiteSpace($FromAddress)) { throw "FromAddress is not configured." }

    $ToRecipients = Normalize-EmailList -List $ToRecipients
    $CcRecipients = Normalize-EmailList -List $CcRecipients

    if ($ToRecipients.Count -eq 0) {
        throw "SendEmail requested but ToRecipients is empty/invalid. Provide -ToRecipients `"user@domain.com`"."
    }

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        throw "Microsoft.Graph module not found. Install with: Install-Module Microsoft.Graph -Scope AllUsers"
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    try {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome | Out-Null

        $subject = "$SubjectPrefix (SGT) - $PDC - Last $HoursBack hours"

        $payload = @{
            message = @{
                subject = $subject
                body = @{
                    contentType = "HTML"
                    content     = $finalEmailHtml
                }
                toRecipients = @(
                    $ToRecipients | ForEach-Object { @{ emailAddress = @{ address = $_ } } }
                )
            }
            saveToSentItems = $SaveToSentItems.IsPresent
        }

        if ($CcRecipients.Count -gt 0) {
            $payload.message.ccRecipients = @(
                $CcRecipients | ForEach-Object { @{ emailAddress = @{ address = $_ } } }
            )
        }

        $json = $payload | ConvertTo-Json -Depth 10
        $uri  = "https://graph.microsoft.com/v1.0/users/$FromAddress/sendMail"

        Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json" -ErrorAction Stop

        Write-Host "Email accepted by Microsoft Graph for delivery. From: $FromAddress | To: $($ToRecipients -join ', ')" -ForegroundColor Green
    }
    catch {
        Write-Host "Email send failed: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
    finally {
        Disconnect-MgGraph | Out-Null
    }
}
