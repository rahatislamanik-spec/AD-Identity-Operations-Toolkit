#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Stale Account Detection — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 1

.DESCRIPTION
    Identifies stale user and computer accounts in Active Directory that exceed
    inactivity thresholds aligned with OSFI E-21 and CIS Controls v8 requirements
    for financial institutions.

    Detections:
        - User accounts inactive beyond threshold (default: 30 days)
        - Computer accounts with stale password (default: 30 days)
        - Accounts that have never logged in
        - Disabled accounts still holding active group memberships
        - Accounts with no lastLogonDate recorded

    All findings are exported to a structured HTML report and optional CSV.
    No changes are made to Active Directory — this is a READ-ONLY audit script.

.PARAMETER DaysInactive
    Number of days since last logon to flag as stale. Default: 30.
    OSFI E-21 recommends 30-day threshold for financial institutions.

.PARAMETER SearchBase
    OU distinguished name to scope the search. Default: entire domain.

.PARAMETER GenerateReport
    Switch to produce an HTML report in the output path.

.PARAMETER ExportCSV
    Switch to also export findings as CSV alongside the HTML report.

.PARAMETER OutputPath
    Directory path for report output. Default: .\Reports\

.PARAMETER WhatIf
    Dry-run mode. Displays what would be flagged without writing any output files.

.EXAMPLE
    # Dry-run — preview findings only
    .\Get-StaleAccounts.ps1 -DaysInactive 30 -WhatIf

.EXAMPLE
    # Full audit with HTML report
    .\Get-StaleAccounts.ps1 -DaysInactive 30 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    # Scoped to specific OU, HTML + CSV export
    .\Get-StaleAccounts.ps1 -DaysInactive 45 -SearchBase "OU=Employees,DC=northbridge,DC=local" -GenerateReport -ExportCSV

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 1 — Stale Account Detection
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 §3.4 | CIS Controls v8 — Control 6 | NIST SP 800-53 AC-2
    Permissions : Domain Read (no write permissions required)
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Days since last logon to flag as stale. OSFI E-21 recommends 30 days.")]
    [ValidateRange(1, 365)]
    [int]$DaysInactive = 30,

    [Parameter(HelpMessage = "OU distinguished name to scope search. Leave blank for full domain.")]
    [string]$SearchBase = "",

    [Parameter(HelpMessage = "Generate HTML report.")]
    [switch]$GenerateReport,

    [Parameter(HelpMessage = "Also export findings to CSV.")]
    [switch]$ExportCSV,

    [Parameter(HelpMessage = "Output directory for reports.")]
    [string]$OutputPath = ".\Reports\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── Banner ──────────────────────────────────────────────────────────────

$banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║          NorthBridge Financial Group — AD Identity Operations Toolkit        ║
║                     Phase 1 │ Stale Account Detection                        ║
║                  OSFI E-21 │ CIS Controls v8 │ NIST 800-53                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Inactivity Threshold : $DaysInactive days" -ForegroundColor Yellow
Write-Host "  Search Scope         : $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })" -ForegroundColor Yellow
Write-Host "  Execution Mode       : $(if ($WhatIfPreference) { 'DRY RUN — No files will be written' } else { 'LIVE AUDIT' })" -ForegroundColor $(if ($WhatIfPreference) { 'Magenta' } else { 'Green' })
Write-Host ""

#endregion

#region ── Pre-flight Checks ───────────────────────────────────────────────────

Write-Host "[*] Pre-flight checks..." -ForegroundColor Cyan

try {
    $null = Get-ADDomain -ErrorAction Stop
    Write-Host "    [+] Active Directory connection verified" -ForegroundColor Green
}
catch {
    Write-Host "    [!] FATAL: Cannot connect to Active Directory. Ensure RSAT is installed and you are domain-joined." -ForegroundColor Red
    Write-Host "        Error: $_" -ForegroundColor Red
    exit 1
}

$cutoffDate = (Get-Date).AddDays(-$DaysInactive)
$runDate    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain     = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"

Write-Host "    [+] Cutoff date      : $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
Write-Host "    [+] Domain           : $domain" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Helper Functions ────────────────────────────────────────────────────

function Get-DaysSince {
    param([datetime]$Date)
    return [math]::Round(((Get-Date) - $Date).TotalDays)
}

function Get-RiskLevel {
    param([int]$Days, [int]$Threshold)
    $ratio = $Days / $Threshold
    if ($ratio -ge 6)     { return "CRITICAL" }
    elseif ($ratio -ge 3) { return "HIGH" }
    elseif ($ratio -ge 1) { return "MEDIUM" }
    else                  { return "LOW" }
}

function Get-RiskColor {
    param([string]$Risk)
    switch ($Risk) {
        "CRITICAL" { return "#c0392b" }
        "HIGH"     { return "#e67e22" }
        "MEDIUM"   { return "#f1c40f" }
        "LOW"      { return "#27ae60" }
        default    { return "#95a5a6" }
    }
}

#endregion

#region ── Phase 1A: Stale User Accounts ──────────────────────────────────────

Write-Host "[1/4] Scanning stale USER accounts (inactive > $DaysInactive days)..." -ForegroundColor Cyan

$adUserParams = @{
    Filter     = { Enabled -eq $true }
    Properties = @(
        "LastLogonDate", "PasswordNeverExpires", "PasswordLastSet",
        "Department", "Manager", "Description", "MemberOf",
        "whenCreated", "DistinguishedName", "EmailAddress", "Title"
    )
}
if ($SearchBase) { $adUserParams["SearchBase"] = $SearchBase }

$allUsers = Get-ADUser @adUserParams

$staleUsers = $allUsers | Where-Object {
    ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate)
} | ForEach-Object {
    $daysSince = if ($_.LastLogonDate) { Get-DaysSince -Date $_.LastLogonDate } else { $null }
    $risk      = if ($daysSince) { Get-RiskLevel -Days $daysSince -Threshold $DaysInactive } else { "CRITICAL" }

    [PSCustomObject]@{
        ObjectType        = "User"
        SamAccountName    = $_.SamAccountName
        DisplayName       = $_.Name
        Department        = $_.Department
        Title             = $_.Title
        EmailAddress      = $_.EmailAddress
        LastLogonDate     = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon    = if ($daysSince) { $daysSince } else { "N/A" }
        PasswordLastSet   = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "N/A" }
        PwdNeverExpires   = $_.PasswordNeverExpires
        GroupMemberships  = ($_.MemberOf | Measure-Object).Count
        WhenCreated       = $_.whenCreated.ToString("yyyy-MM-dd")
        OU                = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel         = $risk
        FindingType       = if ($null -eq $_.LastLogonDate) { "Never Logged In" } else { "Inactive User Account" }
    }
}

Write-Host "    [+] Stale user accounts found: $($staleUsers.Count)" -ForegroundColor $(if ($staleUsers.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 1B: Stale Computer Accounts ──────────────────────────────────

Write-Host "[2/4] Scanning stale COMPUTER accounts (inactive > $DaysInactive days)..." -ForegroundColor Cyan

$adComputerParams = @{
    Filter     = { Enabled -eq $true }
    Properties = @(
        "LastLogonDate", "PasswordLastSet", "OperatingSystem",
        "OperatingSystemVersion", "whenCreated", "DistinguishedName", "DNSHostName"
    )
}
if ($SearchBase) { $adComputerParams["SearchBase"] = $SearchBase }

$allComputers = Get-ADComputer @adComputerParams

$staleComputers = $allComputers | Where-Object {
    ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate)
} | ForEach-Object {
    $daysSince = if ($_.LastLogonDate) { Get-DaysSince -Date $_.LastLogonDate } else { $null }
    $risk      = if ($daysSince) { Get-RiskLevel -Days $daysSince -Threshold $DaysInactive } else { "CRITICAL" }

    [PSCustomObject]@{
        ObjectType       = "Computer"
        SamAccountName   = $_.SamAccountName
        DisplayName      = $_.Name
        DNSHostName      = $_.DNSHostName
        OperatingSystem  = $_.OperatingSystem
        OSVersion        = $_.OperatingSystemVersion
        LastLogonDate    = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon   = if ($daysSince) { $daysSince } else { "N/A" }
        PasswordLastSet  = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "N/A" }
        WhenCreated      = $_.whenCreated.ToString("yyyy-MM-dd")
        OU               = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel        = $risk
        FindingType      = if ($null -eq $_.LastLogonDate) { "Never Logged In" } else { "Inactive Computer Account" }
    }
}

Write-Host "    [+] Stale computer accounts found: $($staleComputers.Count)" -ForegroundColor $(if ($staleComputers.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 1C: Disabled Accounts with Active Group Memberships ──────────

Write-Host "[3/4] Scanning DISABLED accounts with active group memberships..." -ForegroundColor Cyan

$adDisabledParams = @{
    Filter     = { Enabled -eq $false }
    Properties = @("MemberOf", "LastLogonDate", "whenCreated", "Department", "DistinguishedName")
}
if ($SearchBase) { $adDisabledParams["SearchBase"] = $SearchBase }

$disabledWithGroups = Get-ADUser @adDisabledParams | Where-Object {
    $_.MemberOf.Count -gt 0
} | ForEach-Object {
    [PSCustomObject]@{
        ObjectType       = "User (Disabled)"
        SamAccountName   = $_.SamAccountName
        DisplayName      = $_.Name
        Department       = $_.Department
        LastLogonDate    = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        GroupMemberships = $_.MemberOf.Count
        WhenCreated      = $_.whenCreated.ToString("yyyy-MM-dd")
        OU               = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel        = "HIGH"
        FindingType      = "Disabled Account — Active Group Memberships"
    }
}

Write-Host "    [+] Disabled accounts with group memberships: $($disabledWithGroups.Count)" -ForegroundColor $(if ($disabledWithGroups.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Summary Totals ──────────────────────────────────────────────────────

Write-Host "[4/4] Compiling findings..." -ForegroundColor Cyan

$allFindings  = @($staleUsers) + @($staleComputers) + @($disabledWithGroups)
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$lowCount      = ($allFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 1 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Total Findings      : $($allFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL            : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM              : $mediumCount" -ForegroundColor Cyan
Write-Host "  LOW                 : $lowCount" -ForegroundColor Green
Write-Host "  Stale Users         : $($staleUsers.Count)" -ForegroundColor White
Write-Host "  Stale Computers     : $($staleComputers.Count)" -ForegroundColor White
Write-Host "  Disabled w/ Groups  : $($disabledWithGroups.Count)" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "[DRY RUN] No output files written. Remove -WhatIf to generate reports." -ForegroundColor Magenta
    exit 0
}

#endregion

#region ── HTML Report Generation ─────────────────────────────────────────────

if ($GenerateReport) {

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase1-StaleAccounts-$reportStamp.html"

    function New-TableRows {
        param([array]$Data)
        $rows = ""
        foreach ($item in $Data) {
            $riskColor = Get-RiskColor -Risk $item.RiskLevel
            $riskBadge = "<span style='background:$riskColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
            $rows += "<tr>"
            $rows += "<td>$($item.FindingType)</td>"
            $rows += "<td><code>$($item.SamAccountName)</code></td>"
            $rows += "<td>$($item.DisplayName)</td>"
            $rows += "<td>$($item.LastLogonDate)</td>"
            $rows += "<td>$($item.DaysSinceLogon)</td>"
            if ($item.PSObject.Properties["Department"]) {
                $rows += "<td>$($item.Department)</td>"
            } else {
                $rows += "<td>$($item.OperatingSystem)</td>"
            }
            $rows += "<td>$riskBadge</td>"
            $rows += "</tr>"
        }
        return $rows
    }

    $userRows     = New-TableRows -Data $staleUsers
    $computerRows = New-TableRows -Data $staleComputers
    $disabledRows = New-TableRows -Data $disabledWithGroups

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NorthBridge Financial Group — Phase 1: Stale Account Detection</title>
<style>
  :root {
    --nb-navy:   #0a2342;
    --nb-gold:   #c9a84c;
    --nb-light:  #f4f6f9;
    --nb-border: #dce3ec;
    --critical:  #c0392b;
    --high:      #e67e22;
    --medium:    #f1c40f;
    --low:       #27ae60;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: var(--nb-light); color: #2c3e50; font-size: 14px; }

  .header {
    background: var(--nb-navy);
    color: #fff;
    padding: 28px 40px;
    border-bottom: 4px solid var(--nb-gold);
  }
  .header h1 { font-size: 22px; font-weight: 700; letter-spacing: 0.5px; }
  .header .subtitle { color: var(--nb-gold); font-size: 13px; margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }
  .header .meta { margin-top: 12px; font-size: 12px; color: #aab4c2; display: flex; gap: 24px; }

  .container { max-width: 1280px; margin: 0 auto; padding: 32px 40px; }

  .compliance-bar {
    background: var(--nb-navy);
    color: #aab4c2;
    font-size: 11px;
    padding: 8px 40px;
    letter-spacing: 0.5px;
  }
  .compliance-bar span { color: var(--nb-gold); font-weight: 600; }

  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
  .kpi-card {
    background: #fff;
    border: 1px solid var(--nb-border);
    border-top: 4px solid var(--nb-navy);
    border-radius: 6px;
    padding: 20px;
    text-align: center;
  }
  .kpi-card.critical { border-top-color: var(--critical); }
  .kpi-card.high     { border-top-color: var(--high); }
  .kpi-card.medium   { border-top-color: var(--medium); }
  .kpi-card.low      { border-top-color: var(--low); }
  .kpi-value { font-size: 36px; font-weight: 700; color: var(--nb-navy); }
  .kpi-label { font-size: 12px; color: #7f8c8d; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }

  .section { background: #fff; border: 1px solid var(--nb-border); border-radius: 6px; margin-bottom: 28px; overflow: hidden; }
  .section-header {
    background: var(--nb-navy);
    color: #fff;
    padding: 14px 20px;
    font-size: 14px;
    font-weight: 600;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .section-header .badge {
    background: var(--nb-gold);
    color: var(--nb-navy);
    border-radius: 12px;
    padding: 2px 10px;
    font-size: 12px;
    font-weight: 700;
  }
  table { width: 100%; border-collapse: collapse; }
  th {
    background: #eef2f7;
    padding: 10px 14px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--nb-navy);
    text-transform: uppercase;
    letter-spacing: 0.4px;
    border-bottom: 1px solid var(--nb-border);
  }
  td { padding: 10px 14px; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  code { background: #eef2f7; padding: 1px 6px; border-radius: 3px; font-size: 12px; color: #2c3e50; }

  .osfi-box {
    background: #eaf2fb;
    border-left: 4px solid var(--nb-navy);
    border-radius: 4px;
    padding: 16px 20px;
    margin-bottom: 28px;
    font-size: 13px;
    color: #2c3e50;
  }
  .osfi-box strong { color: var(--nb-navy); }

  .footer {
    text-align: center;
    padding: 20px;
    font-size: 11px;
    color: #95a5a6;
    border-top: 1px solid var(--nb-border);
    margin-top: 32px;
  }
  .no-findings { padding: 24px; text-align: center; color: #27ae60; font-weight: 600; }
</style>
</head>
<body>

<div class="header">
  <div class="subtitle">AD Identity Operations Toolkit — Phase 1</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Stale Account Detection Report</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>⏱ Inactivity Threshold: $DaysInactive days</span>
    <span>🔍 Scope: $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>OSFI E-21 §3.4</span> — Account Lifecycle Management &nbsp;|&nbsp;
  <span>CIS Controls v8 — Control 6</span> — Access Account Management &nbsp;|&nbsp;
  <span>NIST SP 800-53 AC-2</span> — Account Management
</div>

<div class="container">

  <div class="osfi-box">
    <strong>⚠️ OSFI E-21 Guidance:</strong> Federally regulated financial institutions are required to review and disable accounts that have not been used within the defined inactivity period.
    NorthBridge Financial Group policy sets this threshold at <strong>$DaysInactive days</strong>, stricter than the 90-day enterprise default, in alignment with OSFI E-21 §3.4 account lifecycle controls.
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">$($allFindings.Count)</div>
      <div class="kpi-label">Total Findings</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$criticalCount</div>
      <div class="kpi-label">Critical</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$highCount</div>
      <div class="kpi-label">High</div>
    </div>
    <div class="kpi-card medium">
      <div class="kpi-value" style="color:#e6b800">$mediumCount</div>
      <div class="kpi-label">Medium</div>
    </div>
  </div>

  <!-- Stale Users -->
  <div class="section">
    <div class="section-header">
      👤 Stale User Accounts — Inactive &gt; $DaysInactive Days
      <span class="badge">$($staleUsers.Count) findings</span>
    </div>
    $(if ($staleUsers.Count -gt 0) {
      "<table><thead><tr>
        <th>Finding Type</th><th>SAM Account</th><th>Display Name</th>
        <th>Last Logon</th><th>Days Inactive</th><th>Department</th><th>Risk</th>
      </tr></thead><tbody>$userRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No stale user accounts detected within current scope.</div>"
    })
  </div>

  <!-- Stale Computers -->
  <div class="section">
    <div class="section-header">
      💻 Stale Computer Accounts — Inactive &gt; $DaysInactive Days
      <span class="badge">$($staleComputers.Count) findings</span>
    </div>
    $(if ($staleComputers.Count -gt 0) {
      "<table><thead><tr>
        <th>Finding Type</th><th>SAM Account</th><th>Host Name</th>
        <th>Last Logon</th><th>Days Inactive</th><th>Operating System</th><th>Risk</th>
      </tr></thead><tbody>$computerRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No stale computer accounts detected within current scope.</div>"
    })
  </div>

  <!-- Disabled with Groups -->
  <div class="section">
    <div class="section-header">
      🔒 Disabled Accounts — Active Group Memberships
      <span class="badge">$($disabledWithGroups.Count) findings</span>
    </div>
    $(if ($disabledWithGroups.Count -gt 0) {
      "<table><thead><tr>
        <th>Finding Type</th><th>SAM Account</th><th>Display Name</th>
        <th>Last Logon</th><th>Days Inactive</th><th>Department</th><th>Risk</th>
      </tr></thead><tbody>$disabledRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No disabled accounts with active group memberships detected.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 1: Stale Account Detection
  &nbsp;|&nbsp; Generated: $runDate &nbsp;|&nbsp; READ-ONLY AUDIT — No changes made to Active Directory
  <br><br>
  Built by Md Rahat Islam Anik &nbsp;|&nbsp;
  <a href="https://rahatislamanik-spec.github.io/IT-Portfolio-Rahat-Islam-Anik" style="color:#0a2342;">Portfolio</a> &nbsp;|&nbsp;
  <a href="https://linkedin.com/in/rahatislamanik" style="color:#0a2342;">LinkedIn</a>
</div>

</body>
</html>
"@

    $html | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "[+] HTML report saved: $reportFile" -ForegroundColor Green
}

#endregion

#region ── CSV Export ──────────────────────────────────────────────────────────

if ($ExportCSV) {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase1-StaleAccounts-$reportStamp.csv"
    $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 1 complete. Review findings and proceed to Phase 2 — Privileged Account Audit." -ForegroundColor Cyan
Write-Host ""

# Return findings object for pipeline use
return $allFindings
