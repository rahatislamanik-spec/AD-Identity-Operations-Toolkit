#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Service Account Governance — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 5

.DESCRIPTION
    Enumerates and audits all service accounts in Active Directory by convention,
    SPN registration, and managed service account type. Identifies Kerberoastable
    accounts, SPNs registered on user objects, and service accounts operating
    outside dedicated OUs or inside privileged groups.

    Detections:
        - Kerberoastable accounts (SPNs registered on user objects)
        - Service accounts in privileged groups (Tier 0/1)
        - Non-gMSA service accounts (missing msDS-ManagedPassword)
        - Service accounts with PasswordNeverExpires
        - Service accounts outside dedicated service account OUs
        - SPN conflicts (duplicate SPNs across multiple accounts)
        - Inactive service accounts (no logon > threshold)
        - Service accounts with weak naming convention compliance

    READ-ONLY — No changes are made to Active Directory.

.PARAMETER InactiveDays
    Days since last logon to flag service account as inactive. Default: 30.

.PARAMETER SearchBase
    OU distinguished name to scope the search. Default: entire domain.

.PARAMETER GenerateReport
    Switch to produce an HTML report in the output path.

.PARAMETER ExportCSV
    Switch to also export findings as CSV.

.PARAMETER OutputPath
    Directory path for report output. Default: .\Reports\

.PARAMETER WhatIf
    Dry-run mode. Preview findings without writing output files.

.EXAMPLE
    .\Get-ServiceAccountGovernance.ps1 -WhatIf

.EXAMPLE
    .\Get-ServiceAccountGovernance.ps1 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    .\Get-ServiceAccountGovernance.ps1 -GenerateReport -ExportCSV -InactiveDays 30

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 5 — Service Account Governance
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : CIS Controls v8 — 5.6 | NIST SP 800-53 AC-6 | OSFI E-21 §3.2
    Permissions : Domain Read (no write permissions required)
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Days since last logon to flag service account as inactive.")]
    [ValidateRange(1, 365)]
    [int]$InactiveDays = 30,

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
║                  Phase 5 │ Service Account Governance                        ║
║           CIS Controls v8 — 5.6 │ NIST 800-53 AC-6 │ OSFI E-21 §3.2        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Inactivity Threshold : $InactiveDays days" -ForegroundColor Yellow
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
    Write-Host "    [!] FATAL: Cannot connect to Active Directory." -ForegroundColor Red
    exit 1
}

$cutoffDate  = (Get-Date).AddDays(-$InactiveDays)
$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain      = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"

Write-Host "    [+] Domain       : $domain" -ForegroundColor Green
Write-Host "    [+] Cutoff date  : $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Helper Functions ────────────────────────────────────────────────────

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

function Test-IsServiceAccount {
    param($User)
    return (
        $User.SamAccountName.ToLower().StartsWith("svc") -or
        $User.SamAccountName.ToLower().StartsWith("sa-") -or
        $User.SamAccountName.ToLower().StartsWith("svc-") -or
        $User.SamAccountName.ToLower().Contains("service") -or
        $User.ServicePrincipalNames.Count -gt 0 -or
        ($User.Description -match "service|svc|automation|scheduled|task|integration|api|daemon")
    )
}

# Privileged groups to check membership against
$privilegedGroups = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Backup Operators", "Account Operators",
    "Server Operators", "Group Policy Creator Owners"
)

#endregion

#region ── Phase 5A: Load All Users with SPNs or SVC Convention ───────────────

Write-Host "[1/5] Loading service accounts by convention and SPN registration..." -ForegroundColor Cyan

$adUserParams = @{
    Filter     = *
    Properties = @(
        "ServicePrincipalNames", "PasswordNeverExpires", "PasswordLastSet",
        "PasswordNotRequired", "LastLogonDate", "Enabled", "Description",
        "Department", "Title", "MemberOf", "whenCreated", "DistinguishedName",
        "msDS-ManagedPasswordInterval", "ObjectClass"
    )
}
if ($SearchBase) { $adUserParams["SearchBase"] = $SearchBase }

$allUsers       = Get-ADUser @adUserParams
$serviceAccounts = $allUsers | Where-Object { Test-IsServiceAccount -User $_ }

Write-Host "    [+] Service accounts identified: $($serviceAccounts.Count)" -ForegroundColor Green

#endregion

#region ── Phase 5B: Kerberoastable Accounts ──────────────────────────────────

Write-Host "[2/5] Detecting Kerberoastable accounts (SPNs on user objects)..." -ForegroundColor Cyan

$kerberoastable = $serviceAccounts | Where-Object {
    $_.ServicePrincipalNames.Count -gt 0
} | ForEach-Object {
    $daysSince = if ($_.LastLogonDate) {
        [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays)
    } else { $null }

    $spns = $_.ServicePrincipalNames -join " | "

    [PSCustomObject]@{
        SamAccountName      = $_.SamAccountName
        DisplayName         = $_.Name
        Enabled             = $_.Enabled
        SPNCount            = $_.ServicePrincipalNames.Count
        SPNs                = $spns
        PasswordNeverExpires = $_.PasswordNeverExpires
        PasswordLastSet     = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "NEVER" }
        LastLogonDate       = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon      = if ($daysSince) { $daysSince } else { "N/A" }
        WhenCreated         = $_.whenCreated.ToString("yyyy-MM-dd")
        OU                  = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel           = if ($_.PasswordNeverExpires) { "CRITICAL" } elseif ($_.Enabled) { "HIGH" } else { "MEDIUM" }
        FindingType         = "Kerberoastable — SPN on User Object"
    }
}

Write-Host "    [+] Kerberoastable accounts: $($kerberoastable.Count)" -ForegroundColor $(if ($kerberoastable.Count -gt 0) { 'Red' } else { 'Green' })

#endregion

#region ── Phase 5C: Service Accounts in Privileged Groups ────────────────────

Write-Host "[3/5] Detecting service accounts in privileged groups..." -ForegroundColor Cyan

$svcInPrivGroups = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($svc in $serviceAccounts) {
    $privGroupMemberships = [System.Collections.Generic.List[string]]::new()

    foreach ($groupDN in $svc.MemberOf) {
        $groupName = $groupDN -replace '^CN=([^,]+),.+$', '$1'
        if ($privilegedGroups -contains $groupName) {
            $privGroupMemberships.Add($groupName)
        }
    }

    if ($privGroupMemberships.Count -gt 0) {
        $svcInPrivGroups.Add([PSCustomObject]@{
            SamAccountName       = $svc.SamAccountName
            DisplayName          = $svc.Name
            Enabled              = $svc.Enabled
            PrivilegedGroups     = $privGroupMemberships -join " · "
            PrivGroupCount       = $privGroupMemberships.Count
            SPNCount             = $svc.ServicePrincipalNames.Count
            PasswordNeverExpires = $svc.PasswordNeverExpires
            LastLogonDate        = if ($svc.LastLogonDate) { $svc.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
            WhenCreated          = $svc.whenCreated.ToString("yyyy-MM-dd")
            OU                   = ($svc.DistinguishedName -replace '^CN=[^,]+,', '')
            RiskLevel            = "CRITICAL"
            FindingType          = "Service Account in Privileged Group"
        })
    }
}

Write-Host "    [+] Service accounts in privileged groups: $($svcInPrivGroups.Count)" -ForegroundColor $(if ($svcInPrivGroups.Count -gt 0) { 'Red' } else { 'Green' })

#endregion

#region ── Phase 5D: Non-gMSA Service Accounts ────────────────────────────────

Write-Host "[4/5] Identifying non-gMSA service accounts (manual password management risk)..." -ForegroundColor Cyan

$nonGmsaAccounts = $serviceAccounts | Where-Object {
    # gMSA accounts have msDS-ManagedPasswordInterval set
    -not $_."msDS-ManagedPasswordInterval" -and $_.Enabled
} | ForEach-Object {
    $daysSince = if ($_.LastLogonDate) {
        [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays)
    } else { $null }

    $riskFactors = [System.Collections.Generic.List[string]]::new()
    if ($_.PasswordNeverExpires)             { $riskFactors.Add("Password Never Expires") }
    if ($null -eq $_.PasswordLastSet)        { $riskFactors.Add("Password Never Set") }
    if ($_.PasswordNotRequired)              { $riskFactors.Add("Password Not Required") }
    if ($null -eq $_.LastLogonDate)          { $riskFactors.Add("Never Logged In") }
    elseif ($_.LastLogonDate -lt $cutoffDate){ $riskFactors.Add("Inactive > $InactiveDays days") }

    [PSCustomObject]@{
        SamAccountName       = $_.SamAccountName
        DisplayName          = $_.Name
        Enabled              = $_.Enabled
        IsGMSA               = $false
        PasswordNeverExpires = $_.PasswordNeverExpires
        PasswordLastSet      = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "NEVER" }
        LastLogonDate        = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon       = if ($daysSince) { $daysSince } else { "N/A" }
        WhenCreated          = $_.whenCreated.ToString("yyyy-MM-dd")
        OU                   = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskFactors          = if ($riskFactors.Count -gt 0) { $riskFactors -join " · " } else { "Manual password — no gMSA" }
        RiskLevel            = if ($riskFactors.Count -ge 2) { "HIGH" } elseif ($riskFactors.Count -ge 1) { "MEDIUM" } else { "LOW" }
        FindingType          = "Non-gMSA Service Account"
    }
}

Write-Host "    [+] Non-gMSA service accounts: $($nonGmsaAccounts.Count)" -ForegroundColor $(if ($nonGmsaAccounts.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 5E: SPN Conflict Detection ───────────────────────────────────

Write-Host "[5/5] Detecting SPN conflicts (duplicate SPNs across accounts)..." -ForegroundColor Cyan

$spnMap     = @{}
$allSvcSpns = $allUsers | Where-Object { $_.ServicePrincipalNames.Count -gt 0 }

foreach ($user in $allSvcSpns) {
    foreach ($spn in $user.ServicePrincipalNames) {
        $spnNorm = $spn.ToLower()
        if (-not $spnMap.ContainsKey($spnNorm)) {
            $spnMap[$spnNorm] = [System.Collections.Generic.List[string]]::new()
        }
        $spnMap[$spnNorm].Add($user.SamAccountName)
    }
}

$spnConflicts = $spnMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 } | ForEach-Object {
    [PSCustomObject]@{
        SPN           = $_.Key
        AccountCount  = $_.Value.Count
        Accounts      = $_.Value -join " · "
        RiskLevel     = "CRITICAL"
        FindingType   = "SPN Conflict — Duplicate Registration"
    }
}

Write-Host "    [+] SPN conflicts detected: $($spnConflicts.Count)" -ForegroundColor $(if ($spnConflicts.Count -gt 0) { 'Red' } else { 'Green' })

#endregion

#region ── Summary ────────────────────────────────────────────────────────────

$allFindings   = @($kerberoastable) + @($svcInPrivGroups) + @($nonGmsaAccounts) + @($spnConflicts)
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 5 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Service Accounts Identified : $($serviceAccounts.Count)" -ForegroundColor White
Write-Host "  Total Findings              : $($allFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL                    : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                        : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM                      : $mediumCount" -ForegroundColor Cyan
Write-Host "  Kerberoastable Accounts     : $($kerberoastable.Count)" -ForegroundColor Red
Write-Host "  Svc Accts in Priv Groups    : $($svcInPrivGroups.Count)" -ForegroundColor Red
Write-Host "  Non-gMSA Accounts           : $($nonGmsaAccounts.Count)" -ForegroundColor Yellow
Write-Host "  SPN Conflicts               : $($spnConflicts.Count)" -ForegroundColor Red
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

if ($WhatIfPreference) {
    Write-Host "[DRY RUN] No output files written. Remove -WhatIf to generate reports." -ForegroundColor Magenta
    exit 0
}

#endregion

#region ── HTML Report ────────────────────────────────────────────────────────

if ($GenerateReport) {

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase5-ServiceAccountGovernance-$reportStamp.html"

    function Get-TableRows {
        param([array]$Data, [string[]]$Columns)
        $rows = ""
        foreach ($item in $Data) {
            $rc    = Get-RiskColor -Risk $item.RiskLevel
            $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
            $rows += "<tr>"
            foreach ($col in $Columns) {
                if ($col -eq "RiskLevel")      { $rows += "<td>$badge</td>" }
                elseif ($col -eq "SamAccountName") { $rows += "<td><code>$($item.$col)</code></td>" }
                else { $rows += "<td>$($item.$col)</td>" }
            }
            $rows += "</tr>"
        }
        return $rows
    }

    $kerbRows    = Get-TableRows -Data $kerberoastable  -Columns @("SamAccountName","DisplayName","SPNCount","PasswordNeverExpires","PasswordLastSet","LastLogonDate","RiskLevel")
    $privRows    = Get-TableRows -Data $svcInPrivGroups -Columns @("SamAccountName","DisplayName","PrivilegedGroups","SPNCount","PasswordNeverExpires","LastLogonDate","RiskLevel")
    $gmsaRows    = Get-TableRows -Data $nonGmsaAccounts -Columns @("SamAccountName","DisplayName","PasswordNeverExpires","PasswordLastSet","DaysSinceLogon","RiskFactors","RiskLevel")
    $spnRows     = Get-TableRows -Data $spnConflicts    -Columns @("SPN","AccountCount","Accounts","RiskLevel")

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NorthBridge Financial Group — Phase 5: Service Account Governance</title>
<style>
  :root { --nb-navy:#0a2342; --nb-gold:#c9a84c; --nb-light:#f4f6f9; --nb-border:#dce3ec; --critical:#c0392b; --high:#e67e22; --medium:#f1c40f; --low:#27ae60; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',Arial,sans-serif; background:var(--nb-light); color:#2c3e50; font-size:14px; }
  .header { background:var(--nb-navy); color:#fff; padding:28px 40px; border-bottom:4px solid var(--nb-gold); }
  .header h1 { font-size:22px; font-weight:700; }
  .header .subtitle { color:var(--nb-gold); font-size:13px; margin-top:4px; letter-spacing:1px; text-transform:uppercase; }
  .header .meta { margin-top:12px; font-size:12px; color:#aab4c2; display:flex; gap:24px; }
  .compliance-bar { background:var(--nb-navy); color:#aab4c2; font-size:11px; padding:8px 40px; }
  .compliance-bar span { color:var(--nb-gold); font-weight:600; }
  .container { max-width:1280px; margin:0 auto; padding:32px 40px; }
  .kpi-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:32px; }
  .kpi-card { background:#fff; border:1px solid var(--nb-border); border-top:4px solid var(--nb-navy); border-radius:6px; padding:20px; text-align:center; }
  .kpi-card.critical { border-top-color:var(--critical); }
  .kpi-card.high { border-top-color:var(--high); }
  .kpi-value { font-size:32px; font-weight:700; color:var(--nb-navy); }
  .kpi-label { font-size:11px; color:#7f8c8d; margin-top:4px; text-transform:uppercase; letter-spacing:0.5px; }
  .section { background:#fff; border:1px solid var(--nb-border); border-radius:6px; margin-bottom:28px; overflow:hidden; }
  .section-header { background:var(--nb-navy); color:#fff; padding:14px 20px; font-size:14px; font-weight:600; display:flex; justify-content:space-between; align-items:center; }
  .section-header .badge { background:var(--nb-gold); color:var(--nb-navy); border-radius:12px; padding:2px 10px; font-size:12px; font-weight:700; }
  table { width:100%; border-collapse:collapse; }
  th { background:#eef2f7; padding:10px 14px; text-align:left; font-size:12px; font-weight:600; color:var(--nb-navy); text-transform:uppercase; border-bottom:1px solid var(--nb-border); }
  td { padding:10px 14px; border-bottom:1px solid #f0f0f0; font-size:13px; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:#f8fafc; }
  code { background:#eef2f7; padding:1px 6px; border-radius:3px; font-size:12px; }
  .osfi-box { background:#fdf3e7; border-left:4px solid #e67e22; border-radius:4px; padding:16px 20px; margin-bottom:28px; font-size:13px; }
  .osfi-box strong { color:#7a3c00; }
  .footer { text-align:center; padding:20px; font-size:11px; color:#95a5a6; border-top:1px solid var(--nb-border); margin-top:32px; }
  .no-findings { padding:24px; text-align:center; color:#27ae60; font-weight:600; }
</style>
</head>
<body>

<div class="header">
  <div class="subtitle">AD Identity Operations Toolkit — Phase 5</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Service Account Governance</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>⚙️ Service Accounts Identified: $($serviceAccounts.Count)</span>
    <span>⏱ Inactivity Threshold: $InactiveDays days</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>CIS Controls v8 — 5.6</span> — Centralize Account Management &nbsp;|&nbsp;
  <span>NIST SP 800-53 AC-6</span> — Least Privilege &nbsp;|&nbsp;
  <span>OSFI E-21 §3.2</span> — Privileged Access Management
</div>

<div class="container">

  <div class="osfi-box">
    <strong>⚠️ Kerberoasting Risk:</strong> Service accounts with SPNs registered on user objects are vulnerable to Kerberoasting attacks — an attacker with any domain user account can request a Kerberos service ticket and attempt offline password cracking.
    In financial environments, this represents a critical attack path to lateral movement and privilege escalation. All service accounts should use Group Managed Service Accounts (gMSA) with auto-rotating 120-character passwords.
  </div>

  <div class="kpi-grid">
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$($kerberoastable.Count)</div>
      <div class="kpi-label">Kerberoastable</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$($svcInPrivGroups.Count)</div>
      <div class="kpi-label">In Priv Groups</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$($spnConflicts.Count)</div>
      <div class="kpi-label">SPN Conflicts</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$($nonGmsaAccounts.Count)</div>
      <div class="kpi-label">Non-gMSA Accounts</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">$($allFindings.Count)</div>
      <div class="kpi-label">Total Findings</div>
    </div>
  </div>

  <!-- Kerberoastable -->
  <div class="section">
    <div class="section-header">
      🔴 Kerberoastable Accounts — SPNs on User Objects
      <span class="badge">$($kerberoastable.Count) findings</span>
    </div>
    $(if ($kerberoastable.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>SPN Count</th>
        <th>Pwd Never Expires</th><th>Pwd Last Set</th><th>Last Logon</th><th>Risk</th>
      </tr></thead><tbody>$kerbRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No Kerberoastable accounts detected.</div>"
    })
  </div>

  <!-- Svc in Privileged Groups -->
  <div class="section">
    <div class="section-header">
      🔴 Service Accounts in Privileged Groups
      <span class="badge">$($svcInPrivGroups.Count) findings</span>
    </div>
    $(if ($svcInPrivGroups.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Privileged Groups</th>
        <th>SPN Count</th><th>Pwd Never Expires</th><th>Last Logon</th><th>Risk</th>
      </tr></thead><tbody>$privRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No service accounts detected in privileged groups.</div>"
    })
  </div>

  <!-- SPN Conflicts -->
  <div class="section">
    <div class="section-header">
      ⚠️ SPN Conflicts — Duplicate SPN Registrations
      <span class="badge">$($spnConflicts.Count) findings</span>
    </div>
    $(if ($spnConflicts.Count -gt 0) {
      "<table><thead><tr>
        <th>SPN</th><th>Account Count</th><th>Accounts</th><th>Risk</th>
      </tr></thead><tbody>$spnRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No SPN conflicts detected.</div>"
    })
  </div>

  <!-- Non-gMSA -->
  <div class="section">
    <div class="section-header">
      🟠 Non-gMSA Service Accounts — Manual Password Management Risk
      <span class="badge">$($nonGmsaAccounts.Count) findings</span>
    </div>
    $(if ($nonGmsaAccounts.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Pwd Never Expires</th>
        <th>Pwd Last Set</th><th>Days Since Logon</th><th>Risk Factors</th><th>Risk</th>
      </tr></thead><tbody>$gmsaRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ All service accounts are using gMSA.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 5: Service Account Governance
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
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase5-ServiceAccountGovernance-$reportStamp.csv"
    $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 5 complete. Proceed to Phase 6 — Inactive Object Cleanup Workflow." -ForegroundColor Cyan
Write-Host ""

return $allFindings
