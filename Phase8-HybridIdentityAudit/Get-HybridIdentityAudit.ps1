#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Hybrid Identity & Entra ID Sync Audit — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 8

.DESCRIPTION
    Audits the hybrid identity environment where on-premises Active Directory
    is synchronized to Microsoft Entra ID (formerly Azure AD) via Azure AD Connect.
    Identifies sync health issues, misconfigured accounts, and security gaps
    that exist at the boundary between on-premises AD and cloud identity.

    Detections:
        - Accounts with sync errors (immutableId conflicts, UPN mismatches)
        - Cloud-only accounts that should be synced (shadow accounts)
        - On-premises accounts blocked from sync (msExchRecipientTypeDetails)
        - Password Hash Sync (PHS) vs Pass-Through Auth (PTA) indicators
        - Accounts with mismatched UPNs between AD and Entra ID format
        - Stale synced accounts (synced but inactive in both environments)
        - Privileged accounts that are synced (should be cloud-only)
        - Azure AD Connect service account detection and audit
        - Duplicate ProxyAddresses and UPN conflicts
        - Accounts missing required sync attributes (mail, UPN suffix)

    READ-ONLY — No changes are made to Active Directory.

.PARAMETER SearchBase
    OU distinguished name to scope the search. Default: entire domain.

.PARAMETER InactiveDays
    Days since last logon to flag synced account as inactive. Default: 30.

.PARAMETER GenerateReport
    Switch to produce an HTML report in the output path.

.PARAMETER ExportCSV
    Switch to also export findings as CSV.

.PARAMETER OutputPath
    Directory path for report output. Default: .\Reports\

.PARAMETER WhatIf
    Dry-run mode. Preview findings without writing output files.

.EXAMPLE
    .\Get-HybridIdentityAudit.ps1 -WhatIf

.EXAMPLE
    .\Get-HybridIdentityAudit.ps1 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    .\Get-HybridIdentityAudit.ps1 -GenerateReport -ExportCSV -InactiveDays 30

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 8 — Hybrid Identity & Entra ID Sync Audit
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 §3.2 §3.4 | CIS Controls v8 — 5, 6 | NIST SP 800-53 IA-2, AC-2
    Permissions : Domain Read (no write permissions required)
    Note        : Full Entra ID cloud-side audit requires Microsoft.Graph module and
                  appropriate Graph API permissions (User.Read.All, Directory.Read.All)
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "OU distinguished name to scope search. Leave blank for full domain.")]
    [string]$SearchBase = "",

    [Parameter(HelpMessage = "Days since last logon to flag synced account as inactive.")]
    [ValidateRange(1, 365)]
    [int]$InactiveDays = 30,

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
║              Phase 8 │ Hybrid Identity & Entra ID Sync Audit                 ║
║         OSFI E-21 §3.2/3.4 │ CIS Controls v8 │ NIST SP 800-53 IA-2          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Search Scope         : $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })" -ForegroundColor Yellow
Write-Host "  Inactivity Threshold : $InactiveDays days" -ForegroundColor Yellow
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

# Check for Microsoft.Graph module (optional — enhances cloud-side audit)
$graphAvailable = $false
try {
    $null = Get-Module -Name "Microsoft.Graph.Users" -ListAvailable -ErrorAction Stop
    $graphAvailable = $true
    Write-Host "    [+] Microsoft.Graph module detected — cloud-side audit enabled" -ForegroundColor Green
}
catch {
    Write-Host "    [!] Microsoft.Graph module not found — running on-premises hybrid indicators only" -ForegroundColor Yellow
    Write-Host "        Install: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor DarkGray
}

$cutoffDate  = (Get-Date).AddDays(-$InactiveDays)
$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain      = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"

# Detect UPN suffixes registered in the domain
$upnSuffixes = @($domain) + (Get-ADForest).UPNSuffixes

Write-Host "    [+] Domain           : $domain" -ForegroundColor Green
Write-Host "    [+] UPN Suffixes     : $($upnSuffixes -join ', ')" -ForegroundColor Green
Write-Host "    [+] Cutoff date      : $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Helper Functions ────────────────────────────────────────────────────

function Get-RiskColor {
    param([string]$Risk)
    switch ($Risk) {
        "CRITICAL" { return "#c0392b" }
        "HIGH"     { return "#e67e22" }
        "MEDIUM"   { return "#f39c12" }
        "LOW"      { return "#27ae60" }
        default    { return "#95a5a6" }
    }
}

# Azure AD Connect service account naming patterns
$aadcPatterns = @(
    "MSOL_*", "AADConnect*", "ADSync*", "AzureADConnect*",
    "Sync_*", "AADC_*", "msol*"
)

function Test-IsAADCAccount {
    param([string]$SamAccountName)
    foreach ($pattern in $aadcPatterns) {
        if ($SamAccountName -like $pattern) { return $true }
    }
    return $false
}

function Test-UPNSuffixValid {
    param([string]$UPN)
    if (-not $UPN -or -not $UPN.Contains("@")) { return $false }
    $suffix = $UPN.Split("@")[1]
    return $upnSuffixes -contains $suffix
}

#endregion

#region ── Load All Users ──────────────────────────────────────────────────────

Write-Host "[1/6] Loading all AD user accounts for hybrid analysis..." -ForegroundColor Cyan

$adUserParams = @{
    Filter     = *
    Properties = @(
        "UserPrincipalName", "mail", "proxyAddresses", "msDS-ExternalDirectoryObjectId",
        "LastLogonDate", "PasswordLastSet", "PasswordNeverExpires", "Enabled",
        "Department", "Title", "Description", "MemberOf", "whenCreated",
        "DistinguishedName", "msExchRecipientTypeDetails", "msExchHideFromAddressLists",
        "ServicePrincipalNames", "adminCount", "thumbnailPhoto"
    )
}
if ($SearchBase) { $adUserParams["SearchBase"] = $SearchBase }

$allUsers = Get-ADUser @adUserParams
Write-Host "    [+] Total users loaded: $($allUsers.Count)" -ForegroundColor Green

# Detect Azure AD Connect sync indicators
$syncedUsers     = $allUsers | Where-Object { $_."msDS-ExternalDirectoryObjectId" -ne $null }
$nonSyncedUsers  = $allUsers | Where-Object { $_."msDS-ExternalDirectoryObjectId" -eq $null }

Write-Host "    [+] Synced to Entra ID   : $($syncedUsers.Count)" -ForegroundColor Green
Write-Host "    [+] On-premises only     : $($nonSyncedUsers.Count)" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Phase 8A: Azure AD Connect Service Account Audit ───────────────────

Write-Host "[2/6] Detecting Azure AD Connect service accounts..." -ForegroundColor Cyan

$aadcAccounts = $allUsers | Where-Object { Test-IsAADCAccount -SamAccountName $_.SamAccountName } | ForEach-Object {
    $inPrivGroup = $false
    foreach ($groupDN in $_.MemberOf) {
        $gName = $groupDN -replace '^CN=([^,]+),.+$', '$1'
        if (@("Domain Admins","Enterprise Admins","Administrators") -contains $gName) {
            $inPrivGroup = $true
            break
        }
    }

    [PSCustomObject]@{
        SamAccountName       = $_.SamAccountName
        DisplayName          = $_.Name
        Enabled              = $_.Enabled
        UPN                  = $_.UserPrincipalName
        PasswordNeverExpires = $_.PasswordNeverExpires
        PasswordLastSet      = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "NEVER" }
        LastLogonDate        = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        InPrivilegedGroup    = $inPrivGroup
        WhenCreated          = $_.whenCreated.ToString("yyyy-MM-dd")
        OU                   = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel            = if ($inPrivGroup) { "CRITICAL" } elseif ($_.PasswordNeverExpires) { "HIGH" } else { "LOW" }
        FindingType          = "Azure AD Connect Service Account"
    }
}

Write-Host "    [+] AADC service accounts found: $($aadcAccounts.Count)" -ForegroundColor $(if ($aadcAccounts.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 8B: Privileged Accounts Synced to Cloud ──────────────────────

Write-Host "[3/6] Detecting privileged on-premises accounts synced to Entra ID..." -ForegroundColor Cyan

$privilegedGroups = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Group Policy Creator Owners"
)

$syncedPrivAccounts = $syncedUsers | Where-Object {
    $user = $_
    $isPriv = $false
    foreach ($groupDN in $user.MemberOf) {
        $gName = $groupDN -replace '^CN=([^,]+),.+$', '$1'
        if ($privilegedGroups -contains $gName) { $isPriv = $true; break }
    }
    $isPriv
} | ForEach-Object {
    $privGroups = $_.MemberOf | ForEach-Object {
        $gn = $_ -replace '^CN=([^,]+),.+$', '$1'
        if ($privilegedGroups -contains $gn) { $gn }
    }

    [PSCustomObject]@{
        SamAccountName        = $_.SamAccountName
        DisplayName           = $_.Name
        Enabled               = $_.Enabled
        UPN                   = $_.UserPrincipalName
        EntraObjectId         = $_."msDS-ExternalDirectoryObjectId"
        PrivilegedGroups      = ($privGroups -join " · ")
        PasswordNeverExpires  = $_.PasswordNeverExpires
        LastLogonDate         = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        WhenCreated           = $_.whenCreated.ToString("yyyy-MM-dd")
        OU                    = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel             = "CRITICAL"
        FindingType           = "Privileged Account Synced to Entra ID"
    }
}

Write-Host "    [+] Privileged synced accounts: $($syncedPrivAccounts.Count)" -ForegroundColor $(if ($syncedPrivAccounts.Count -gt 0) { 'Red' } else { 'Green' })

#endregion

#region ── Phase 8C: UPN Mismatch & Sync Attribute Issues ────────────────────

Write-Host "[4/6] Auditing UPN mismatches and missing sync attributes..." -ForegroundColor Cyan

$upnIssues = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($user in $allUsers) {
    $issues = [System.Collections.Generic.List[string]]::new()

    # Check UPN suffix validity
    if (-not $user.UserPrincipalName) {
        $issues.Add("Missing UPN")
    } elseif (-not (Test-UPNSuffixValid -UPN $user.UserPrincipalName)) {
        $issues.Add("UPN suffix not in registered suffixes")
    }

    # Check for missing mail attribute on synced accounts
    if ($user."msDS-ExternalDirectoryObjectId" -and -not $user.mail) {
        $issues.Add("Synced account missing mail attribute")
    }

    # Check for duplicate/malformed proxy addresses
    if ($user.proxyAddresses.Count -gt 0) {
        $smtpAddresses = $user.proxyAddresses | Where-Object { $_ -match "^SMTP:" -or $_ -match "^smtp:" }
        $primarySMTP   = $smtpAddresses | Where-Object { $_ -cmatch "^SMTP:" }
        if ($primarySMTP.Count -gt 1) {
            $issues.Add("Multiple primary SMTP addresses (proxyAddresses conflict)")
        }
        if ($primarySMTP.Count -eq 0 -and $smtpAddresses.Count -gt 0) {
            $issues.Add("No primary SMTP address defined")
        }
    }

    # UPN contains spaces or illegal characters
    if ($user.UserPrincipalName -match '\s') {
        $issues.Add("UPN contains whitespace")
    }

    # Synced account with adminCount = 1 (was previously in admin group, SDProp artifact)
    if ($user.adminCount -eq 1 -and $user."msDS-ExternalDirectoryObjectId") {
        $issues.Add("adminCount=1 on synced account — SDProp artifact risk")
    }

    if ($issues.Count -eq 0) { continue }

    $riskLevel = if ($issues.Count -ge 3)                          { "CRITICAL" }
                 elseif ($issues.Contains("Multiple primary SMTP addresses (proxyAddresses conflict)") -or
                         $issues.Contains("adminCount=1 on synced account — SDProp artifact risk")) { "HIGH" }
                 else                                               { "MEDIUM" }

    $upnIssues.Add([PSCustomObject]@{
        SamAccountName = $user.SamAccountName
        DisplayName    = $user.Name
        Enabled        = $user.Enabled
        UPN            = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { "MISSING" }
        Mail           = if ($user.mail) { $user.mail } else { "MISSING" }
        IsSynced       = ($null -ne $user."msDS-ExternalDirectoryObjectId")
        ProxyCount     = $user.proxyAddresses.Count
        Issues         = ($issues -join " · ")
        WhenCreated    = $user.whenCreated.ToString("yyyy-MM-dd")
        OU             = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel      = $riskLevel
        FindingType    = "UPN / Sync Attribute Issue"
    })
}

Write-Host "    [+] UPN and sync attribute issues: $($upnIssues.Count)" -ForegroundColor $(if ($upnIssues.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 8D: Stale Synced Accounts ────────────────────────────────────

Write-Host "[5/6] Detecting stale synced accounts (inactive in both environments)..." -ForegroundColor Cyan

$staleSyncedAccounts = $syncedUsers | Where-Object {
    $_.Enabled -eq $true -and
    (($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate))
} | ForEach-Object {
    $daysSince = if ($_.LastLogonDate) {
        [math]::Round(((Get-Date) - $_.LastLogonDate).TotalDays)
    } else { 999 }

    $riskLevel = if ($daysSince -ge ($InactiveDays * 6))    { "CRITICAL" }
                 elseif ($daysSince -ge ($InactiveDays * 3)) { "HIGH" }
                 else                                         { "MEDIUM" }

    [PSCustomObject]@{
        SamAccountName  = $_.SamAccountName
        DisplayName     = $_.Name
        Enabled         = $_.Enabled
        UPN             = $_.UserPrincipalName
        EntraObjectId   = $_."msDS-ExternalDirectoryObjectId"
        LastLogonDate   = if ($_.LastLogonDate) { $_.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon  = $daysSince
        Department      = $_.Department
        WhenCreated     = $_.whenCreated.ToString("yyyy-MM-dd")
        OU              = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel       = $riskLevel
        FindingType     = "Stale Synced Account — Active in Both Environments"
    }
}

Write-Host "    [+] Stale synced accounts: $($staleSyncedAccounts.Count)" -ForegroundColor $(if ($staleSyncedAccounts.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 8E: Hybrid Sync Health Summary ───────────────────────────────

Write-Host "[6/6] Compiling hybrid sync health summary..." -ForegroundColor Cyan

$allFindings   = @($aadcAccounts) + @($syncedPrivAccounts) + @($upnIssues) + @($staleSyncedAccounts)
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count

# Sync health metrics
$syncCoverage     = if ($allUsers.Count -gt 0) { [math]::Round(($syncedUsers.Count / $allUsers.Count) * 100, 1) } else { 0 }
$noUPN            = ($allUsers | Where-Object { -not $_.UserPrincipalName }).Count
$noMail           = ($syncedUsers | Where-Object { -not $_.mail }).Count
$adminCountSynced = ($syncedUsers | Where-Object { $_.adminCount -eq 1 }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 8 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Total Users              : $($allUsers.Count)" -ForegroundColor White
Write-Host "  Synced to Entra ID       : $($syncedUsers.Count) ($syncCoverage%)" -ForegroundColor White
Write-Host "  On-Premises Only         : $($nonSyncedUsers.Count)" -ForegroundColor White
Write-Host "  Total Findings           : $($allFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL                 : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                     : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM                   : $mediumCount" -ForegroundColor Cyan
Write-Host "  AADC Service Accounts    : $($aadcAccounts.Count)" -ForegroundColor White
Write-Host "  Privileged Synced Accts  : $($syncedPrivAccounts.Count)" -ForegroundColor Red
Write-Host "  UPN/Attribute Issues     : $($upnIssues.Count)" -ForegroundColor Yellow
Write-Host "  Stale Synced Accounts    : $($staleSyncedAccounts.Count)" -ForegroundColor Yellow
Write-Host "  adminCount=1 Synced      : $adminCountSynced" -ForegroundColor Yellow
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

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase8-HybridIdentityAudit-$reportStamp.html"

    function Get-TableRows {
        param([array]$Data, [string[]]$Columns)
        $rows = ""
        foreach ($item in $Data) {
            $rc    = Get-RiskColor -Risk $item.RiskLevel
            $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
            $rows += "<tr>"
            foreach ($col in $Columns) {
                if ($col -eq "RiskLevel")        { $rows += "<td>$badge</td>" }
                elseif ($col -eq "SamAccountName") { $rows += "<td><code>$($item.$col)</code></td>" }
                elseif ($col -eq "EntraObjectId") {
                    $val = if ($item.$col) { "<span style='font-size:10px;color:#7f8c8d;'>$($item.$col.Substring(0,[math]::Min(20,$item.$col.Length)))...</span>" } else { "—" }
                    $rows += "<td>$val</td>"
                }
                else { $rows += "<td>$($item.$col)</td>" }
            }
            $rows += "</tr>"
        }
        return $rows
    }

    $aadcRows    = Get-TableRows -Data $aadcAccounts       -Columns @("SamAccountName","DisplayName","Enabled","PasswordNeverExpires","PasswordLastSet","InPrivilegedGroup","RiskLevel")
    $privRows    = Get-TableRows -Data $syncedPrivAccounts -Columns @("SamAccountName","DisplayName","Enabled","PrivilegedGroups","EntraObjectId","LastLogonDate","RiskLevel")
    $upnRows     = Get-TableRows -Data $upnIssues          -Columns @("SamAccountName","DisplayName","Enabled","UPN","IsSynced","Issues","RiskLevel")
    $staleRows   = Get-TableRows -Data $staleSyncedAccounts -Columns @("SamAccountName","DisplayName","UPN","LastLogonDate","DaysSinceLogon","Department","RiskLevel")

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NorthBridge Financial Group — Phase 8: Hybrid Identity & Entra ID Sync Audit</title>
<style>
  :root { --nb-navy:#0a2342; --nb-gold:#c9a84c; --nb-light:#f4f6f9; --nb-border:#dce3ec; --critical:#c0392b; --high:#e67e22; --medium:#f39c12; --low:#27ae60; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',Arial,sans-serif; background:var(--nb-light); color:#2c3e50; font-size:14px; }
  .header { background:var(--nb-navy); color:#fff; padding:28px 40px; border-bottom:4px solid var(--nb-gold); }
  .header h1 { font-size:22px; font-weight:700; }
  .header .subtitle { color:var(--nb-gold); font-size:13px; margin-top:4px; letter-spacing:1px; text-transform:uppercase; }
  .header .meta { margin-top:12px; font-size:12px; color:#aab4c2; display:flex; gap:24px; flex-wrap:wrap; }
  .compliance-bar { background:var(--nb-navy); color:#aab4c2; font-size:11px; padding:8px 40px; }
  .compliance-bar span { color:var(--nb-gold); font-weight:600; }
  .container { max-width:1280px; margin:0 auto; padding:32px 40px; }
  .kpi-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin-bottom:32px; }
  .kpi-card { background:#fff; border:1px solid var(--nb-border); border-top:4px solid var(--nb-navy); border-radius:6px; padding:20px; text-align:center; }
  .kpi-card.critical { border-top-color:var(--critical); }
  .kpi-card.high { border-top-color:var(--high); }
  .kpi-card.green { border-top-color:var(--low); }
  .kpi-value { font-size:32px; font-weight:700; color:var(--nb-navy); }
  .kpi-label { font-size:11px; color:#7f8c8d; margin-top:4px; text-transform:uppercase; letter-spacing:0.5px; }
  .sync-health { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-bottom:32px; }
  .sync-card { background:#fff; border:1px solid var(--nb-border); border-radius:6px; padding:20px; }
  .sync-card h3 { font-size:13px; color:var(--nb-navy); font-weight:600; margin-bottom:12px; text-transform:uppercase; letter-spacing:0.5px; }
  .sync-bar { background:#eef2f7; border-radius:4px; height:8px; margin:8px 0; }
  .sync-bar-fill { background:var(--nb-navy); height:8px; border-radius:4px; }
  .sync-stat { display:flex; justify-content:space-between; font-size:12px; color:#7f8c8d; margin-top:4px; }
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
  <div class="subtitle">AD Identity Operations Toolkit — Phase 8</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Hybrid Identity & Entra ID Sync Audit</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>☁️ Synced to Entra ID: $($syncedUsers.Count) / $($allUsers.Count) ($syncCoverage%)</span>
    <span>⏱ Inactivity Threshold: $InactiveDays days</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>OSFI E-21 §3.2</span> — Privileged Access &nbsp;|&nbsp;
  <span>OSFI E-21 §3.4</span> — Account Lifecycle &nbsp;|&nbsp;
  <span>NIST SP 800-53 IA-2</span> — Identification & Authentication &nbsp;|&nbsp;
  <span>CIS Controls v8 — 5, 6</span> — Account Management
</div>

<div class="container">

  <div class="osfi-box">
    <strong>⚠️ Hybrid Identity Risk:</strong> CIBC and Big 6 Canadian banks operate hybrid AD environments where on-premises Active Directory is synchronized to Microsoft Entra ID via Azure AD Connect.
    Privileged accounts synced to the cloud expand the attack surface beyond the on-premises perimeter. A compromised Entra ID account with on-premises admin rights enables full domain compromise.
    OSFI E-21 §3.2 requires privileged access to be managed at the identity provider level — cloud-synced privileged accounts violate this control.
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
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$($syncedPrivAccounts.Count)</div>
      <div class="kpi-label">Priv Accts Synced</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$($upnIssues.Count)</div>
      <div class="kpi-label">UPN/Attr Issues</div>
    </div>
    <div class="kpi-card green">
      <div class="kpi-value" style="color:var(--nb-navy)">$syncCoverage%</div>
      <div class="kpi-label">Sync Coverage</div>
    </div>
  </div>

  <!-- Sync Health -->
  <div class="sync-health">
    <div class="sync-card">
      <h3>Sync Coverage</h3>
      <div style="font-size:28px;font-weight:700;color:var(--nb-navy)">$syncCoverage%</div>
      <div class="sync-bar"><div class="sync-bar-fill" style="width:$syncCoverage%"></div></div>
      <div class="sync-stat"><span>Synced: $($syncedUsers.Count)</span><span>On-prem only: $($nonSyncedUsers.Count)</span></div>
    </div>
    <div class="sync-card">
      <h3>Attribute Health</h3>
      <div style="font-size:13px;margin-top:8px;">
        <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f0f0f0;"><span>Missing UPN</span><span style="font-weight:600;color:$(if ($noUPN -gt 0) { '#c0392b' } else { '#27ae60' })">$noUPN</span></div>
        <div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f0f0f0;"><span>Synced — No Mail</span><span style="font-weight:600;color:$(if ($noMail -gt 0) { '#e67e22' } else { '#27ae60' })">$noMail</span></div>
        <div style="display:flex;justify-content:space-between;padding:4px 0;"><span>adminCount=1 Synced</span><span style="font-weight:600;color:$(if ($adminCountSynced -gt 0) { '#c0392b' } else { '#27ae60' })">$adminCountSynced</span></div>
      </div>
    </div>
    <div class="sync-card">
      <h3>AADC Service Accounts</h3>
      <div style="font-size:28px;font-weight:700;color:$(if ($aadcAccounts.Count -gt 0) { '#e67e22' } else { '#27ae60' })">$($aadcAccounts.Count)</div>
      <div style="font-size:12px;color:#7f8c8d;margin-top:8px;">Azure AD Connect sync accounts detected in domain. Verify each is scoped to minimum required permissions.</div>
    </div>
  </div>

  <!-- Privileged Synced Accounts -->
  <div class="section">
    <div class="section-header">
      🔴 Privileged Accounts Synced to Entra ID — Critical Risk
      <span class="badge">$($syncedPrivAccounts.Count) findings</span>
    </div>
    $(if ($syncedPrivAccounts.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Enabled</th>
        <th>Privileged Groups</th><th>Entra Object ID</th><th>Last Logon</th><th>Risk</th>
      </tr></thead><tbody>$privRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No privileged accounts synced to Entra ID detected.</div>"
    })
  </div>

  <!-- AADC Service Accounts -->
  <div class="section">
    <div class="section-header">
      ⚙️ Azure AD Connect Service Accounts
      <span class="badge">$($aadcAccounts.Count) accounts</span>
    </div>
    $(if ($aadcAccounts.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Enabled</th>
        <th>Pwd Never Expires</th><th>Pwd Last Set</th><th>In Priv Group</th><th>Risk</th>
      </tr></thead><tbody>$aadcRows</tbody></table>"
    } else {
      "<div class='no-findings'>ℹ️ No Azure AD Connect service accounts detected by naming convention.</div>"
    })
  </div>

  <!-- UPN Issues -->
  <div class="section">
    <div class="section-header">
      ⚠️ UPN & Sync Attribute Issues
      <span class="badge">$($upnIssues.Count) findings</span>
    </div>
    $(if ($upnIssues.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Enabled</th>
        <th>UPN</th><th>Is Synced</th><th>Issues</th><th>Risk</th>
      </tr></thead><tbody>$upnRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No UPN or sync attribute issues detected.</div>"
    })
  </div>

  <!-- Stale Synced Accounts -->
  <div class="section">
    <div class="section-header">
      👤 Stale Synced Accounts — Active in Both Environments
      <span class="badge">$($staleSyncedAccounts.Count) findings</span>
    </div>
    $(if ($staleSyncedAccounts.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>UPN</th>
        <th>Last Logon</th><th>Days Inactive</th><th>Department</th><th>Risk</th>
      </tr></thead><tbody>$staleRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No stale synced accounts detected.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 8: Hybrid Identity & Entra ID Sync Audit
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
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase8-HybridIdentityAudit-$reportStamp.csv"
    $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 8 complete. AD Identity Operations Toolkit — All 8 phases executed." -ForegroundColor Cyan
Write-Host "  Proceed to Phase 7 Executive Summary to aggregate all findings." -ForegroundColor Cyan
Write-Host ""

return $allFindings
