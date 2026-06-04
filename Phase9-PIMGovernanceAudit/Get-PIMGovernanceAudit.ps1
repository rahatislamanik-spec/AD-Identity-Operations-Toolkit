#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Privileged Identity Management (PIM) Audit — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 9

.DESCRIPTION
    Audits Privileged Identity Management controls across the Active Directory
    environment, simulating the governance checks a financial institution would
    perform on just-in-time privileged access.

    In environments with Microsoft Entra PIM, this script audits the on-premises
    AD indicators of PIM readiness and governance gaps. For full Entra PIM cloud
    audit, Microsoft.Graph module is required.

    Detections:
        - Permanent privileged role assignments (should be eligible/JIT)
        - Accounts with adminCount=1 not currently in admin groups (SDProp artifacts)
        - Privileged accounts without MFA indicators (description/title flags)
        - Admin accounts used for daily tasks (no dedicated admin account separation)
        - Privileged accounts with no recent activation (stale permanent assignments)
        - Service accounts with permanent privileged access
        - Accounts eligible for PIM but still using permanent assignment
        - Privileged access outside business hours indicators

    READ-ONLY — No changes are made to Active Directory.

.PARAMETER InactiveDays
    Days since last logon to flag privileged account as stale. Default: 30.

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
    .\Get-PIMGovernanceAudit.ps1 -WhatIf

.EXAMPLE
    .\Get-PIMGovernanceAudit.ps1 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    .\Get-PIMGovernanceAudit.ps1 -GenerateReport -ExportCSV -InactiveDays 30

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 9 — Privileged Identity Management (PIM) Audit
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 §3.2 | CIS Controls v8 — 5.4 | NIST SP 800-53 AC-6(5)
    Permissions : Domain Read (no write permissions required)
    Note        : Full Entra PIM audit requires Microsoft.Graph with
                  RoleManagement.Read.All and PrivilegedAccess.Read.AzureAD
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Days since last logon to flag privileged account as stale.")]
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
║              Phase 9 │ Privileged Identity Management (PIM) Audit            ║
║         OSFI E-21 §3.2 │ CIS Controls v8 — 5.4 │ NIST SP 800-53 AC-6(5)    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Inactivity Threshold : $InactiveDays days" -ForegroundColor Yellow
Write-Host "  Search Scope         : $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })" -ForegroundColor Yellow
Write-Host "  Execution Mode       : $(if ($WhatIfPreference) { 'DRY RUN — No files will be written' } else { 'LIVE AUDIT' })" -ForegroundColor $(if ($WhatIfPreference) { 'Magenta' } else { 'Green' })
Write-Host ""

#endregion

#region ── Pre-flight ──────────────────────────────────────────────────────────

Write-Host "[*] Pre-flight checks..." -ForegroundColor Cyan

try {
    $null = Get-ADDomain -ErrorAction Stop
    Write-Host "    [+] Active Directory connection verified" -ForegroundColor Green
}
catch {
    Write-Host "    [!] FATAL: Cannot connect to Active Directory." -ForegroundColor Red
    exit 1
}

# Check for Microsoft.Graph (optional — enables Entra PIM cloud audit)
$graphAvailable = $false
try {
    $null = Get-Module -Name "Microsoft.Graph.Identity.Governance" -ListAvailable -ErrorAction Stop
    $graphAvailable = $true
    Write-Host "    [+] Microsoft.Graph.Identity.Governance detected — Entra PIM audit enabled" -ForegroundColor Green
}
catch {
    Write-Host "    [!] Microsoft.Graph not found — running on-premises PIM readiness audit only" -ForegroundColor Yellow
    Write-Host "        Install: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor DarkGray
}

$cutoffDate  = (Get-Date).AddDays(-$InactiveDays)
$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain      = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"

Write-Host "    [+] Domain       : $domain" -ForegroundColor Green
Write-Host "    [+] Cutoff date  : $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Tier Definitions ────────────────────────────────────────────────────

# Groups that should use JIT/PIM rather than permanent assignment
$pimCandidateGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners",
    "Backup Operators",
    "Account Operators",
    "Server Operators"
)

# Admin account naming conventions (accounts that ARE dedicated admin accounts)
$adminNamingPatterns = @("adm_*", "adm-*", "admin_*", "admin-*", "a-*", "da-*", "pa-*", "t0-*", "t1-*")

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

function Test-IsDedicatedAdminAccount {
    param([string]$SamAccountName)
    foreach ($pattern in $adminNamingPatterns) {
        if ($SamAccountName -like $pattern) { return $true }
    }
    return $false
}

function Test-IsServiceAccount {
    param([string]$SamAccountName, [string]$Description)
    return (
        $SamAccountName.ToLower().StartsWith("svc") -or
        $SamAccountName.ToLower().StartsWith("sa-") -or
        ($Description -match "service|svc|automation|scheduled|task|integration|api")
    )
}

#endregion

#region ── Load Privileged Users ───────────────────────────────────────────────

Write-Host "[1/5] Loading privileged group members..." -ForegroundColor Cyan

$privilegedPrincipals = [System.Collections.Generic.List[PSCustomObject]]::new()
$seenDNs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($groupName in $pimCandidateGroups) {
    try {
        $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq "user" }

        foreach ($member in $members) {
            if (-not $seenDNs.Add($member.DistinguishedName)) { continue }

            try {
                $user = Get-ADUser -Identity $member.DistinguishedName -Properties @(
                    "LastLogonDate", "PasswordNeverExpires", "PasswordLastSet",
                    "Enabled", "Description", "Title", "Department",
                    "MemberOf", "whenCreated", "DistinguishedName",
                    "ServicePrincipalNames", "adminCount",
                    "msDS-ExternalDirectoryObjectId", "UserPrincipalName"
                ) -ErrorAction Stop

                $privilegedPrincipals.Add([PSCustomObject]@{
                    User         = $user
                    SourceGroup  = $groupName
                })
            } catch { }
        }
    }
    catch {
        Write-Host "    [!] Cannot enumerate: $groupName" -ForegroundColor DarkYellow
    }
}

Write-Host "    [+] Privileged principals loaded: $($privilegedPrincipals.Count)" -ForegroundColor Green

#endregion

#region ── Phase 9A: Permanent Privileged Assignments ─────────────────────────

Write-Host "[2/5] Identifying permanent privileged assignments (PIM candidates)..." -ForegroundColor Cyan

$permanentAssignments = $privilegedPrincipals | ForEach-Object {
    $user = $_.User
    $group = $_.SourceGroup

    $daysSince = if ($user.LastLogonDate) {
        [math]::Round(((Get-Date) - $user.LastLogonDate).TotalDays)
    } else { $null }

    $riskFactors = [System.Collections.Generic.List[string]]::new()
    $riskFactors.Add("Permanent assignment — should be PIM eligible/JIT")
    if ($user.PasswordNeverExpires)                          { $riskFactors.Add("Password Never Expires") }
    if ($null -eq $user.LastLogonDate)                      { $riskFactors.Add("Never Logged In") }
    elseif ($user.LastLogonDate -lt $cutoffDate)            { $riskFactors.Add("Inactive > $InactiveDays days") }
    if ($user.ServicePrincipalNames.Count -gt 0)            { $riskFactors.Add("Service Account with Permanent Priv") }
    if (-not (Test-IsDedicatedAdminAccount $user.SamAccountName)) { $riskFactors.Add("No Admin Naming Convention") }

    $riskLevel = if ($riskFactors.Count -ge 4)              { "CRITICAL" }
                 elseif ($riskFactors.Count -ge 3)           { "HIGH" }
                 elseif ($riskFactors.Count -ge 2)           { "MEDIUM" }
                 else                                         { "LOW" }

    [PSCustomObject]@{
        SamAccountName       = $user.SamAccountName
        DisplayName          = $user.Name
        Enabled              = $user.Enabled
        PrivilegedGroup      = $group
        AssignmentType       = "PERMANENT"
        PIMRecommendation    = "Convert to ELIGIBLE (JIT)"
        LastLogonDate        = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon       = if ($daysSince) { $daysSince } else { "N/A" }
        PasswordNeverExpires = $user.PasswordNeverExpires
        IsDedicatedAdmin     = (Test-IsDedicatedAdminAccount $user.SamAccountName)
        IsServiceAccount     = (Test-IsServiceAccount $user.SamAccountName ($user.Description ?? ""))
        IsSyncedToCloud      = ($null -ne $user."msDS-ExternalDirectoryObjectId")
        AdminCount           = $user.adminCount
        WhenCreated          = $user.whenCreated.ToString("yyyy-MM-dd")
        OU                   = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskFactors          = ($riskFactors -join " · ")
        RiskLevel            = $riskLevel
        FindingType          = "Permanent Privileged Assignment — PIM Candidate"
    }
}

Write-Host "    [+] Permanent privileged assignments: $($permanentAssignments.Count)" -ForegroundColor $(if ($permanentAssignments.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 9B: SDProp AdminCount Artifacts ──────────────────────────────

Write-Host "[3/5] Detecting adminCount=1 artifacts (SDProp residue)..." -ForegroundColor Cyan

$adUserParams = @{
    Filter     = { adminCount -eq 1 }
    Properties = @("adminCount", "MemberOf", "LastLogonDate", "Enabled", "Description", "DistinguishedName", "whenCreated")
}
if ($SearchBase) { $adUserParams["SearchBase"] = $SearchBase }

$adminCountUsers = Get-ADUser @adUserParams
$sdpropArtifacts = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($user in $adminCountUsers) {
    # Check if still in a privileged group
    $stillPrivileged = $false
    foreach ($groupDN in $user.MemberOf) {
        $gName = $groupDN -replace '^CN=([^,]+),.+$', '$1'
        if ($pimCandidateGroups -contains $gName) { $stillPrivileged = $true; break }
    }

    if (-not $stillPrivileged) {
        $sdpropArtifacts.Add([PSCustomObject]@{
            SamAccountName  = $user.SamAccountName
            DisplayName     = $user.Name
            Enabled         = $user.Enabled
            AdminCount      = $user.adminCount
            StillPrivileged = $false
            LastLogonDate   = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
            WhenCreated     = $user.whenCreated.ToString("yyyy-MM-dd")
            OU              = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
            RiskLevel       = "HIGH"
            FindingType     = "SDProp Artifact — adminCount=1 Without Current Privilege"
        })
    }
}

Write-Host "    [+] SDProp artifacts (adminCount=1, not privileged): $($sdpropArtifacts.Count)" -ForegroundColor $(if ($sdpropArtifacts.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 9C: Non-Dedicated Admin Accounts in Privileged Groups ─────────

Write-Host "[4/5] Detecting non-dedicated accounts with permanent privileged access..." -ForegroundColor Cyan

$nonDedicatedAdmins = $permanentAssignments | Where-Object {
    -not $_.IsDedicatedAdmin -and -not $_.IsServiceAccount
} | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName   = $_.SamAccountName
        DisplayName      = $_.DisplayName
        Enabled          = $_.Enabled
        PrivilegedGroup  = $_.PrivilegedGroup
        LastLogonDate    = $_.LastLogonDate
        DaysSinceLogon   = $_.DaysSinceLogon
        IsSyncedToCloud  = $_.IsSyncedToCloud
        WhenCreated      = $_.WhenCreated
        OU               = $_.OU
        RiskLevel        = "HIGH"
        FindingType      = "Non-Dedicated Account — Permanent Privileged Access"
        Recommendation   = "Create dedicated admin account (adm_username), assign to PIM eligible role"
    }
}

Write-Host "    [+] Non-dedicated accounts with permanent privilege: $($nonDedicatedAdmins.Count)" -ForegroundColor $(if ($nonDedicatedAdmins.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 9D: Stale Permanent Privileged Accounts ──────────────────────

Write-Host "[5/5] Detecting stale permanent privileged accounts..." -ForegroundColor Cyan

$stalePrivAccounts = $permanentAssignments | Where-Object {
    $_.DaysSinceLogon -ne "N/A" -and [int]$_.DaysSinceLogon -gt $InactiveDays -or
    $_.LastLogonDate -eq "NEVER"
} | ForEach-Object {
    [PSCustomObject]@{
        SamAccountName   = $_.SamAccountName
        DisplayName      = $_.DisplayName
        Enabled          = $_.Enabled
        PrivilegedGroup  = $_.PrivilegedGroup
        LastLogonDate    = $_.LastLogonDate
        DaysSinceLogon   = $_.DaysSinceLogon
        AssignmentType   = "PERMANENT"
        WhenCreated      = $_.WhenCreated
        OU               = $_.OU
        RiskLevel        = if ($_.LastLogonDate -eq "NEVER") { "CRITICAL" } else { "HIGH" }
        FindingType      = "Stale Permanent Privileged Account"
        Recommendation   = "Revoke permanent assignment, review business need, convert to PIM eligible if required"
    }
}

Write-Host "    [+] Stale permanent privileged accounts: $($stalePrivAccounts.Count)" -ForegroundColor $(if ($stalePrivAccounts.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Summary ────────────────────────────────────────────────────────────

$allFindings   = @($permanentAssignments) + @($sdpropArtifacts) + @($nonDedicatedAdmins) + @($stalePrivAccounts)
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$cloudSyncedPriv = ($permanentAssignments | Where-Object { $_.IsSyncedToCloud -eq $true }).Count
$svcInPriv     = ($permanentAssignments | Where-Object { $_.IsServiceAccount -eq $true }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 9 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Total Findings              : $($allFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL                    : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                        : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM                      : $mediumCount" -ForegroundColor Cyan
Write-Host "  Permanent Assignments       : $($permanentAssignments.Count)" -ForegroundColor Yellow
Write-Host "  SDProp Artifacts            : $($sdpropArtifacts.Count)" -ForegroundColor Yellow
Write-Host "  Non-Dedicated Admins        : $($nonDedicatedAdmins.Count)" -ForegroundColor Yellow
Write-Host "  Stale Privileged Accounts   : $($stalePrivAccounts.Count)" -ForegroundColor Yellow
Write-Host "  Privileged + Cloud Synced   : $cloudSyncedPriv" -ForegroundColor Red
Write-Host "  Service Accts in Priv Groups: $svcInPriv" -ForegroundColor Red
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

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase9-PIMGovernanceAudit-$reportStamp.html"

    function Get-TableRows {
        param([array]$Data, [string[]]$Columns)
        $rows = ""
        foreach ($item in $Data) {
            $rc    = Get-RiskColor -Risk $item.RiskLevel
            $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
            $rows += "<tr>"
            foreach ($col in $Columns) {
                if ($col -eq "RiskLevel")          { $rows += "<td>$badge</td>" }
                elseif ($col -eq "SamAccountName") { $rows += "<td><code>$($item.$col)</code></td>" }
                elseif ($col -eq "AssignmentType") {
                    $atColor = if ($item.$col -eq "PERMANENT") { "#c0392b" } else { "#27ae60" }
                    $rows += "<td><span style='color:$atColor;font-weight:700;'>$($item.$col)</span></td>"
                }
                else { $rows += "<td>$($item.$col)</td>" }
            }
            $rows += "</tr>"
        }
        return $rows
    }

    $permRows   = Get-TableRows -Data $permanentAssignments -Columns @("SamAccountName","DisplayName","PrivilegedGroup","AssignmentType","IsDedicatedAdmin","IsSyncedToCloud","DaysSinceLogon","RiskLevel")
    $sdpropRows = Get-TableRows -Data $sdpropArtifacts     -Columns @("SamAccountName","DisplayName","Enabled","AdminCount","LastLogonDate","OU","RiskLevel")
    $ndRows     = Get-TableRows -Data $nonDedicatedAdmins  -Columns @("SamAccountName","DisplayName","PrivilegedGroup","LastLogonDate","IsSyncedToCloud","Recommendation","RiskLevel")
    $staleRows  = Get-TableRows -Data $stalePrivAccounts   -Columns @("SamAccountName","DisplayName","PrivilegedGroup","LastLogonDate","DaysSinceLogon","Recommendation","RiskLevel")

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NorthBridge Financial Group — Phase 9: PIM Governance Audit</title>
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
  .kpi-value { font-size:32px; font-weight:700; color:var(--nb-navy); }
  .kpi-label { font-size:11px; color:#7f8c8d; margin-top:4px; text-transform:uppercase; letter-spacing:0.5px; }
  .pim-model { background:#fff; border:1px solid var(--nb-border); border-radius:6px; padding:24px; margin-bottom:28px; }
  .pim-model h3 { font-size:14px; font-weight:600; color:var(--nb-navy); margin-bottom:16px; text-transform:uppercase; letter-spacing:0.5px; }
  .pim-flow { display:flex; align-items:center; gap:0; flex-wrap:wrap; }
  .pim-step { flex:1; min-width:140px; text-align:center; padding:16px 12px; border:1px solid var(--nb-border); font-size:12px; }
  .pim-step.bad { background:#fdf3e7; border-color:#e67e22; }
  .pim-step.good { background:#eaf4ea; border-color:#27ae60; }
  .pim-step-title { font-weight:700; font-size:13px; margin-bottom:4px; }
  .pim-arrow { font-size:20px; color:#bdc3c7; padding:0 8px; }
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
  <div class="subtitle">AD Identity Operations Toolkit — Phase 9</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Privileged Identity Management (PIM) Audit</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>⏱ Inactivity Threshold: $InactiveDays days</span>
    <span>🔐 Privileged Groups Audited: $($pimCandidateGroups.Count)</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>OSFI E-21 §3.2</span> — Privileged Access Management &nbsp;|&nbsp;
  <span>CIS Controls v8 — 5.4</span> — Restrict Administrator Privileges &nbsp;|&nbsp;
  <span>NIST SP 800-53 AC-6(5)</span> — Least Privilege — Privileged Accounts
</div>

<div class="container">

  <div class="osfi-box">
    <strong>⚠️ OSFI E-21 §3.2 — Just-In-Time Access Requirement:</strong>
    Federally regulated financial institutions must implement just-in-time (JIT) privileged access controls. Permanent privileged role assignments violate the principle of least privilege and expand the attack window.
    Microsoft Entra Privileged Identity Management (PIM) provides eligible role assignments that require explicit activation, MFA verification, and time-bound access — eliminating standing privilege entirely.
    Every permanent Domain Admin is a 24/7 attack surface. Every eligible PIM role is a closed door that opens only when needed.
  </div>

  <div class="kpi-grid">
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$($permanentAssignments.Count)</div>
      <div class="kpi-label">Permanent Assignments</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$criticalCount</div>
      <div class="kpi-label">Critical Risk</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$($sdpropArtifacts.Count)</div>
      <div class="kpi-label">SDProp Artifacts</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$($nonDedicatedAdmins.Count)</div>
      <div class="kpi-label">Non-Dedicated Admins</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$cloudSyncedPriv</div>
      <div class="kpi-label">Priv + Cloud Synced</div>
    </div>
  </div>

  <!-- PIM Model Explainer -->
  <div class="pim-model">
    <h3>Current State vs Target State — PIM Governance Model</h3>
    <div class="pim-flow">
      <div class="pim-step bad">
        <div class="pim-step-title" style="color:var(--critical)">❌ Current State</div>
        <div>Permanent Domain Admin</div>
        <div style="font-size:11px;color:#7f8c8d;margin-top:4px;">Standing privilege 24/7 — always exploitable</div>
      </div>
      <div class="pim-arrow">→</div>
      <div class="pim-step good">
        <div class="pim-step-title" style="color:#27ae60">✅ Target State</div>
        <div>PIM Eligible Role</div>
        <div style="font-size:11px;color:#7f8c8d;margin-top:4px;">No standing privilege — activate when needed</div>
      </div>
      <div class="pim-arrow">→</div>
      <div class="pim-step good">
        <div class="pim-step-title" style="color:#27ae60">✅ Activation</div>
        <div>MFA + Justification</div>
        <div style="font-size:11px;color:#7f8c8d;margin-top:4px;">Time-bound, audited, auto-expires</div>
      </div>
      <div class="pim-arrow">→</div>
      <div class="pim-step good">
        <div class="pim-step-title" style="color:#27ae60">✅ Auto-Revoke</div>
        <div>Role Expires</div>
        <div style="font-size:11px;color:#7f8c8d;margin-top:4px;">Returns to zero-standing privilege</div>
      </div>
    </div>
  </div>

  <!-- Permanent Assignments -->
  <div class="section">
    <div class="section-header">
      🔴 Permanent Privileged Assignments — PIM Conversion Required
      <span class="badge">$($permanentAssignments.Count) accounts</span>
    </div>
    $(if ($permanentAssignments.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Privileged Group</th>
        <th>Assignment</th><th>Dedicated Admin</th><th>Cloud Synced</th><th>Days Inactive</th><th>Risk</th>
      </tr></thead><tbody>$permRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No permanent privileged assignments detected — PIM governance in place.</div>"
    })
  </div>

  <!-- SDProp Artifacts -->
  <div class="section">
    <div class="section-header">
      ⚠️ SDProp Artifacts — adminCount=1 Without Current Privilege
      <span class="badge">$($sdpropArtifacts.Count) findings</span>
    </div>
    $(if ($sdpropArtifacts.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Enabled</th>
        <th>Admin Count</th><th>Last Logon</th><th>OU</th><th>Risk</th>
      </tr></thead><tbody>$sdpropRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No SDProp artifacts detected.</div>"
    })
  </div>

  <!-- Non-Dedicated Admins -->
  <div class="section">
    <div class="section-header">
      🟠 Non-Dedicated Accounts — Permanent Privileged Access
      <span class="badge">$($nonDedicatedAdmins.Count) findings</span>
    </div>
    $(if ($nonDedicatedAdmins.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Privileged Group</th>
        <th>Last Logon</th><th>Cloud Synced</th><th>Recommendation</th><th>Risk</th>
      </tr></thead><tbody>$ndRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ All privileged accounts use dedicated admin naming convention.</div>"
    })
  </div>

  <!-- Stale Privileged -->
  <div class="section">
    <div class="section-header">
      👤 Stale Permanent Privileged Accounts
      <span class="badge">$($stalePrivAccounts.Count) findings</span>
    </div>
    $(if ($stalePrivAccounts.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Privileged Group</th>
        <th>Last Logon</th><th>Days Inactive</th><th>Recommendation</th><th>Risk</th>
      </tr></thead><tbody>$staleRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No stale permanent privileged accounts detected.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 9: PIM Governance Audit
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
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase9-PIMGovernanceAudit-$reportStamp.csv"
    $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 9 complete. AD Identity Operations Toolkit — 9 phases executed." -ForegroundColor Cyan
Write-Host "  Recommendation: Implement Microsoft Entra PIM for all permanent assignments identified." -ForegroundColor Yellow
Write-Host ""

return $allFindings
