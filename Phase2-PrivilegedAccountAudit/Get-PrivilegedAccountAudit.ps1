#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Privileged Account Audit — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 2

.DESCRIPTION
    Enumerates and audits all privileged principals across Tier 0 and Tier 1
    Active Directory groups in a financial institution environment. Performs
    recursive nested group explosion to surface shadow privilege paths that
    standard tooling misses.

    Detections:
        - All members of Tier 0 groups (Domain Admins, Schema Admins, Enterprise Admins)
        - All members of Tier 1 groups (Backup Operators, Account Operators, Server Operators)
        - Recursive nested group membership explosion
        - Privileged accounts with PasswordNeverExpires
        - Service accounts embedded in privileged groups
        - Privileged accounts with no logon activity > 30 days
        - Admin accounts without dedicated admin naming convention
        - Privileged accounts with non-expiring or never-set passwords

    READ-ONLY — No changes are made to Active Directory.

.PARAMETER InactiveDays
    Days since last logon to flag privileged account as inactive. Default: 30.

.PARAMETER SearchBase
    OU distinguished name to scope the search. Default: entire domain.

.PARAMETER GenerateReport
    Switch to produce an HTML report in the output path.

.PARAMETER ExportCSV
    Switch to also export findings as CSV.

.PARAMETER OutputPath
    Directory path for report output. Default: .\Reports\

.PARAMETER WhatIf
    Dry-run mode. Displays what would be flagged without writing output files.

.EXAMPLE
    # Dry-run preview
    .\Get-PrivilegedAccountAudit.ps1 -WhatIf

.EXAMPLE
    # Full audit with HTML report
    .\Get-PrivilegedAccountAudit.ps1 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    # Full audit with HTML + CSV
    .\Get-PrivilegedAccountAudit.ps1 -GenerateReport -ExportCSV -InactiveDays 30

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 2 — Privileged Account Audit
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 §3.2 | CIS Controls v8 — Control 5 | NIST SP 800-53 AC-6
    Permissions : Domain Read (no write permissions required)
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Days since last logon to flag privileged account as inactive.")]
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
║                   Phase 2 │ Privileged Account Audit                         ║
║              OSFI E-21 §3.2 │ CIS Controls v8 │ NIST 800-53 AC-6            ║
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
    Write-Host "        Error: $_" -ForegroundColor Red
    exit 1
}

$cutoffDate  = (Get-Date).AddDays(-$InactiveDays)
$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain      = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"

Write-Host "    [+] Cutoff date      : $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
Write-Host "    [+] Domain           : $domain" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Tier Definitions ────────────────────────────────────────────────────

# Tier 0 — Domain-level control. Compromise = full forest compromise.
$tier0Groups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Group Policy Creator Owners",
    "Administrators"
)

# Tier 1 — Server/service level control. Compromise = significant lateral movement risk.
$tier1Groups = @(
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "Remote Desktop Users",
    "Network Configuration Operators"
)

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

# Recursive group member explosion — surfaces nested privilege paths
function Get-GroupMembersRecursive {
    param(
        [string]$GroupName,
        [string]$Tier,
        [System.Collections.Generic.HashSet[string]]$Visited = $null
    )

    if ($null -eq $Visited) {
        $Visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $group = Get-ADGroup -Filter { Name -eq $GroupName } -ErrorAction Stop
    }
    catch {
        Write-Host "    [!] Group not found: $GroupName" -ForegroundColor DarkYellow
        return $results
    }

    if (-not $Visited.Add($group.DistinguishedName)) { return $results }

    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
    }
    catch {
        Write-Host "    [!] Cannot enumerate members of: $GroupName" -ForegroundColor DarkYellow
        return $results
    }

    foreach ($member in $members) {
        if ($member.objectClass -eq "group") {
            # Recurse into nested group
            $nested = Get-GroupMembersRecursive -GroupName $member.Name -Tier $Tier -Visited $Visited
            $results.AddRange($nested)
        }
        elseif ($member.objectClass -eq "user") {
            try {
                $user = Get-ADUser -Identity $member.DistinguishedName -Properties @(
                    "LastLogonDate", "PasswordNeverExpires", "PasswordLastSet",
                    "PasswordNotRequired", "Enabled", "Description",
                    "whenCreated", "Department", "Title", "EmailAddress",
                    "ServicePrincipalNames", "DistinguishedName"
                ) -ErrorAction Stop

                $daysSinceLogon = if ($user.LastLogonDate) {
                    [math]::Round(((Get-Date) - $user.LastLogonDate).TotalDays)
                } else { $null }

                # Risk classification
                $riskFactors = [System.Collections.Generic.List[string]]::new()
                if ($Tier -eq "Tier0")                           { $riskFactors.Add("Tier 0 Group Member") }
                if ($user.PasswordNeverExpires)                  { $riskFactors.Add("Password Never Expires") }
                if ($user.PasswordNotRequired)                   { $riskFactors.Add("Password Not Required") }
                if (-not $user.Enabled)                          { $riskFactors.Add("Account Disabled") }
                if ($null -eq $user.LastLogonDate)               { $riskFactors.Add("Never Logged In") }
                elseif ($user.LastLogonDate -lt $cutoffDate)     { $riskFactors.Add("Inactive > $InactiveDays days") }
                if ($user.ServicePrincipalNames.Count -gt 0)     { $riskFactors.Add("Kerberoastable (SPN on User)") }
                if (-not $user.SamAccountName.ToLower().StartsWith("adm") -and
                    -not $user.SamAccountName.ToLower().Contains("admin") -and
                    -not $user.SamAccountName.ToLower().Contains("svc")) {
                    $riskFactors.Add("No Admin Naming Convention")
                }

                $riskLevel = if ($Tier -eq "Tier0" -and $riskFactors.Count -ge 2)    { "CRITICAL" }
                             elseif ($Tier -eq "Tier0")                                { "HIGH" }
                             elseif ($riskFactors.Count -ge 3)                         { "HIGH" }
                             elseif ($riskFactors.Count -ge 1)                         { "MEDIUM" }
                             else                                                       { "LOW" }

                $isServiceAccount = ($user.ServicePrincipalNames.Count -gt 0) -or
                                    ($user.SamAccountName.ToLower().StartsWith("svc")) -or
                                    ($user.Description -match "service|svc|automation|scheduled")

                $results.Add([PSCustomObject]@{
                    SamAccountName      = $user.SamAccountName
                    DisplayName         = $user.Name
                    Tier                = $Tier
                    PrivilegedGroup     = $GroupName
                    Department          = $user.Department
                    Title               = $user.Title
                    Enabled             = $user.Enabled
                    LastLogonDate       = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
                    DaysSinceLogon      = if ($daysSinceLogon) { $daysSinceLogon } else { "N/A" }
                    PasswordNeverExpires = $user.PasswordNeverExpires
                    PasswordLastSet     = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd") } else { "N/A" }
                    IsServiceAccount    = $isServiceAccount
                    SPNCount            = $user.ServicePrincipalNames.Count
                    WhenCreated         = $user.whenCreated.ToString("yyyy-MM-dd")
                    OU                  = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
                    RiskFactors         = ($riskFactors -join " · ")
                    RiskLevel           = $riskLevel
                    FindingType         = if ($isServiceAccount) { "Service Account in Privileged Group" } else { "Privileged User Account" }
                })
            }
            catch {
                Write-Host "    [!] Cannot retrieve user: $($member.SamAccountName)" -ForegroundColor DarkYellow
            }
        }
    }

    return $results
}

#endregion

#region ── Phase 2A: Tier 0 Group Audit ───────────────────────────────────────

Write-Host "[1/3] Auditing TIER 0 privileged groups..." -ForegroundColor Cyan
Write-Host "      Groups: $($tier0Groups -join ', ')" -ForegroundColor DarkGray

$tier0Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($group in $tier0Groups) {
    Write-Host "    [*] Enumerating: $group" -ForegroundColor DarkGray
    $members = Get-GroupMembersRecursive -GroupName $group -Tier "Tier0"
    foreach ($m in $members) { $tier0Findings.Add($m) }
}

# Deduplicate by SamAccountName + Group combination
$tier0Findings = $tier0Findings | Sort-Object SamAccountName, PrivilegedGroup -Unique

Write-Host "    [+] Tier 0 privileged principals found: $($tier0Findings.Count)" -ForegroundColor $(if ($tier0Findings.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 2B: Tier 1 Group Audit ───────────────────────────────────────

Write-Host "[2/3] Auditing TIER 1 privileged groups..." -ForegroundColor Cyan
Write-Host "      Groups: $($tier1Groups -join ', ')" -ForegroundColor DarkGray

$tier1Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($group in $tier1Groups) {
    Write-Host "    [*] Enumerating: $group" -ForegroundColor DarkGray
    $members = Get-GroupMembersRecursive -GroupName $group -Tier "Tier1"
    foreach ($m in $members) { $tier1Findings.Add($m) }
}

$tier1Findings = $tier1Findings | Sort-Object SamAccountName, PrivilegedGroup -Unique

Write-Host "    [+] Tier 1 privileged principals found: $($tier1Findings.Count)" -ForegroundColor $(if ($tier1Findings.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 2C: Summary ──────────────────────────────────────────────────

Write-Host "[3/3] Compiling findings..." -ForegroundColor Cyan

$allFindings   = @($tier0Findings) + @($tier1Findings)
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$lowCount      = ($allFindings | Where-Object { $_.RiskLevel -eq "LOW" }).Count
$svcAcctCount  = ($allFindings | Where-Object { $_.IsServiceAccount -eq $true }).Count
$pwdNeverCount = ($allFindings | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
$inactiveCount = ($allFindings | Where-Object { $_.DaysSinceLogon -ne "N/A" -and [int]$_.DaysSinceLogon -gt $InactiveDays }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 2 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Total Privileged Principals : $($allFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL                    : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                        : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM                      : $mediumCount" -ForegroundColor Cyan
Write-Host "  LOW                         : $lowCount" -ForegroundColor Green
Write-Host "  Tier 0 Members              : $($tier0Findings.Count)" -ForegroundColor White
Write-Host "  Tier 1 Members              : $($tier1Findings.Count)" -ForegroundColor White
Write-Host "  Service Accounts in Priv.   : $svcAcctCount" -ForegroundColor Yellow
Write-Host "  Password Never Expires      : $pwdNeverCount" -ForegroundColor Yellow
Write-Host "  Inactive Privileged Accts   : $inactiveCount" -ForegroundColor Yellow
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

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase2-PrivilegedAudit-$reportStamp.html"

    function New-PrivTableRows {
        param([array]$Data)
        $rows = ""
        foreach ($item in $Data) {
            $riskColor  = Get-RiskColor -Risk $item.RiskLevel
            $riskBadge  = "<span style='background:$riskColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
            $tierColor  = if ($item.Tier -eq "Tier0") { "#c0392b" } else { "#e67e22" }
            $tierBadge  = "<span style='background:$tierColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.Tier)</span>"
            $svcBadge   = if ($item.IsServiceAccount) { "<span style='background:#8e44ad;color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;'>SVC</span>" } else { "" }
            $pwdBadge   = if ($item.PasswordNeverExpires) { "<span style='background:#c0392b;color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;'>PWD∞</span>" } else { "" }
            $rows += "<tr>"
            $rows += "<td>$tierBadge</td>"
            $rows += "<td><code>$($item.SamAccountName)</code> $svcBadge $pwdBadge</td>"
            $rows += "<td>$($item.DisplayName)</td>"
            $rows += "<td>$($item.PrivilegedGroup)</td>"
            $rows += "<td>$($item.LastLogonDate)</td>"
            $rows += "<td style='font-size:11px;color:#7f8c8d;'>$($item.RiskFactors)</td>"
            $rows += "<td>$riskBadge</td>"
            $rows += "</tr>"
        }
        return $rows
    }

    $tier0Rows = New-PrivTableRows -Data $tier0Findings
    $tier1Rows = New-PrivTableRows -Data $tier1Findings

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NorthBridge Financial Group — Phase 2: Privileged Account Audit</title>
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
  .header { background: var(--nb-navy); color: #fff; padding: 28px 40px; border-bottom: 4px solid var(--nb-gold); }
  .header h1 { font-size: 22px; font-weight: 700; }
  .header .subtitle { color: var(--nb-gold); font-size: 13px; margin-top: 4px; letter-spacing: 1px; text-transform: uppercase; }
  .header .meta { margin-top: 12px; font-size: 12px; color: #aab4c2; display: flex; gap: 24px; }
  .compliance-bar { background: var(--nb-navy); color: #aab4c2; font-size: 11px; padding: 8px 40px; letter-spacing: 0.5px; }
  .compliance-bar span { color: var(--nb-gold); font-weight: 600; }
  .container { max-width: 1280px; margin: 0 auto; padding: 32px 40px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }
  .kpi-card { background: #fff; border: 1px solid var(--nb-border); border-top: 4px solid var(--nb-navy); border-radius: 6px; padding: 20px; text-align: center; }
  .kpi-card.critical { border-top-color: var(--critical); }
  .kpi-card.high     { border-top-color: var(--high); }
  .kpi-card.purple   { border-top-color: #8e44ad; }
  .kpi-value { font-size: 32px; font-weight: 700; color: var(--nb-navy); }
  .kpi-label { font-size: 11px; color: #7f8c8d; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .section { background: #fff; border: 1px solid var(--nb-border); border-radius: 6px; margin-bottom: 28px; overflow: hidden; }
  .section-header { background: var(--nb-navy); color: #fff; padding: 14px 20px; font-size: 14px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; }
  .section-header .badge { background: var(--nb-gold); color: var(--nb-navy); border-radius: 12px; padding: 2px 10px; font-size: 12px; font-weight: 700; }
  .tier0-header { background: #7b1a1a; }
  .tier1-header { background: #7a3c00; }
  table { width: 100%; border-collapse: collapse; }
  th { background: #eef2f7; padding: 10px 14px; text-align: left; font-size: 12px; font-weight: 600; color: var(--nb-navy); text-transform: uppercase; letter-spacing: 0.4px; border-bottom: 1px solid var(--nb-border); }
  td { padding: 10px 14px; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  code { background: #eef2f7; padding: 1px 6px; border-radius: 3px; font-size: 12px; }
  .osfi-box { background: #fdf3e7; border-left: 4px solid #e67e22; border-radius: 4px; padding: 16px 20px; margin-bottom: 28px; font-size: 13px; }
  .osfi-box strong { color: #7a3c00; }
  .footer { text-align: center; padding: 20px; font-size: 11px; color: #95a5a6; border-top: 1px solid var(--nb-border); margin-top: 32px; }
  .no-findings { padding: 24px; text-align: center; color: #27ae60; font-weight: 600; }
</style>
</head>
<body>

<div class="header">
  <div class="subtitle">AD Identity Operations Toolkit — Phase 2</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Privileged Account Audit</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>⏱ Inactivity Threshold: $InactiveDays days</span>
    <span>🔍 Scope: $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>OSFI E-21 §3.2</span> — Privileged Access Management &nbsp;|&nbsp;
  <span>CIS Controls v8 — Control 5</span> — Account Management &nbsp;|&nbsp;
  <span>NIST SP 800-53 AC-6</span> — Least Privilege
</div>

<div class="container">

  <div class="osfi-box">
    <strong>⚠️ OSFI E-21 §3.2 — Privileged Access Management:</strong> Federally regulated financial institutions must maintain a current inventory of all privileged accounts, enforce least-privilege principles, and review privileged access on a regular basis. Tier 0 compromise represents a full forest takeover risk. Service accounts in privileged groups represent a critical Kerberoasting attack surface.
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">$($allFindings.Count)</div>
      <div class="kpi-label">Total Privileged Principals</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$criticalCount</div>
      <div class="kpi-label">Critical Risk</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$highCount</div>
      <div class="kpi-label">High Risk</div>
    </div>
    <div class="kpi-card purple">
      <div class="kpi-value" style="color:#8e44ad">$svcAcctCount</div>
      <div class="kpi-label">Service Accts in Priv Groups</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$pwdNeverCount</div>
      <div class="kpi-label">Password Never Expires</div>
    </div>
  </div>

  <!-- Tier 0 -->
  <div class="section">
    <div class="section-header tier0-header">
      🔴 Tier 0 — Domain-Level Privileged Accounts (Full Forest Control)
      <span class="badge">$($tier0Findings.Count) principals</span>
    </div>
    $(if ($tier0Findings.Count -gt 0) {
      "<table><thead><tr>
        <th>Tier</th><th>SAM Account</th><th>Display Name</th>
        <th>Privileged Group</th><th>Last Logon</th><th>Risk Factors</th><th>Risk</th>
      </tr></thead><tbody>$tier0Rows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No Tier 0 privileged principals detected within current scope.</div>"
    })
  </div>

  <!-- Tier 1 -->
  <div class="section">
    <div class="section-header tier1-header">
      🟠 Tier 1 — Server/Service Level Privileged Accounts
      <span class="badge">$($tier1Findings.Count) principals</span>
    </div>
    $(if ($tier1Findings.Count -gt 0) {
      "<table><thead><tr>
        <th>Tier</th><th>SAM Account</th><th>Display Name</th>
        <th>Privileged Group</th><th>Last Logon</th><th>Risk Factors</th><th>Risk</th>
      </tr></thead><tbody>$tier1Rows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No Tier 1 privileged principals detected within current scope.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 2: Privileged Account Audit
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
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase2-PrivilegedAudit-$reportStamp.csv"
    $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 2 complete. Review privileged principals and proceed to Phase 3 — Password Policy Compliance." -ForegroundColor Cyan
Write-Host ""

return $allFindings
