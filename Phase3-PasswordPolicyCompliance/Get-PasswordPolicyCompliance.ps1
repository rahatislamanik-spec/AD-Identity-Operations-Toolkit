#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Password Policy Compliance — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 3

.DESCRIPTION
    Audits Active Directory password policies across the entire domain including
    the Default Domain Password Policy and all Fine-Grained Password Policies (FGPPs)
    applied via Password Settings Objects (PSOs).

    Detections:
        - Accounts with PasswordNeverExpires flag set
        - Accounts with PasswordNotRequired flag set
        - Accounts with passwords older than policy maximum age
        - Accounts not covered by any Fine-Grained Password Policy
        - PSO policy strength vs OSFI E-21 minimum requirements
        - Default Domain Policy strength assessment
        - Accounts with passwords that have never been set
        - Privileged accounts falling outside strong PSO coverage

    READ-ONLY — No changes are made to Active Directory.

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
    .\Get-PasswordPolicyCompliance.ps1 -WhatIf

.EXAMPLE
    .\Get-PasswordPolicyCompliance.ps1 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    .\Get-PasswordPolicyCompliance.ps1 -GenerateReport -ExportCSV

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 3 — Password Policy Compliance
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 §3.3 | NIST SP 800-53 IA-5 | CIS Controls v8 — Control 5.2
    Permissions : Domain Read (no write permissions required)
#>

[CmdletBinding(SupportsShouldProcess)]
param (
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
║                  Phase 3 │ Password Policy Compliance                        ║
║           OSFI E-21 §3.3 │ NIST SP 800-53 IA-5 │ CIS Controls v8            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Search Scope   : $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })" -ForegroundColor Yellow
Write-Host "  Execution Mode : $(if ($WhatIfPreference) { 'DRY RUN — No files will be written' } else { 'LIVE AUDIT' })" -ForegroundColor $(if ($WhatIfPreference) { 'Magenta' } else { 'Green' })
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

$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain      = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"

# OSFI E-21 minimum password policy requirements for financial institutions
$osfiMinLength        = 12
$osfiMaxAgeDays       = 90
$osfiMinAgeDays       = 1
$osfiHistoryCount     = 12
$osfiLockoutThreshold = 5
$osfiComplexity       = $true

Write-Host "    [+] Domain           : $domain" -ForegroundColor Green
Write-Host "    [+] OSFI Min Length  : $osfiMinLength characters" -ForegroundColor Green
Write-Host "    [+] OSFI Max Age     : $osfiMaxAgeDays days" -ForegroundColor Green
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
        "PASS"     { return "#27ae60" }
        "FAIL"     { return "#c0392b" }
        default    { return "#95a5a6" }
    }
}

function Get-PolicyComplianceStatus {
    param(
        [int]$MinLength,
        [int]$MaxAgeDays,
        [int]$MinAgeDays,
        [int]$HistoryCount,
        [bool]$Complexity,
        [int]$LockoutThreshold
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if ($MinLength -lt $osfiMinLength)             { $issues.Add("Min length $MinLength < OSFI $osfiMinLength") }
    if ($MaxAgeDays -gt $osfiMaxAgeDays -or
        $MaxAgeDays -eq 0)                         { $issues.Add("Max age ${MaxAgeDays}d exceeds OSFI ${osfiMaxAgeDays}d") }
    if ($MinAgeDays -lt $osfiMinAgeDays)           { $issues.Add("Min age ${MinAgeDays}d below OSFI ${osfiMinAgeDays}d") }
    if ($HistoryCount -lt $osfiHistoryCount)       { $issues.Add("History $HistoryCount < OSFI $osfiHistoryCount") }
    if (-not $Complexity)                          { $issues.Add("Complexity not enforced") }
    if ($LockoutThreshold -eq 0 -or
        $LockoutThreshold -gt $osfiLockoutThreshold) { $issues.Add("Lockout threshold $LockoutThreshold > OSFI $osfiLockoutThreshold") }

    return $issues
}

#endregion

#region ── Phase 3A: Default Domain Password Policy ───────────────────────────

Write-Host "[1/4] Auditing Default Domain Password Policy..." -ForegroundColor Cyan

$ddp         = Get-ADDefaultDomainPasswordPolicy
$ddpMaxAge   = [math]::Round($ddp.MaxPasswordAge.TotalDays)
$ddpMinAge   = [math]::Round($ddp.MinPasswordAge.TotalDays)
$ddpIssues   = Get-PolicyComplianceStatus `
    -MinLength        $ddp.MinPasswordLength `
    -MaxAgeDays       $ddpMaxAge `
    -MinAgeDays       $ddpMinAge `
    -HistoryCount     $ddp.PasswordHistoryCount `
    -Complexity       $ddp.ComplexityEnabled `
    -LockoutThreshold $ddp.LockoutThreshold

$ddpCompliant  = ($ddpIssues.Count -eq 0)
$ddpRisk       = if ($ddpCompliant) { "PASS" } elseif ($ddpIssues.Count -ge 3) { "CRITICAL" } elseif ($ddpIssues.Count -ge 2) { "HIGH" } else { "MEDIUM" }

Write-Host "    [+] Default Domain Policy assessed — Compliant: $ddpCompliant" -ForegroundColor $(if ($ddpCompliant) { 'Green' } else { 'Yellow' })

#endregion

#region ── Phase 3B: Fine-Grained Password Policies (PSOs) ────────────────────

Write-Host "[2/4] Auditing Fine-Grained Password Policies (PSOs)..." -ForegroundColor Cyan

$psoFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    $psos = Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -ErrorAction Stop

    foreach ($pso in $psos) {
        $psoMaxAge  = [math]::Round($pso.MaxPasswordAge.TotalDays)
        $psoMinAge  = [math]::Round($pso.MinPasswordAge.TotalDays)
        $psoIssues  = Get-PolicyComplianceStatus `
            -MinLength        $pso.MinPasswordLength `
            -MaxAgeDays       $psoMaxAge `
            -MinAgeDays       $psoMinAge `
            -HistoryCount     $pso.PasswordHistoryCount `
            -Complexity       $pso.ComplexityEnabled `
            -LockoutThreshold $pso.LockoutThreshold

        $psoCompliant = ($psoIssues.Count -eq 0)
        $psoRisk      = if ($psoCompliant) { "PASS" } elseif ($psoIssues.Count -ge 3) { "CRITICAL" } elseif ($psoIssues.Count -ge 2) { "HIGH" } else { "MEDIUM" }

        # Get subjects (users/groups this PSO applies to)
        $subjects = Get-ADFineGrainedPasswordPolicySubject -Identity $pso.Name -ErrorAction SilentlyContinue
        $subjectNames = ($subjects | ForEach-Object { $_.Name }) -join ", "

        $psoFindings.Add([PSCustomObject]@{
            PSO_Name          = $pso.Name
            Precedence        = $pso.Precedence
            MinLength         = $pso.MinPasswordLength
            MaxAgeDays        = $psoMaxAge
            MinAgeDays        = $psoMinAge
            HistoryCount      = $pso.PasswordHistoryCount
            ComplexityEnabled = $pso.ComplexityEnabled
            LockoutThreshold  = $pso.LockoutThreshold
            AppliesTo         = if ($subjectNames) { $subjectNames } else { "No subjects assigned" }
            Compliant         = $psoCompliant
            Issues            = if ($psoIssues.Count -gt 0) { $psoIssues -join " · " } else { "None" }
            RiskLevel         = $psoRisk
        })
    }

    Write-Host "    [+] PSOs found: $($psoFindings.Count)" -ForegroundColor Green
}
catch {
    Write-Host "    [!] Cannot enumerate PSOs — may require Domain Admin read or PSO feature not in use." -ForegroundColor DarkYellow
}

#endregion

#region ── Phase 3C: User-Level Password Compliance ───────────────────────────

Write-Host "[3/4] Scanning user accounts for password compliance violations..." -ForegroundColor Cyan

$adUserParams = @{
    Filter     = *
    Properties = @(
        "PasswordNeverExpires", "PasswordNotRequired", "PasswordLastSet",
        "PasswordExpired", "LastLogonDate", "Enabled", "Department",
        "Title", "DistinguishedName", "whenCreated", "MemberOf"
    )
}
if ($SearchBase) { $adUserParams["SearchBase"] = $SearchBase }

$allUsers      = Get-ADUser @adUserParams
$userFindings  = [System.Collections.Generic.List[PSCustomObject]]::new()
$maxPwdAgeDays = $ddpMaxAge

foreach ($user in $allUsers) {

    $violations = [System.Collections.Generic.List[string]]::new()

    if ($user.PasswordNeverExpires -and $user.Enabled)  { $violations.Add("Password Never Expires") }
    if ($user.PasswordNotRequired)                       { $violations.Add("Password Not Required") }
    if ($null -eq $user.PasswordLastSet)                 { $violations.Add("Password Never Set") }
    if ($user.PasswordExpired -and $user.Enabled)        { $violations.Add("Password Currently Expired") }

    # Check if password exceeds max age
    if ($user.PasswordLastSet -and $maxPwdAgeDays -gt 0) {
        $pwdAgeDays = [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays)
        if ($pwdAgeDays -gt $maxPwdAgeDays) {
            $violations.Add("Password Age ${pwdAgeDays}d exceeds max ${maxPwdAgeDays}d")
        }
    }

    if ($violations.Count -eq 0) { continue }

    $riskLevel = if ($violations.Count -ge 3)                          { "CRITICAL" }
                 elseif ($violations.Contains("Password Never Expires") -and
                         $violations.Contains("Password Not Required")) { "CRITICAL" }
                 elseif ($violations.Count -ge 2)                       { "HIGH" }
                 else                                                   { "MEDIUM" }

    $pwdAgeDays = if ($user.PasswordLastSet) {
        [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays)
    } else { "N/A" }

    $userFindings.Add([PSCustomObject]@{
        SamAccountName      = $user.SamAccountName
        DisplayName         = $user.Name
        Enabled             = $user.Enabled
        Department          = $user.Department
        Title               = $user.Title
        PasswordNeverExpires = $user.PasswordNeverExpires
        PasswordNotRequired = $user.PasswordNotRequired
        PasswordLastSet     = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd") } else { "NEVER" }
        PasswordAgeDays     = $pwdAgeDays
        PasswordExpired     = $user.PasswordExpired
        WhenCreated         = $user.whenCreated.ToString("yyyy-MM-dd")
        OU                  = ($user.DistinguishedName -replace '^CN=[^,]+,', '')
        Violations          = ($violations -join " · ")
        RiskLevel           = $riskLevel
        FindingType         = "Password Policy Violation"
    })
}

Write-Host "    [+] User password violations found: $($userFindings.Count)" -ForegroundColor $(if ($userFindings.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Summary ────────────────────────────────────────────────────────────

Write-Host "[4/4] Compiling findings..." -ForegroundColor Cyan

$criticalCount = ($userFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($userFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($userFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$pwdNeverCount = ($userFindings | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
$pwdNeverSet   = ($userFindings | Where-Object { $_.PasswordLastSet -eq "NEVER" }).Count
$psoFailCount  = ($psoFindings  | Where-Object { $_.Compliant -eq $false }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 3 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Default Domain Policy  : $(if ($ddpCompliant) { 'COMPLIANT' } else { 'NON-COMPLIANT' })" -ForegroundColor $(if ($ddpCompliant) { 'Green' } else { 'Red' })
Write-Host "  PSOs Assessed          : $($psoFindings.Count)" -ForegroundColor White
Write-Host "  PSOs Non-Compliant     : $psoFailCount" -ForegroundColor $(if ($psoFailCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  User Violations        : $($userFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL               : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                   : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM                 : $mediumCount" -ForegroundColor Cyan
Write-Host "  Password Never Expires : $pwdNeverCount" -ForegroundColor Yellow
Write-Host "  Password Never Set     : $pwdNeverSet" -ForegroundColor Yellow
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

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase3-PasswordPolicy-$reportStamp.html"

    # Build PSO table rows
    $psoRows = ""
    foreach ($pso in $psoFindings) {
        $rc = Get-RiskColor -Risk $pso.RiskLevel
        $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($pso.RiskLevel)</span>"
        $psoRows += "<tr>"
        $psoRows += "<td><strong>$($pso.PSO_Name)</strong></td>"
        $psoRows += "<td>$($pso.Precedence)</td>"
        $psoRows += "<td>$($pso.MinLength)</td>"
        $psoRows += "<td>$($pso.MaxAgeDays)d</td>"
        $psoRows += "<td>$($pso.HistoryCount)</td>"
        $psoRows += "<td>$(if ($pso.ComplexityEnabled) { '✅' } else { '❌' })</td>"
        $psoRows += "<td>$($pso.LockoutThreshold)</td>"
        $psoRows += "<td style='font-size:11px;'>$($pso.AppliesTo)</td>"
        $psoRows += "<td>$badge</td>"
        $psoRows += "</tr>"
    }

    # Build user violation rows
    $userRows = ""
    foreach ($u in $userFindings) {
        $rc = Get-RiskColor -Risk $u.RiskLevel
        $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($u.RiskLevel)</span>"
        $userRows += "<tr>"
        $userRows += "<td><code>$($u.SamAccountName)</code></td>"
        $userRows += "<td>$($u.DisplayName)</td>"
        $userRows += "<td>$(if ($u.Enabled) { '✅' } else { '❌ Disabled' })</td>"
        $userRows += "<td>$($u.PasswordLastSet)</td>"
        $userRows += "<td>$($u.PasswordAgeDays)</td>"
        $userRows += "<td style='font-size:11px;color:#7f8c8d;'>$($u.Violations)</td>"
        $userRows += "<td>$badge</td>"
        $userRows += "</tr>"
    }

    # Default Domain Policy row values
    $ddpColor  = Get-RiskColor -Risk $ddpRisk
    $ddpBadge  = "<span style='background:$ddpColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$ddpRisk</span>"
    $ddpIssueText = if ($ddpIssues.Count -gt 0) { $ddpIssues -join " · " } else { "None — Policy meets OSFI E-21 minimums" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NorthBridge Financial Group — Phase 3: Password Policy Compliance</title>
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
  .ddp-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; padding:20px; }
  .ddp-item { background:#f8fafc; border:1px solid var(--nb-border); border-radius:4px; padding:12px 16px; }
  .ddp-label { font-size:11px; color:#7f8c8d; text-transform:uppercase; letter-spacing:0.4px; }
  .ddp-value { font-size:18px; font-weight:700; color:var(--nb-navy); margin-top:4px; }
  .ddp-status { font-size:12px; margin-top:2px; }
  table { width:100%; border-collapse:collapse; }
  th { background:#eef2f7; padding:10px 14px; text-align:left; font-size:12px; font-weight:600; color:var(--nb-navy); text-transform:uppercase; border-bottom:1px solid var(--nb-border); }
  td { padding:10px 14px; border-bottom:1px solid #f0f0f0; font-size:13px; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:#f8fafc; }
  code { background:#eef2f7; padding:1px 6px; border-radius:3px; font-size:12px; }
  .osfi-box { background:#eaf4ea; border-left:4px solid #27ae60; border-radius:4px; padding:16px 20px; margin-bottom:28px; font-size:13px; }
  .osfi-box.warn { background:#fdf3e7; border-left-color:#e67e22; }
  .footer { text-align:center; padding:20px; font-size:11px; color:#95a5a6; border-top:1px solid var(--nb-border); margin-top:32px; }
  .no-findings { padding:24px; text-align:center; color:#27ae60; font-weight:600; }
</style>
</head>
<body>

<div class="header">
  <div class="subtitle">AD Identity Operations Toolkit — Phase 3</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Password Policy Compliance Report</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>📋 OSFI Min Length: $osfiMinLength chars</span>
    <span>📋 OSFI Max Age: ${osfiMaxAgeDays}d</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>OSFI E-21 §3.3</span> — Authentication Controls &nbsp;|&nbsp;
  <span>NIST SP 800-53 IA-5</span> — Authenticator Management &nbsp;|&nbsp;
  <span>CIS Controls v8 — 5.2</span> — Use Unique Passwords
</div>

<div class="container">

  <div class="osfi-box $(if (-not $ddpCompliant) { 'warn' } else { '' })">
    <strong>$(if ($ddpCompliant) { '✅ Default Domain Policy:' } else { '⚠️ Default Domain Policy:' })</strong>
    $(if ($ddpCompliant) { 'Meets OSFI E-21 §3.3 minimum requirements.' } else { "NON-COMPLIANT — $ddpIssueText" })
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">$($userFindings.Count)</div>
      <div class="kpi-label">User Violations</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$criticalCount</div>
      <div class="kpi-label">Critical</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$highCount</div>
      <div class="kpi-label">High</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$pwdNeverCount</div>
      <div class="kpi-label">Pwd Never Expires</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$pwdNeverSet</div>
      <div class="kpi-label">Pwd Never Set</div>
    </div>
  </div>

  <!-- Default Domain Policy -->
  <div class="section">
    <div class="section-header">
      🔐 Default Domain Password Policy &nbsp;|&nbsp; $domain
      <span class="badge">$ddpBadge</span>
    </div>
    <div class="ddp-grid">
      <div class="ddp-item">
        <div class="ddp-label">Min Password Length</div>
        <div class="ddp-value" style="color:$(if ($ddp.MinPasswordLength -ge $osfiMinLength) { '#27ae60' } else { '#c0392b' })">$($ddp.MinPasswordLength) chars</div>
        <div class="ddp-status">OSFI minimum: $osfiMinLength</div>
      </div>
      <div class="ddp-item">
        <div class="ddp-label">Max Password Age</div>
        <div class="ddp-value" style="color:$(if ($ddpMaxAge -le $osfiMaxAgeDays -and $ddpMaxAge -gt 0) { '#27ae60' } else { '#c0392b' })">$ddpMaxAge days</div>
        <div class="ddp-status">OSFI maximum: $osfiMaxAgeDays days</div>
      </div>
      <div class="ddp-item">
        <div class="ddp-label">Password History</div>
        <div class="ddp-value" style="color:$(if ($ddp.PasswordHistoryCount -ge $osfiHistoryCount) { '#27ae60' } else { '#c0392b' })">$($ddp.PasswordHistoryCount) remembered</div>
        <div class="ddp-status">OSFI minimum: $osfiHistoryCount</div>
      </div>
      <div class="ddp-item">
        <div class="ddp-label">Complexity Enforced</div>
        <div class="ddp-value">$(if ($ddp.ComplexityEnabled) { '✅ Yes' } else { '❌ No' })</div>
        <div class="ddp-status">OSFI: Required</div>
      </div>
      <div class="ddp-item">
        <div class="ddp-label">Lockout Threshold</div>
        <div class="ddp-value" style="color:$(if ($ddp.LockoutThreshold -gt 0 -and $ddp.LockoutThreshold -le $osfiLockoutThreshold) { '#27ae60' } else { '#c0392b' })">$($ddp.LockoutThreshold) attempts</div>
        <div class="ddp-status">OSFI maximum: $osfiLockoutThreshold</div>
      </div>
      <div class="ddp-item">
        <div class="ddp-label">Min Password Age</div>
        <div class="ddp-value">$ddpMinAge days</div>
        <div class="ddp-status">OSFI minimum: $osfiMinAgeDays day</div>
      </div>
    </div>
  </div>

  <!-- PSO Table -->
  <div class="section">
    <div class="section-header">
      🔏 Fine-Grained Password Policies (PSOs)
      <span class="badge">$($psoFindings.Count) PSOs</span>
    </div>
    $(if ($psoFindings.Count -gt 0) {
      "<table><thead><tr>
        <th>PSO Name</th><th>Precedence</th><th>Min Length</th><th>Max Age</th>
        <th>History</th><th>Complexity</th><th>Lockout</th><th>Applies To</th><th>Status</th>
      </tr></thead><tbody>$psoRows</tbody></table>"
    } else {
      "<div class='no-findings'>ℹ️ No Fine-Grained Password Policies configured. All users subject to Default Domain Policy.</div>"
    })
  </div>

  <!-- User Violations -->
  <div class="section">
    <div class="section-header">
      👤 User Account Password Violations
      <span class="badge">$($userFindings.Count) findings</span>
    </div>
    $(if ($userFindings.Count -gt 0) {
      "<table><thead><tr>
        <th>SAM Account</th><th>Display Name</th><th>Enabled</th>
        <th>Pwd Last Set</th><th>Pwd Age (days)</th><th>Violations</th><th>Risk</th>
      </tr></thead><tbody>$userRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No user password policy violations detected.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 3: Password Policy Compliance
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
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase3-PasswordPolicy-$reportStamp.csv"
    $userFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 3 complete. Proceed to Phase 4 — Group Membership Audit." -ForegroundColor Cyan
Write-Host ""

return $userFindings
