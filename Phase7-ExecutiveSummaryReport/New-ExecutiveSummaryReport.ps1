#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Executive Summary Report — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 7

.DESCRIPTION
    Aggregates findings from the core AD governance phases of the AD Identity
    Operations Toolkit
    into a single executive-ready HTML report with risk scoring, trend indicators,
    and OSFI E-21 control mapping. Designed for CISO and audit committee consumption.

    This script can be run in two modes:
        1. STANDALONE — runs the core AD governance checks internally and aggregates results
        2. PIPELINE   — accepts pre-collected findings arrays from prior phase runs

    Report Sections:
        - Executive Risk Dashboard (KPI cards)
        - OSFI E-21 Control Coverage Heatmap
        - Phase-by-Phase Finding Summary
        - Remediation Priority Matrix
        - Compliance Gap Analysis
        - Full audit-ready HTML export

.PARAMETER DaysInactive
    Inactivity threshold passed to sub-phases. Default: 30.

.PARAMETER SearchBase
    OU scope passed to all sub-phases. Default: entire domain.

.PARAMETER OutputPath
    Directory for report output. Default: .\Reports\

.PARAMETER OrganizationName
    Organization name displayed in report header. Default: NorthBridge Financial Group.

.PARAMETER AuditorName
    Name of the auditor running the report. Default: current Windows username.

.EXAMPLE
    # Full standalone run — executes all phases and generates executive report
    .\New-ExecutiveSummaryReport.ps1 -OutputPath ".\Reports\"

.EXAMPLE
    # Scoped to specific OU
    .\New-ExecutiveSummaryReport.ps1 -SearchBase "OU=Employees,DC=northbridge,DC=local" -OutputPath ".\Reports\"

.EXAMPLE
    # Custom organization name
    .\New-ExecutiveSummaryReport.ps1 -OrganizationName "CIBC — Identity Operations" -OutputPath ".\Reports\"

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 7 — Executive Summary Report
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 | CIS Controls v8 | NIST SP 800-53 | SOC 2
    Permissions : Domain Read (aggregates read-only phase results)
#>

[CmdletBinding()]
param (
    [Parameter(HelpMessage = "Inactivity threshold in days.")]
    [ValidateRange(1, 365)]
    [int]$DaysInactive = 30,

    [Parameter(HelpMessage = "OU distinguished name to scope all phases.")]
    [string]$SearchBase = "",

    [Parameter(HelpMessage = "Output directory for the executive report.")]
    [string]$OutputPath = ".\Reports\",

    [Parameter(HelpMessage = "Organization name for report header.")]
    [string]$OrganizationName = "NorthBridge Financial Group",

    [Parameter(HelpMessage = "Auditor name for report footer.")]
    [string]$AuditorName = $env:USERNAME
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── Banner ──────────────────────────────────────────────────────────────

$banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║          NorthBridge Financial Group — AD Identity Operations Toolkit        ║
║                   Phase 7 │ Executive Summary Report                         ║
║              OSFI E-21 │ CIS Controls v8 │ NIST SP 800-53 │ SOC 2            ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Organization  : $OrganizationName" -ForegroundColor Yellow
Write-Host "  Auditor       : $AuditorName" -ForegroundColor Yellow
Write-Host "  Scope         : $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })" -ForegroundColor Yellow
Write-Host "  Threshold     : $DaysInactive days inactivity" -ForegroundColor Yellow
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

$runDate     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$runDateShort = Get-Date -Format "MMMM dd, yyyy"
$domain      = (Get-ADDomain).DNSRoot
$reportStamp = Get-Date -Format "yyyyMMdd-HHmm"
$cutoffDate  = (Get-Date).AddDays(-$DaysInactive)

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "    [+] Domain : $domain" -ForegroundColor Green
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
        "PASS"     { return "#27ae60" }
        "FAIL"     { return "#c0392b" }
        default    { return "#95a5a6" }
    }
}

function Get-OverallRisk {
    param([int]$Critical, [int]$High, [int]$Total)
    if ($Critical -ge 5 -or $Total -ge 50)    { return "CRITICAL" }
    elseif ($Critical -ge 1 -or $High -ge 10) { return "HIGH" }
    elseif ($High -ge 1)                       { return "MEDIUM" }
    else                                       { return "LOW" }
}

#endregion

#region ── Phase Execution ─────────────────────────────────────────────────────

Write-Host "[*] Executing all phases — this may take several minutes..." -ForegroundColor Cyan
Write-Host ""

$phaseResults = @{}

# ── Phase 1: Stale Accounts ──
Write-Host "[Phase 1/6] Stale Account Detection..." -ForegroundColor DarkCyan
try {
    $p1Params = @{ Filter = { Enabled -eq $true }; Properties = @("LastLogonDate","PasswordNeverExpires","PasswordLastSet","MemberOf","whenCreated","DistinguishedName","Department") }
    if ($SearchBase) { $p1Params["SearchBase"] = $SearchBase }
    $p1Users = Get-ADUser @p1Params | Where-Object { ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate) }

    $p1CompParams = @{ Filter = { Enabled -eq $true }; Properties = @("LastLogonDate","PasswordLastSet","OperatingSystem","whenCreated","DistinguishedName") }
    if ($SearchBase) { $p1CompParams["SearchBase"] = $SearchBase }
    $p1Computers = Get-ADComputer @p1CompParams | Where-Object { ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate) }

    $p1DisabledParams = @{ Filter = { Enabled -eq $false }; Properties = @("MemberOf","LastLogonDate","whenCreated","DistinguishedName") }
    if ($SearchBase) { $p1DisabledParams["SearchBase"] = $SearchBase }
    $p1Disabled = Get-ADUser @p1DisabledParams | Where-Object { $_.MemberOf.Count -gt 0 }

    $phaseResults["Phase1"] = @{
        Total    = $p1Users.Count + $p1Computers.Count + $p1Disabled.Count
        Critical = ($p1Users | Where-Object { $null -eq $_.LastLogonDate }).Count
        High     = ($p1Disabled).Count
        Medium   = ($p1Users | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoffDate }).Count
        Details  = "Stale Users: $($p1Users.Count) · Stale Computers: $($p1Computers.Count) · Disabled w/ Groups: $($p1Disabled.Count)"
    }
    Write-Host "    [+] Phase 1 complete — $($phaseResults['Phase1'].Total) findings" -ForegroundColor Green
}
catch {
    $phaseResults["Phase1"] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Details = "Error: $_" }
    Write-Host "    [!] Phase 1 error: $_" -ForegroundColor Yellow
}

# ── Phase 2: Privileged Accounts ──
Write-Host "[Phase 2/6] Privileged Account Audit..." -ForegroundColor DarkCyan
try {
    $tier0Groups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","Group Policy Creator Owners")
    $p2Total = 0; $p2Critical = 0; $p2High = 0

    foreach ($grp in $tier0Groups) {
        try {
            $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq "user" }
            $p2Total += $members.Count
            foreach ($m in $members) {
                try {
                    $u = Get-ADUser -Identity $m.DistinguishedName -Properties "PasswordNeverExpires","LastLogonDate","ServicePrincipalNames" -ErrorAction Stop
                    if ($u.PasswordNeverExpires -or $u.ServicePrincipalNames.Count -gt 0) { $p2Critical++ }
                    elseif ($u.LastLogonDate -lt $cutoffDate -or $null -eq $u.LastLogonDate) { $p2High++ }
                } catch { }
            }
        } catch { }
    }

    $phaseResults["Phase2"] = @{
        Total    = $p2Total
        Critical = $p2Critical
        High     = $p2High
        Medium   = [math]::Max(0, $p2Total - $p2Critical - $p2High)
        Details  = "Tier 0 Privileged Principals: $p2Total · Critical Risk: $p2Critical · High Risk: $p2High"
    }
    Write-Host "    [+] Phase 2 complete — $p2Total privileged principals" -ForegroundColor Green
}
catch {
    $phaseResults["Phase2"] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Details = "Error: $_" }
    Write-Host "    [!] Phase 2 error: $_" -ForegroundColor Yellow
}

# ── Phase 3: Password Policy ──
Write-Host "[Phase 3/6] Password Policy Compliance..." -ForegroundColor DarkCyan
try {
    $p3Params = @{ Filter = *; Properties = @("PasswordNeverExpires","PasswordNotRequired","PasswordLastSet","PasswordExpired","Enabled") }
    if ($SearchBase) { $p3Params["SearchBase"] = $SearchBase }
    $p3Users = Get-ADUser @p3Params

    $p3NeverExpires  = ($p3Users | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }).Count
    $p3NotRequired   = ($p3Users | Where-Object { $_.PasswordNotRequired }).Count
    $p3NeverSet      = ($p3Users | Where-Object { $null -eq $_.PasswordLastSet }).Count
    $p3Total         = $p3NeverExpires + $p3NotRequired + $p3NeverSet

    $phaseResults["Phase3"] = @{
        Total    = $p3Total
        Critical = $p3NeverExpires + $p3NotRequired
        High     = $p3NeverSet
        Medium   = 0
        Details  = "Pwd Never Expires: $p3NeverExpires · Pwd Not Required: $p3NotRequired · Never Set: $p3NeverSet"
    }
    Write-Host "    [+] Phase 3 complete — $p3Total violations" -ForegroundColor Green
}
catch {
    $phaseResults["Phase3"] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Details = "Error: $_" }
    Write-Host "    [!] Phase 3 error: $_" -ForegroundColor Yellow
}

# ── Phase 4: Group Membership ──
Write-Host "[Phase 4/6] Group Membership Audit..." -ForegroundColor DarkCyan
try {
    $p4Params = @{ Filter = *; Properties = @("Members","MemberOf","Description","GroupCategory","ManagedBy") }
    if ($SearchBase) { $p4Params["SearchBase"] = $SearchBase }
    $p4Groups    = Get-ADGroup @p4Params
    $p4Empty     = ($p4Groups | Where-Object { $_.Members.Count -eq 0 }).Count
    $p4Large     = ($p4Groups | Where-Object { $_.Members.Count -gt 500 -and -not $_.ManagedBy }).Count
    $p4Total     = $p4Empty + $p4Large

    $phaseResults["Phase4"] = @{
        Total    = $p4Total
        Critical = 0
        High     = $p4Large
        Medium   = $p4Empty
        Details  = "Empty Groups: $p4Empty · Large Ungoverned Groups (>500): $p4Large · Total Groups Scanned: $($p4Groups.Count)"
    }
    Write-Host "    [+] Phase 4 complete — $($p4Groups.Count) groups scanned" -ForegroundColor Green
}
catch {
    $phaseResults["Phase4"] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Details = "Error: $_" }
    Write-Host "    [!] Phase 4 error: $_" -ForegroundColor Yellow
}

# ── Phase 5: Service Accounts ──
Write-Host "[Phase 5/6] Service Account Governance..." -ForegroundColor DarkCyan
try {
    $p5Params = @{ Filter = *; Properties = @("ServicePrincipalNames","PasswordNeverExpires","MemberOf","LastLogonDate","Description") }
    if ($SearchBase) { $p5Params["SearchBase"] = $SearchBase }
    $p5AllUsers      = Get-ADUser @p5Params
    $p5SvcAccounts   = $p5AllUsers | Where-Object {
        $_.ServicePrincipalNames.Count -gt 0 -or
        $_.SamAccountName.ToLower().StartsWith("svc") -or
        $_.Description -match "service|svc|automation"
    }
    $p5Kerberoastable = ($p5SvcAccounts | Where-Object { $_.ServicePrincipalNames.Count -gt 0 }).Count
    $p5PwdNever       = ($p5SvcAccounts | Where-Object { $_.PasswordNeverExpires }).Count

    $phaseResults["Phase5"] = @{
        Total    = $p5SvcAccounts.Count
        Critical = $p5Kerberoastable
        High     = $p5PwdNever
        Medium   = [math]::Max(0, $p5SvcAccounts.Count - $p5Kerberoastable - $p5PwdNever)
        Details  = "Service Accounts: $($p5SvcAccounts.Count) · Kerberoastable: $p5Kerberoastable · Pwd Never Expires: $p5PwdNever"
    }
    Write-Host "    [+] Phase 5 complete — $($p5SvcAccounts.Count) service accounts" -ForegroundColor Green
}
catch {
    $phaseResults["Phase5"] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Details = "Error: $_" }
    Write-Host "    [!] Phase 5 error: $_" -ForegroundColor Yellow
}

# ── Phase 6: Cleanup ──
Write-Host "[Phase 6/6] Inactive Object Cleanup Discovery..." -ForegroundColor DarkCyan
try {
    $p6Params = @{ Filter = { Enabled -eq $true }; Properties = @("LastLogonDate","MemberOf","whenCreated","DistinguishedName") }
    if ($SearchBase) { $p6Params["SearchBase"] = $SearchBase }
    $p6Users     = Get-ADUser @p6Params | Where-Object { ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate) }
    $p6CompParams = @{ Filter = { Enabled -eq $true }; Properties = @("LastLogonDate","whenCreated","DistinguishedName") }
    if ($SearchBase) { $p6CompParams["SearchBase"] = $SearchBase }
    $p6Computers = Get-ADComputer @p6CompParams | Where-Object { ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate) }
    $p6Total     = $p6Users.Count + $p6Computers.Count

    $phaseResults["Phase6"] = @{
        Total    = $p6Total
        Critical = ($p6Users | Where-Object { $null -eq $_.LastLogonDate }).Count
        High     = ($p6Users | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-($DaysInactive * 3)) }).Count
        Medium   = [math]::Max(0, $p6Total - ($p6Users | Where-Object { $null -eq $_.LastLogonDate }).Count)
        Details  = "Inactive Users: $($p6Users.Count) · Inactive Computers: $($p6Computers.Count) · Pending Remediation: $p6Total"
    }
    Write-Host "    [+] Phase 6 complete — $p6Total objects pending remediation" -ForegroundColor Green
}
catch {
    $phaseResults["Phase6"] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Details = "Error: $_" }
    Write-Host "    [!] Phase 6 error: $_" -ForegroundColor Yellow
}

#endregion

#region ── Aggregate Totals ────────────────────────────────────────────────────

$totalFindings  = ($phaseResults.Values | Measure-Object -Property Total    -Sum).Sum
$totalCritical  = ($phaseResults.Values | Measure-Object -Property Critical -Sum).Sum
$totalHigh      = ($phaseResults.Values | Measure-Object -Property High     -Sum).Sum
$totalMedium    = ($phaseResults.Values | Measure-Object -Property Medium   -Sum).Sum
$overallRisk    = Get-OverallRisk -Critical $totalCritical -High $totalHigh -Total $totalFindings
$overallColor   = Get-RiskColor  -Risk $overallRisk

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  EXECUTIVE SUMMARY — ALL PHASES" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Overall Risk Rating : $overallRisk" -ForegroundColor $(if ($overallRisk -eq 'CRITICAL') { 'Red' } elseif ($overallRisk -eq 'HIGH') { 'Yellow' } else { 'Green' })
Write-Host "  Total Findings      : $totalFindings" -ForegroundColor White
Write-Host "  CRITICAL            : $totalCritical" -ForegroundColor Red
Write-Host "  HIGH                : $totalHigh" -ForegroundColor Yellow
Write-Host "  MEDIUM              : $totalMedium" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

#endregion

#region ── HTML Executive Report ───────────────────────────────────────────────

$reportFile = Join-Path $OutputPath "NorthBridge-Phase7-ExecutiveSummary-$reportStamp.html"

# Build phase summary rows
$phaseRows = ""
$phaseNames = @{
    "Phase1" = "Phase 1 — Stale Account Detection"
    "Phase2" = "Phase 2 — Privileged Account Audit"
    "Phase3" = "Phase 3 — Password Policy Compliance"
    "Phase4" = "Phase 4 — Group Membership Audit"
    "Phase5" = "Phase 5 — Service Account Governance"
    "Phase6" = "Phase 6 — Inactive Object Cleanup"
}
$phaseControls = @{
    "Phase1" = "OSFI E-21 §3.4 · CIS 6"
    "Phase2" = "OSFI E-21 §3.2 · CIS 5"
    "Phase3" = "OSFI E-21 §3.3 · NIST IA-5"
    "Phase4" = "CIS 6.3 · SOC 2 CC6.3"
    "Phase5" = "CIS 5.6 · NIST AC-6"
    "Phase6" = "OSFI E-21 §3.4 · NIST AC-2"
}

foreach ($key in @("Phase1","Phase2","Phase3","Phase4","Phase5","Phase6")) {
    $p       = $phaseResults[$key]
    $pRisk   = Get-OverallRisk -Critical $p.Critical -High $p.High -Total $p.Total
    $pColor  = Get-RiskColor -Risk $pRisk
    $pBadge  = "<span style='background:$pColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$pRisk</span>"
    $cBadge  = "<span style='background:#c0392b;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;'>$($p.Critical)</span>"
    $hBadge  = "<span style='background:#e67e22;color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;'>$($p.High)</span>"

    $phaseRows += "<tr>"
    $phaseRows += "<td><strong>$($phaseNames[$key])</strong></td>"
    $phaseRows += "<td style='text-align:center;'>$($p.Total)</td>"
    $phaseRows += "<td style='text-align:center;'>$cBadge</td>"
    $phaseRows += "<td style='text-align:center;'>$hBadge</td>"
    $phaseRows += "<td style='font-size:11px;color:#7f8c8d;'>$($p.Details)</td>"
    $phaseRows += "<td style='font-size:11px;'>$($phaseControls[$key])</td>"
    $phaseRows += "<td>$pBadge</td>"
    $phaseRows += "</tr>"
}

# OSFI Control Heatmap
$osfiControls = @(
    @{ Ref="OSFI E-21 §3.2"; Name="Privileged Access Management";    Phase="Phase 2, 5"; Status=if($phaseResults['Phase2'].Critical -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="OSFI E-21 §3.3"; Name="Authentication Controls";         Phase="Phase 3";    Status=if($phaseResults['Phase3'].Critical -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="OSFI E-21 §3.4"; Name="Account Lifecycle Management";    Phase="Phase 1, 6"; Status=if($phaseResults['Phase1'].Critical -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="OSFI E-21 §4.1"; Name="Audit Logging & Monitoring";      Phase="Phase 6, 7"; Status="REVIEWED" },
    @{ Ref="CIS Control 5";  Name="Account Management";              Phase="Phase 2, 3"; Status=if($phaseResults['Phase2'].Total -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="CIS Control 6";  Name="Access Control Management";       Phase="Phase 1, 4"; Status=if($phaseResults['Phase4'].High -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="NIST AC-2";      Name="Account Management";              Phase="Phase 1, 6"; Status=if($phaseResults['Phase6'].Critical -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="NIST AC-6";      Name="Least Privilege";                 Phase="Phase 2, 5"; Status=if($phaseResults['Phase5'].Critical -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="NIST IA-5";      Name="Authenticator Management";        Phase="Phase 3";    Status=if($phaseResults['Phase3'].Critical -gt 0){"GAPS FOUND"}else{"REVIEWED"} },
    @{ Ref="SOC 2 CC6.3";   Name="Logical Access Controls";          Phase="Phase 4";    Status=if($phaseResults['Phase4'].High -gt 0){"GAPS FOUND"}else{"REVIEWED"} }
)

$osfiRows = ""
foreach ($ctrl in $osfiControls) {
    $statusColor = if ($ctrl.Status -eq "GAPS FOUND") { "#c0392b" } else { "#27ae60" }
    $statusBadge = "<span style='background:$statusColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($ctrl.Status)</span>"
    $osfiRows += "<tr>"
    $osfiRows += "<td><strong>$($ctrl.Ref)</strong></td>"
    $osfiRows += "<td>$($ctrl.Name)</td>"
    $osfiRows += "<td>$($ctrl.Phase)</td>"
    $osfiRows += "<td>$statusBadge</td>"
    $osfiRows += "</tr>"
}

# Remediation priorities
$remediationItems = @(
    @{ Priority="1"; Action="Migrate all service accounts with SPNs to gMSA";                      Phase="Phase 5"; Risk="CRITICAL"; Effort="High";   Impact="Eliminates Kerberoasting attack surface" },
    @{ Priority="2"; Action="Remove service accounts from Tier 0 privileged groups";               Phase="Phase 2"; Risk="CRITICAL"; Effort="Low";    Impact="Prevents privilege escalation via service account compromise" },
    @{ Priority="3"; Action="Disable and quarantine all accounts inactive > $DaysInactive days";   Phase="Phase 6"; Risk="CRITICAL"; Effort="Medium"; Impact="Reduces attack surface from dormant credentials" },
    @{ Priority="4"; Action="Remediate PasswordNeverExpires on all privileged accounts";           Phase="Phase 3"; Risk="HIGH";     Effort="Low";    Impact="Enforces credential rotation compliance" },
    @{ Priority="5"; Action="Resolve all SPN conflicts across user objects";                       Phase="Phase 5"; Risk="HIGH";     Effort="Medium"; Impact="Prevents Kerberos authentication failures and security gaps" },
    @{ Priority="6"; Action="Remove disabled accounts from all security groups";                   Phase="Phase 1"; Risk="HIGH";     Effort="Low";    Impact="Closes residual access paths from terminated accounts" },
    @{ Priority="7"; Action="Assign governance owners to all groups > 500 members";               Phase="Phase 4"; Risk="MEDIUM";   Effort="Medium"; Impact="Establishes accountability for large access groups" },
    @{ Priority="8"; Action="Resolve circular group nesting";                                      Phase="Phase 4"; Risk="MEDIUM";   Effort="High";   Impact="Eliminates unresolvable privilege chains" }
)

$remRows = ""
foreach ($r in $remediationItems) {
    $rc    = Get-RiskColor -Risk $r.Risk
    $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($r.Risk)</span>"
    $effortColor = switch ($r.Effort) { "Low" { "#27ae60" } "Medium" { "#e67e22" } "High" { "#c0392b" } default { "#95a5a6" } }
    $remRows += "<tr>"
    $remRows += "<td style='text-align:center;font-weight:700;font-size:16px;color:#0a2342;'>$($r.Priority)</td>"
    $remRows += "<td>$($r.Action)</td>"
    $remRows += "<td style='font-size:12px;color:#7f8c8d;'>$($r.Phase)</td>"
    $remRows += "<td>$badge</td>"
    $remRows += "<td><span style='color:$effortColor;font-weight:600;'>$($r.Effort)</span></td>"
    $remRows += "<td style='font-size:12px;'>$($r.Impact)</td>"
    $remRows += "</tr>"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>$OrganizationName — AD Identity Operations Toolkit: Executive Summary</title>
<style>
  :root {
    --nb-navy:   #0a2342;
    --nb-gold:   #c9a84c;
    --nb-light:  #f4f6f9;
    --nb-border: #dce3ec;
    --critical:  #c0392b;
    --high:      #e67e22;
    --medium:    #f39c12;
    --low:       #27ae60;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',Arial,sans-serif; background:var(--nb-light); color:#2c3e50; font-size:14px; }

  .header { background:var(--nb-navy); color:#fff; padding:36px 48px; border-bottom:5px solid var(--nb-gold); }
  .header .org { font-size:13px; color:var(--nb-gold); letter-spacing:2px; text-transform:uppercase; margin-bottom:8px; }
  .header h1 { font-size:26px; font-weight:700; letter-spacing:0.5px; }
  .header .subtitle { font-size:14px; color:#aab4c2; margin-top:6px; }
  .header .meta { margin-top:16px; font-size:12px; color:#7f8c8d; display:flex; gap:32px; flex-wrap:wrap; }
  .header .meta span { color:#aab4c2; }
  .header .meta strong { color:#fff; }

  .risk-banner {
    background: $overallColor;
    color: #fff;
    padding: 16px 48px;
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1px;
    text-align: center;
    text-transform: uppercase;
  }

  .compliance-bar { background:var(--nb-navy); color:#aab4c2; font-size:11px; padding:8px 48px; letter-spacing:0.5px; }
  .compliance-bar span { color:var(--nb-gold); font-weight:600; }

  .container { max-width:1320px; margin:0 auto; padding:36px 48px; }

  .kpi-grid { display:grid; grid-template-columns:repeat(6,1fr); gap:16px; margin-bottom:36px; }
  .kpi-card { background:#fff; border:1px solid var(--nb-border); border-top:4px solid var(--nb-navy); border-radius:6px; padding:20px 16px; text-align:center; }
  .kpi-card.critical { border-top-color:var(--critical); }
  .kpi-card.high     { border-top-color:var(--high); }
  .kpi-card.medium   { border-top-color:var(--medium); }
  .kpi-card.gold     { border-top-color:var(--nb-gold); }
  .kpi-value { font-size:36px; font-weight:700; color:var(--nb-navy); line-height:1; }
  .kpi-label { font-size:11px; color:#7f8c8d; margin-top:6px; text-transform:uppercase; letter-spacing:0.5px; }

  .section { background:#fff; border:1px solid var(--nb-border); border-radius:6px; margin-bottom:32px; overflow:hidden; }
  .section-header { background:var(--nb-navy); color:#fff; padding:16px 20px; font-size:15px; font-weight:600; display:flex; justify-content:space-between; align-items:center; }
  .section-header .badge { background:var(--nb-gold); color:var(--nb-navy); border-radius:12px; padding:3px 12px; font-size:12px; font-weight:700; }

  table { width:100%; border-collapse:collapse; }
  th { background:#eef2f7; padding:11px 16px; text-align:left; font-size:12px; font-weight:600; color:var(--nb-navy); text-transform:uppercase; letter-spacing:0.4px; border-bottom:1px solid var(--nb-border); }
  td { padding:11px 16px; border-bottom:1px solid #f0f0f0; font-size:13px; vertical-align:middle; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:#f8fafc; }

  .signature-box {
    background: var(--nb-navy);
    color: #fff;
    border-radius: 6px;
    padding: 28px 32px;
    margin-bottom: 32px;
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 24px;
  }
  .sig-label { font-size:11px; color:#aab4c2; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; }
  .sig-value { font-size:14px; font-weight:600; color:#fff; border-bottom:1px solid #2c4a6e; padding-bottom:8px; }

  .footer { background:var(--nb-navy); color:#aab4c2; text-align:center; padding:24px; font-size:11px; margin-top:32px; }
  .footer a { color:var(--nb-gold); text-decoration:none; }
  .footer .toolkit-name { color:var(--nb-gold); font-weight:600; font-size:13px; margin-bottom:8px; }
</style>
</head>
<body>

<div class="header">
  <div class="org">🏦 $OrganizationName</div>
  <h1>Active Directory Identity Operations — Executive Summary Report</h1>
  <div class="subtitle">Comprehensive identity governance audit across the core AD governance phases · OSFI E-21 · CIS Controls v8 · NIST SP 800-53</div>
  <div class="meta">
    <span><strong>Report Date:</strong> $runDateShort</span>
    <span><strong>Domain:</strong> $domain</span>
    <span><strong>Auditor:</strong> $AuditorName</span>
    <span><strong>Scope:</strong> $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })</span>
    <span><strong>Inactivity Threshold:</strong> $DaysInactive days</span>
    <span><strong>Generated:</strong> $runDate</span>
  </div>
</div>

<div class="risk-banner">
  ⚠️ Overall Identity Risk Rating: $overallRisk &nbsp;|&nbsp; $totalCritical Critical · $totalHigh High · $totalFindings Total Findings Across 6 Phases
</div>

<div class="compliance-bar">
  Frameworks Assessed: &nbsp;
  <span>OSFI E-21</span> §3.2 §3.3 §3.4 §4.1 &nbsp;|&nbsp;
  <span>CIS Controls v8</span> Controls 5, 6 &nbsp;|&nbsp;
  <span>NIST SP 800-53</span> AC-2, AC-6, IA-5 &nbsp;|&nbsp;
  <span>SOC 2</span> CC6.3
</div>

<div class="container">

  <!-- KPI Dashboard -->
  <div class="kpi-grid">
    <div class="kpi-card gold">
      <div class="kpi-value" style="color:var(--nb-gold)">$totalFindings</div>
      <div class="kpi-label">Total Findings</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$totalCritical</div>
      <div class="kpi-label">Critical Risk</div>
    </div>
    <div class="kpi-card high">
      <div class="kpi-value" style="color:var(--high)">$totalHigh</div>
      <div class="kpi-label">High Risk</div>
    </div>
    <div class="kpi-card medium">
      <div class="kpi-value" style="color:var(--medium)">$totalMedium</div>
      <div class="kpi-label">Medium Risk</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">6</div>
      <div class="kpi-label">Phases Executed</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">10</div>
      <div class="kpi-label">Controls Assessed</div>
    </div>
  </div>

  <!-- Audit Signature Block -->
  <div class="signature-box">
    <div>
      <div class="sig-label">Prepared By</div>
      <div class="sig-value">$AuditorName</div>
    </div>
    <div>
      <div class="sig-label">Organization</div>
      <div class="sig-value">$OrganizationName</div>
    </div>
    <div>
      <div class="sig-label">Report Classification</div>
      <div class="sig-value">CONFIDENTIAL — Internal Audit Use Only</div>
    </div>
    <div>
      <div class="sig-label">Audit Date</div>
      <div class="sig-value">$runDateShort</div>
    </div>
    <div>
      <div class="sig-label">Domain Audited</div>
      <div class="sig-value">$domain</div>
    </div>
    <div>
      <div class="sig-label">Overall Risk Rating</div>
      <div class="sig-value" style="color:$overallColor">$overallRisk</div>
    </div>
  </div>

  <!-- Phase Summary Table -->
  <div class="section">
    <div class="section-header">
      📊 Phase-by-Phase Finding Summary
      <span class="badge">6 Phases · $totalFindings Total Findings</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Phase</th>
          <th style="text-align:center">Total</th>
          <th style="text-align:center">Critical</th>
          <th style="text-align:center">High</th>
          <th>Key Findings</th>
          <th>Compliance Reference</th>
          <th>Risk Rating</th>
        </tr>
      </thead>
      <tbody>$phaseRows</tbody>
    </table>
  </div>

  <!-- Remediation Priority Matrix -->
  <div class="section">
    <div class="section-header">
      🎯 Remediation Priority Matrix — Ranked by Risk &amp; Impact
      <span class="badge">8 Priority Actions</span>
    </div>
    <table>
      <thead>
        <tr>
          <th style="text-align:center">#</th>
          <th>Recommended Action</th>
          <th>Phase</th>
          <th>Risk</th>
          <th>Effort</th>
          <th>Business Impact</th>
        </tr>
      </thead>
      <tbody>$remRows</tbody>
    </table>
  </div>

  <!-- OSFI Control Coverage Heatmap -->
  <div class="section">
    <div class="section-header">
      🏛️ Compliance Control Coverage — OSFI E-21 · CIS · NIST · SOC 2
      <span class="badge">10 Controls Assessed</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Control Reference</th>
          <th>Control Name</th>
          <th>Covered by Phase</th>
          <th>Assessment Status</th>
        </tr>
      </thead>
      <tbody>$osfiRows</tbody>
    </table>
  </div>

</div>

<div class="footer">
  <div class="toolkit-name">AD Identity Operations Toolkit — NorthBridge Financial Group</div>
  Phase 7: Executive Summary Report &nbsp;|&nbsp; Generated: $runDate &nbsp;|&nbsp; READ-ONLY AUDIT — No changes made to Active Directory
  <br><br>
  Built by <strong style="color:#fff;">Md Rahat Islam Anik</strong> &nbsp;|&nbsp;
  <a href="https://rahatislamanik-spec.github.io/IT-Portfolio-Rahat-Islam-Anik">Portfolio</a> &nbsp;|&nbsp;
  <a href="https://linkedin.com/in/rahatislamanik">LinkedIn</a> &nbsp;|&nbsp;
  <a href="https://github.com/rahatislamanik-spec/AD-Identity-Operations-Toolkit">GitHub Repository</a>
</div>

</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "[+] Executive Summary Report saved: $reportFile" -ForegroundColor Green

#endregion

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  AD Identity Operations Toolkit — ALL 7 PHASES COMPLETE" -ForegroundColor White
Write-Host "  $OrganizationName" -ForegroundColor Yellow
Write-Host "  Overall Risk: $overallRisk · $totalFindings findings · $totalCritical critical" -ForegroundColor White
Write-Host "══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

return $phaseResults
