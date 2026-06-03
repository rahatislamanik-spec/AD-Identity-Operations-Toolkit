#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Inactive Object Cleanup Workflow — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 6

.DESCRIPTION
    Implements the full disable → move → delete remediation pipeline for inactive
    AD objects with staged execution, mandatory dry-run preview, and a structured
    audit trail for compliance review.

    Pipeline Stages:
        Stage 1 — Discovery    : Identify inactive users and computers
        Stage 2 — Risk Class   : Classify by risk tier and inactivity severity
        Stage 3 — Dry-Run      : Preview all actions before execution
        Stage 4 — Disable      : Disable accounts and stamp description with date
        Stage 5 — Quarantine   : Move disabled objects to quarantine OU
        Stage 6 — Delete       : Remove objects in quarantine beyond hold period

    Safety Controls:
        - Dry-run mode is DEFAULT — destructive stages require -ExecuteDisable,
          -ExecuteMove, or -ExecuteDelete flags explicitly
        - All actions logged to structured CSV audit trail
        - Privileged accounts (Domain Admins etc.) are automatically excluded
        - 30-day quarantine hold enforced before deletion

.PARAMETER DaysInactive
    Days since last logon to flag as inactive. Default: 30.

.PARAMETER QuarantineHoldDays
    Days an object must remain in quarantine OU before deletion. Default: 30.

.PARAMETER QuarantineOU
    Distinguished name of the quarantine OU. Required for -ExecuteMove.

.PARAMETER SearchBase
    OU to scope discovery. Default: entire domain.

.PARAMETER ExecuteDisable
    Switch to execute the disable stage. Default: dry-run only.

.PARAMETER ExecuteMove
    Switch to execute the quarantine move stage. Requires -QuarantineOU.

.PARAMETER ExecuteDelete
    Switch to execute the delete stage. Requires -QuarantineOU. USE WITH CAUTION.

.PARAMETER GenerateReport
    Switch to produce an HTML report.

.PARAMETER OutputPath
    Directory path for report and audit log output. Default: .\Reports\

.EXAMPLE
    # Dry-run — preview all findings only
    .\Invoke-InactiveObjectCleanup.ps1 -DaysInactive 30

.EXAMPLE
    # Execute disable stage only
    .\Invoke-InactiveObjectCleanup.ps1 -DaysInactive 30 -ExecuteDisable -GenerateReport

.EXAMPLE
    # Execute disable + move to quarantine
    .\Invoke-InactiveObjectCleanup.ps1 -DaysInactive 30 -ExecuteDisable -ExecuteMove `
        -QuarantineOU "OU=Quarantine,DC=northbridge,DC=local" -GenerateReport

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 6 — Inactive Object Cleanup Workflow
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : OSFI E-21 §3.4 | CIS Controls v8 — Control 6 | NIST SP 800-53 AC-2
    Permissions : Disable/Move/Delete require Domain Admin or delegated OU permissions
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Days since last logon to flag as inactive.")]
    [ValidateRange(1, 365)]
    [int]$DaysInactive = 30,

    [Parameter(HelpMessage = "Days an object must remain in quarantine before deletion.")]
    [ValidateRange(1, 365)]
    [int]$QuarantineHoldDays = 30,

    [Parameter(HelpMessage = "Distinguished name of the quarantine OU.")]
    [string]$QuarantineOU = "",

    [Parameter(HelpMessage = "OU distinguished name to scope discovery.")]
    [string]$SearchBase = "",

    [Parameter(HelpMessage = "Execute the disable stage.")]
    [switch]$ExecuteDisable,

    [Parameter(HelpMessage = "Execute the quarantine move stage.")]
    [switch]$ExecuteMove,

    [Parameter(HelpMessage = "Execute the delete stage — USE WITH CAUTION.")]
    [switch]$ExecuteDelete,

    [Parameter(HelpMessage = "Generate HTML report.")]
    [switch]$GenerateReport,

    [Parameter(HelpMessage = "Output directory for reports and audit logs.")]
    [string]$OutputPath = ".\Reports\"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region ── Banner ──────────────────────────────────────────────────────────────

$banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║          NorthBridge Financial Group — AD Identity Operations Toolkit        ║
║                Phase 6 │ Inactive Object Cleanup Workflow                    ║
║              OSFI E-21 §3.4 │ CIS Controls v8 — 6 │ NIST 800-53 AC-2       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan

$executionMode = "DRY RUN"
if ($ExecuteDelete)  { $executionMode = "LIVE — DISABLE + MOVE + DELETE" }
elseif ($ExecuteMove){ $executionMode = "LIVE — DISABLE + MOVE TO QUARANTINE" }
elseif ($ExecuteDisable) { $executionMode = "LIVE — DISABLE ONLY" }

Write-Host "  Inactivity Threshold  : $DaysInactive days" -ForegroundColor Yellow
Write-Host "  Quarantine Hold       : $QuarantineHoldDays days" -ForegroundColor Yellow
Write-Host "  Execution Mode        : $executionMode" -ForegroundColor $(if ($executionMode -eq "DRY RUN") { 'Magenta' } else { 'Red' })
if ($ExecuteDelete -or $ExecuteMove) {
    Write-Host "  Quarantine OU         : $(if ($QuarantineOU) { $QuarantineOU } else { 'NOT SET — required for move/delete' })" -ForegroundColor Yellow
}
Write-Host ""

if (($ExecuteMove -or $ExecuteDelete) -and -not $QuarantineOU) {
    Write-Host "[!] FATAL: -QuarantineOU is required when using -ExecuteMove or -ExecuteDelete." -ForegroundColor Red
    exit 1
}

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

$cutoffDate     = (Get-Date).AddDays(-$DaysInactive)
$quarantineCutoff = (Get-Date).AddDays(-$QuarantineHoldDays)
$runDate        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$domain         = (Get-ADDomain).DNSRoot
$reportStamp    = Get-Date -Format "yyyyMMdd-HHmm"

# Audit log setup
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$auditLog = Join-Path $OutputPath "NorthBridge-Phase6-AuditLog-$reportStamp.csv"
$auditEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-AuditEntry {
    param([string]$ObjectType, [string]$SamAccountName, [string]$Action, [string]$Result, [string]$Details)
    $entry = [PSCustomObject]@{
        Timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        ObjectType     = $ObjectType
        SamAccountName = $SamAccountName
        Action         = $Action
        Result         = $Result
        Details        = $Details
        ExecutedBy     = $env:USERNAME
        Domain         = $domain
    }
    $auditEntries.Add($entry)
}

# Groups that are always excluded from cleanup
$protectedGroups = @(
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Backup Operators"
)

function Test-IsProtected {
    param($ADObject)
    foreach ($groupDN in $ADObject.MemberOf) {
        $gName = $groupDN -replace '^CN=([^,]+),.+$', '$1'
        if ($protectedGroups -contains $gName) { return $true }
    }
    return $false
}

Write-Host "    [+] Domain           : $domain" -ForegroundColor Green
Write-Host "    [+] Cutoff date      : $($cutoffDate.ToString('yyyy-MM-dd'))" -ForegroundColor Green
Write-Host "    [+] Audit log        : $auditLog" -ForegroundColor Green
Write-Host ""

#endregion

#region ── Helper ──────────────────────────────────────────────────────────────

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

#region ── Stage 1: Discovery ──────────────────────────────────────────────────

Write-Host "[Stage 1/4] Discovering inactive objects..." -ForegroundColor Cyan

$userParams = @{
    Filter     = { Enabled -eq $true }
    Properties = @(
        "LastLogonDate", "PasswordLastSet", "MemberOf", "Department",
        "Description", "whenCreated", "DistinguishedName", "Title"
    )
}
if ($SearchBase) { $userParams["SearchBase"] = $SearchBase }

$computerParams = @{
    Filter     = { Enabled -eq $true }
    Properties = @(
        "LastLogonDate", "PasswordLastSet", "OperatingSystem",
        "whenCreated", "DistinguishedName"
    )
}
if ($SearchBase) { $computerParams["SearchBase"] = $SearchBase }

$inactiveUsers = Get-ADUser @userParams | Where-Object {
    (($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate)) -and
    (-not (Test-IsProtected -ADObject $_))
}

$inactiveComputers = Get-ADComputer @computerParams | Where-Object {
    ($_.LastLogonDate -lt $cutoffDate) -or ($null -eq $_.LastLogonDate)
}

Write-Host "    [+] Inactive users found     : $($inactiveUsers.Count)" -ForegroundColor Yellow
Write-Host "    [+] Inactive computers found : $($inactiveComputers.Count)" -ForegroundColor Yellow

#endregion

#region ── Stage 2: Risk Classification ───────────────────────────────────────

Write-Host "[Stage 2/4] Classifying by risk tier..." -ForegroundColor Cyan

$discoveryResults = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($obj in @($inactiveUsers) + @($inactiveComputers)) {
    $isUser     = $obj.PSObject.TypeNames -match "ADUser"
    $objType    = if ($isUser) { "User" } else { "Computer" }
    $daysSince  = if ($obj.LastLogonDate) {
        [math]::Round(((Get-Date) - $obj.LastLogonDate).TotalDays)
    } else { 999 }

    $ratio     = $daysSince / $DaysInactive
    $riskLevel = if ($ratio -ge 6)     { "CRITICAL" }
                 elseif ($ratio -ge 3)  { "HIGH" }
                 elseif ($ratio -ge 1)  { "MEDIUM" }
                 else                   { "LOW" }

    $discoveryResults.Add([PSCustomObject]@{
        ObjectType     = $objType
        SamAccountName = $obj.SamAccountName
        DisplayName    = $obj.Name
        LastLogonDate  = if ($obj.LastLogonDate) { $obj.LastLogonDate.ToString("yyyy-MM-dd") } else { "NEVER" }
        DaysSinceLogon = $daysSince
        Department     = if ($isUser) { $obj.Department } else { $obj.OperatingSystem }
        WhenCreated    = $obj.whenCreated.ToString("yyyy-MM-dd")
        OU             = ($obj.DistinguishedName -replace '^CN=[^,]+,', '')
        DN             = $obj.DistinguishedName
        RiskLevel      = $riskLevel
        ProposedAction = "Disable → Quarantine → Delete (after ${QuarantineHoldDays}d hold)"
        ActionStatus   = "PENDING"
    })
}

$criticalCount = ($discoveryResults | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($discoveryResults | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($discoveryResults | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count

Write-Host "    [+] CRITICAL : $criticalCount" -ForegroundColor Red
Write-Host "    [+] HIGH     : $highCount" -ForegroundColor Yellow
Write-Host "    [+] MEDIUM   : $mediumCount" -ForegroundColor Cyan

#endregion

#region ── Stage 3: Dry-Run Preview ───────────────────────────────────────────

Write-Host ""
Write-Host "[Stage 3/4] Dry-run preview — proposed actions:" -ForegroundColor Cyan
Write-Host ""

$discoveryResults | Format-Table ObjectType, SamAccountName, LastLogonDate, DaysSinceLogon, RiskLevel, ProposedAction -AutoSize

if (-not $ExecuteDisable -and -not $ExecuteMove -and -not $ExecuteDelete) {
    Write-Host "[DRY RUN COMPLETE] No changes made. Add -ExecuteDisable to begin remediation." -ForegroundColor Magenta
}

#endregion

#region ── Stage 4: Execute Disable ───────────────────────────────────────────

$disabledCount = 0
$disableErrors = 0

if ($ExecuteDisable) {
    Write-Host "[Stage 4/4] Executing DISABLE stage..." -ForegroundColor Red
    Write-Host ""

    foreach ($item in $discoveryResults) {
        try {
            $stampDesc = "DISABLED by AD-Identity-Toolkit on $(Get-Date -Format 'yyyy-MM-dd') — Inactive > $DaysInactive days"

            if ($item.ObjectType -eq "User") {
                Disable-ADAccount -Identity $item.DN -ErrorAction Stop
                Set-ADUser -Identity $item.DN -Description $stampDesc -ErrorAction Stop
            } else {
                Disable-ADAccount -Identity $item.DN -ErrorAction Stop
                Set-ADComputer -Identity $item.DN -Description $stampDesc -ErrorAction Stop
            }

            $item.ActionStatus = "DISABLED"
            $disabledCount++
            Write-Host "    [+] Disabled: $($item.SamAccountName)" -ForegroundColor Green
            Write-AuditEntry -ObjectType $item.ObjectType -SamAccountName $item.SamAccountName `
                -Action "Disable" -Result "Success" -Details $stampDesc
        }
        catch {
            $item.ActionStatus = "DISABLE FAILED"
            $disableErrors++
            Write-Host "    [!] Failed to disable: $($item.SamAccountName) — $_" -ForegroundColor Red
            Write-AuditEntry -ObjectType $item.ObjectType -SamAccountName $item.SamAccountName `
                -Action "Disable" -Result "Failed" -Details $_
        }
    }

    Write-Host ""
    Write-Host "    [+] Disabled successfully : $disabledCount" -ForegroundColor Green
    Write-Host "    [!] Disable errors        : $disableErrors" -ForegroundColor $(if ($disableErrors -gt 0) { 'Red' } else { 'Green' })
}

#endregion

#region ── Stage 5: Execute Move to Quarantine ────────────────────────────────

$movedCount  = 0
$moveErrors  = 0

if ($ExecuteMove -and $QuarantineOU) {
    Write-Host "[Stage 5] Executing QUARANTINE MOVE stage..." -ForegroundColor Red

    # Verify quarantine OU exists
    try {
        $null = Get-ADOrganizationalUnit -Identity $QuarantineOU -ErrorAction Stop
        Write-Host "    [+] Quarantine OU verified: $QuarantineOU" -ForegroundColor Green
    }
    catch {
        Write-Host "    [!] FATAL: Quarantine OU not found: $QuarantineOU" -ForegroundColor Red
        exit 1
    }

    foreach ($item in ($discoveryResults | Where-Object { $_.ActionStatus -eq "DISABLED" })) {
        try {
            Move-ADObject -Identity $item.DN -TargetPath $QuarantineOU -ErrorAction Stop
            $item.ActionStatus = "QUARANTINED"
            $movedCount++
            Write-Host "    [+] Moved to quarantine: $($item.SamAccountName)" -ForegroundColor Green
            Write-AuditEntry -ObjectType $item.ObjectType -SamAccountName $item.SamAccountName `
                -Action "Move to Quarantine" -Result "Success" -Details $QuarantineOU
        }
        catch {
            $item.ActionStatus = "MOVE FAILED"
            $moveErrors++
            Write-Host "    [!] Failed to move: $($item.SamAccountName) — $_" -ForegroundColor Red
            Write-AuditEntry -ObjectType $item.ObjectType -SamAccountName $item.SamAccountName `
                -Action "Move to Quarantine" -Result "Failed" -Details $_
        }
    }

    Write-Host "    [+] Moved successfully : $movedCount" -ForegroundColor Green
    Write-Host "    [!] Move errors        : $moveErrors" -ForegroundColor $(if ($moveErrors -gt 0) { 'Red' } else { 'Green' })
}

#endregion

#region ── Stage 6: Execute Delete ────────────────────────────────────────────

$deletedCount = 0
$deleteErrors = 0

if ($ExecuteDelete -and $QuarantineOU) {
    Write-Host "[Stage 6] Executing DELETE stage — objects beyond $QuarantineHoldDays day hold..." -ForegroundColor Red

    try {
        $quarantineObjects = Get-ADObject -SearchBase $QuarantineOU -Filter * -Properties "whenChanged", "Description" -ErrorAction Stop |
            Where-Object { $_.whenChanged -lt $quarantineCutoff }

        foreach ($obj in $quarantineObjects) {
            try {
                Remove-ADObject -Identity $obj.DistinguishedName -Recursive -Confirm:$false -ErrorAction Stop
                $deletedCount++
                Write-Host "    [+] Deleted: $($obj.Name)" -ForegroundColor Green
                Write-AuditEntry -ObjectType $obj.ObjectClass -SamAccountName $obj.Name `
                    -Action "Delete" -Result "Success" -Details "Quarantine hold exceeded ${QuarantineHoldDays} days"
            }
            catch {
                $deleteErrors++
                Write-Host "    [!] Failed to delete: $($obj.Name) — $_" -ForegroundColor Red
                Write-AuditEntry -ObjectType $obj.ObjectClass -SamAccountName $obj.Name `
                    -Action "Delete" -Result "Failed" -Details $_
            }
        }
    }
    catch {
        Write-Host "    [!] Cannot enumerate quarantine OU: $_" -ForegroundColor Red
    }

    Write-Host "    [+] Deleted successfully : $deletedCount" -ForegroundColor Green
    Write-Host "    [!] Delete errors        : $deleteErrors" -ForegroundColor $(if ($deleteErrors -gt 0) { 'Red' } else { 'Green' })
}

#endregion

#region ── Save Audit Log ──────────────────────────────────────────────────────

if ($auditEntries.Count -gt 0) {
    $auditEntries | Export-Csv -Path $auditLog -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "[+] Audit log saved: $auditLog" -ForegroundColor Green
}

#endregion

#region ── Summary ────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 6 EXECUTION SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Objects Discovered  : $($discoveryResults.Count)" -ForegroundColor White
Write-Host "  Execution Mode      : $executionMode" -ForegroundColor White
Write-Host "  Disabled            : $disabledCount" -ForegroundColor Green
Write-Host "  Moved to Quarantine : $movedCount" -ForegroundColor Green
Write-Host "  Deleted             : $deletedCount" -ForegroundColor Green
Write-Host "  Disable Errors      : $disableErrors" -ForegroundColor $(if ($disableErrors -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Move Errors         : $moveErrors" -ForegroundColor $(if ($moveErrors -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Delete Errors       : $deleteErrors" -ForegroundColor $(if ($deleteErrors -gt 0) { 'Red' } else { 'Green' })
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

#endregion

#region ── HTML Report ────────────────────────────────────────────────────────

if ($GenerateReport) {

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase6-CleanupWorkflow-$reportStamp.html"

    $discoveryRows = ""
    foreach ($item in $discoveryResults) {
        $rc    = Get-RiskColor -Risk $item.RiskLevel
        $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
        $statusColor = switch ($item.ActionStatus) {
            "DISABLED"    { "#27ae60" }
            "QUARANTINED" { "#2980b9" }
            "PENDING"     { "#95a5a6" }
            default       { "#c0392b" }
        }
        $statusBadge = "<span style='background:$statusColor;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.ActionStatus)</span>"
        $discoveryRows += "<tr>"
        $discoveryRows += "<td>$($item.ObjectType)</td>"
        $discoveryRows += "<td><code>$($item.SamAccountName)</code></td>"
        $discoveryRows += "<td>$($item.DisplayName)</td>"
        $discoveryRows += "<td>$($item.LastLogonDate)</td>"
        $discoveryRows += "<td>$($item.DaysSinceLogon)</td>"
        $discoveryRows += "<td>$badge</td>"
        $discoveryRows += "<td>$statusBadge</td>"
        $discoveryRows += "</tr>"
    }

    $auditRows = ""
    foreach ($entry in $auditEntries) {
        $resultColor = if ($entry.Result -eq "Success") { "#27ae60" } else { "#c0392b" }
        $auditRows += "<tr>"
        $auditRows += "<td>$($entry.Timestamp)</td>"
        $auditRows += "<td>$($entry.ObjectType)</td>"
        $auditRows += "<td><code>$($entry.SamAccountName)</code></td>"
        $auditRows += "<td>$($entry.Action)</td>"
        $auditRows += "<td><span style='color:$resultColor;font-weight:600;'>$($entry.Result)</span></td>"
        $auditRows += "<td style='font-size:11px;'>$($entry.Details)</td>"
        $auditRows += "</tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NorthBridge Financial Group — Phase 6: Inactive Object Cleanup</title>
<style>
  :root { --nb-navy:#0a2342; --nb-gold:#c9a84c; --nb-light:#f4f6f9; --nb-border:#dce3ec; --critical:#c0392b; --high:#e67e22; --medium:#f1c40f; --low:#27ae60; }
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
  .pipeline { display:flex; gap:0; margin-bottom:32px; }
  .pipeline-step { flex:1; text-align:center; padding:16px 8px; background:#fff; border:1px solid var(--nb-border); font-size:12px; font-weight:600; color:#7f8c8d; position:relative; }
  .pipeline-step.active { background:var(--nb-navy); color:#fff; }
  .pipeline-step.done { background:#27ae60; color:#fff; }
  .pipeline-step + .pipeline-step { border-left:none; }
  .pipeline-arrow { display:flex; align-items:center; font-size:18px; color:#bdc3c7; padding:0 4px; }
  .section { background:#fff; border:1px solid var(--nb-border); border-radius:6px; margin-bottom:28px; overflow:hidden; }
  .section-header { background:var(--nb-navy); color:#fff; padding:14px 20px; font-size:14px; font-weight:600; display:flex; justify-content:space-between; align-items:center; }
  .section-header .badge { background:var(--nb-gold); color:var(--nb-navy); border-radius:12px; padding:2px 10px; font-size:12px; font-weight:700; }
  table { width:100%; border-collapse:collapse; }
  th { background:#eef2f7; padding:10px 14px; text-align:left; font-size:12px; font-weight:600; color:var(--nb-navy); text-transform:uppercase; border-bottom:1px solid var(--nb-border); }
  td { padding:10px 14px; border-bottom:1px solid #f0f0f0; font-size:13px; }
  tr:last-child td { border-bottom:none; }
  tr:hover td { background:#f8fafc; }
  code { background:#eef2f7; padding:1px 6px; border-radius:3px; font-size:12px; }
  .warn-box { background:#fdf3e7; border-left:4px solid #e67e22; border-radius:4px; padding:16px 20px; margin-bottom:28px; font-size:13px; }
  .warn-box strong { color:#7a3c00; }
  .footer { text-align:center; padding:20px; font-size:11px; color:#95a5a6; border-top:1px solid var(--nb-border); margin-top:32px; }
  .no-findings { padding:24px; text-align:center; color:#27ae60; font-weight:600; }
</style>
</head>
<body>

<div class="header">
  <div class="subtitle">AD Identity Operations Toolkit — Phase 6</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Inactive Object Cleanup Workflow</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>⏱ Inactivity Threshold: $DaysInactive days</span>
    <span>🔒 Quarantine Hold: $QuarantineHoldDays days</span>
    <span>⚙️ Mode: $executionMode</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>OSFI E-21 §3.4</span> — Account Lifecycle Management &nbsp;|&nbsp;
  <span>CIS Controls v8 — Control 6</span> — Access Account Management &nbsp;|&nbsp;
  <span>NIST SP 800-53 AC-2</span> — Account Management
</div>

<div class="container">

  <div class="warn-box">
    <strong>⚠️ Cleanup Pipeline — Staged Execution:</strong>
    This workflow implements a mandatory 3-stage remediation pipeline. Accounts are first <strong>disabled</strong> with a dated description stamp, then <strong>moved to a quarantine OU</strong>, and only <strong>deleted after a $QuarantineHoldDays-day hold period</strong>.
    All privileged accounts (Domain Admins, Enterprise Admins, Schema Admins) are automatically excluded from remediation. All actions are logged to a structured audit trail.
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-value">$($discoveryResults.Count)</div>
      <div class="kpi-label">Objects Discovered</div>
    </div>
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$criticalCount</div>
      <div class="kpi-label">Critical Risk</div>
    </div>
    <div class="kpi-card green">
      <div class="kpi-value" style="color:#27ae60">$disabledCount</div>
      <div class="kpi-label">Disabled</div>
    </div>
    <div class="kpi-card green">
      <div class="kpi-value" style="color:#2980b9">$movedCount</div>
      <div class="kpi-label">Quarantined</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">$deletedCount</div>
      <div class="kpi-label">Deleted</div>
    </div>
  </div>

  <!-- Discovery Table -->
  <div class="section">
    <div class="section-header">
      🔍 Discovered Inactive Objects — Remediation Pipeline
      <span class="badge">$($discoveryResults.Count) objects</span>
    </div>
    $(if ($discoveryResults.Count -gt 0) {
      "<table><thead><tr>
        <th>Type</th><th>SAM Account</th><th>Display Name</th>
        <th>Last Logon</th><th>Days Inactive</th><th>Risk</th><th>Status</th>
      </tr></thead><tbody>$discoveryRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No inactive objects found within current scope and threshold.</div>"
    })
  </div>

  <!-- Audit Log -->
  $(if ($auditEntries.Count -gt 0) {
  "<div class='section'>
    <div class='section-header'>
      📋 Execution Audit Log
      <span class='badge'>$($auditEntries.Count) actions</span>
    </div>
    <table><thead><tr>
      <th>Timestamp</th><th>Type</th><th>SAM Account</th>
      <th>Action</th><th>Result</th><th>Details</th>
    </tr></thead><tbody>$auditRows</tbody></table>
  </div>"
  })

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 6: Inactive Object Cleanup
  &nbsp;|&nbsp; Generated: $runDate &nbsp;|&nbsp; Audit Log: $auditLog
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

Write-Host ""
Write-Host "  Phase 6 complete. Proceed to Phase 7 — Executive Summary Report." -ForegroundColor Cyan
Write-Host ""

return $discoveryResults
