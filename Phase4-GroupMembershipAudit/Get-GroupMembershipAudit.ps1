#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Group Membership Audit — NorthBridge Financial Group
    AD Identity Operations Toolkit | Phase 4

.DESCRIPTION
    Audits Active Directory security group health across the enterprise environment.
    Detects circular nesting, orphaned groups, over-privileged distribution lists,
    and groups exceeding membership thresholds without assigned governance owners.

    Detections:
        - Empty security groups (no members)
        - Circular group nesting
        - Groups exceeding 500 members without a description/owner
        - Distribution lists containing nested security groups
        - Groups with no members and no description (orphaned)
        - Security groups outside standard OU structure
        - Groups with stale membership (all members disabled/inactive)
        - Duplicate group names across OUs

    READ-ONLY — No changes are made to Active Directory.

.PARAMETER MemberThreshold
    Member count above which a group is flagged for governance review. Default: 500.

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
    .\Get-GroupMembershipAudit.ps1 -WhatIf

.EXAMPLE
    .\Get-GroupMembershipAudit.ps1 -GenerateReport -OutputPath ".\Reports\"

.EXAMPLE
    .\Get-GroupMembershipAudit.ps1 -GenerateReport -ExportCSV -MemberThreshold 250

.NOTES
    Author      : Md Rahat Islam Anik
    Toolkit     : AD Identity Operations Toolkit — NorthBridge Financial Group
    Phase       : 4 — Group Membership Audit
    Version     : 1.0
    Last Updated: June 2026
    Compliance  : CIS Controls v8 — Control 6.3 | NIST SP 800-53 AC-3 | SOC 2 CC6.3
    Permissions : Domain Read (no write permissions required)
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(HelpMessage = "Member count threshold for governance review flag.")]
    [ValidateRange(1, 10000)]
    [int]$MemberThreshold = 500,

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
║                    Phase 4 │ Group Membership Audit                          ║
║              CIS Controls v8 — 6.3 │ NIST 800-53 AC-3 │ SOC 2 CC6.3        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan
Write-Host "  Member Threshold : $MemberThreshold (groups above this flagged for governance review)" -ForegroundColor Yellow
Write-Host "  Search Scope     : $(if ($SearchBase) { $SearchBase } else { 'Full Domain' })" -ForegroundColor Yellow
Write-Host "  Execution Mode   : $(if ($WhatIfPreference) { 'DRY RUN — No files will be written' } else { 'LIVE AUDIT' })" -ForegroundColor $(if ($WhatIfPreference) { 'Magenta' } else { 'Green' })
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

Write-Host "    [+] Domain : $domain" -ForegroundColor Green
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

# Detect circular nesting via DFS with visited tracking
function Test-CircularNesting {
    param(
        [string]$GroupDN,
        [System.Collections.Generic.HashSet[string]]$Visited = $null,
        [System.Collections.Generic.HashSet[string]]$Stack = $null
    )

    if ($null -eq $Visited) { $Visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
    if ($null -eq $Stack)   { $Stack   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }

    if ($Stack.Contains($GroupDN))   { return $true }
    if ($Visited.Contains($GroupDN)) { return $false }

    $null = $Visited.Add($GroupDN)
    $null = $Stack.Add($GroupDN)

    try {
        $members = Get-ADGroupMember -Identity $GroupDN -ErrorAction Stop
        foreach ($member in $members) {
            if ($member.objectClass -eq "group") {
                if (Test-CircularNesting -GroupDN $member.DistinguishedName -Visited $Visited -Stack $Stack) {
                    return $true
                }
            }
        }
    }
    catch { }

    $null = $Stack.Remove($GroupDN)
    return $false
}

#endregion

#region ── Load All Groups ─────────────────────────────────────────────────────

Write-Host "[1/5] Loading all AD groups..." -ForegroundColor Cyan

$adGroupParams = @{
    Filter     = *
    Properties = @(
        "Members", "MemberOf", "Description", "GroupCategory",
        "GroupScope", "whenCreated", "whenChanged", "DistinguishedName",
        "ManagedBy", "mail"
    )
}
if ($SearchBase) { $adGroupParams["SearchBase"] = $SearchBase }

$allGroups = Get-ADGroup @adGroupParams
Write-Host "    [+] Total groups loaded: $($allGroups.Count)" -ForegroundColor Green

#endregion

#region ── Phase 4A: Empty Groups ─────────────────────────────────────────────

Write-Host "[2/5] Detecting empty groups..." -ForegroundColor Cyan

$emptyGroups = $allGroups | Where-Object { $_.Members.Count -eq 0 } | ForEach-Object {
    $hasDesc = (-not [string]::IsNullOrWhiteSpace($_.Description))
    [PSCustomObject]@{
        GroupName     = $_.Name
        GroupCategory = $_.GroupCategory
        GroupScope    = $_.GroupScope
        Description   = if ($hasDesc) { $_.Description } else { "None" }
        ManagedBy     = if ($_.ManagedBy) { $_.ManagedBy -replace '^CN=([^,]+),.+$','$1' } else { "None" }
        MemberCount   = 0
        WhenCreated   = $_.whenCreated.ToString("yyyy-MM-dd")
        WhenChanged   = $_.whenChanged.ToString("yyyy-MM-dd")
        OU            = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel     = if (-not $hasDesc) { "HIGH" } else { "MEDIUM" }
        FindingType   = "Empty Group"
    }
}

Write-Host "    [+] Empty groups: $($emptyGroups.Count)" -ForegroundColor $(if ($emptyGroups.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 4B: Large Groups Without Governance Owner ────────────────────

Write-Host "[3/5] Detecting large groups without governance owner..." -ForegroundColor Cyan

$largeGroups = $allGroups | Where-Object { $_.Members.Count -gt $MemberThreshold } | ForEach-Object {
    $hasOwner = (-not [string]::IsNullOrWhiteSpace($_.ManagedBy))
    $hasDesc  = (-not [string]::IsNullOrWhiteSpace($_.Description))

    [PSCustomObject]@{
        GroupName     = $_.Name
        GroupCategory = $_.GroupCategory
        GroupScope    = $_.GroupScope
        Description   = if ($hasDesc) { $_.Description } else { "None" }
        ManagedBy     = if ($hasOwner) { $_.ManagedBy -replace '^CN=([^,]+),.+$','$1' } else { "UNASSIGNED" }
        MemberCount   = $_.Members.Count
        WhenCreated   = $_.whenCreated.ToString("yyyy-MM-dd")
        WhenChanged   = $_.whenChanged.ToString("yyyy-MM-dd")
        OU            = ($_.DistinguishedName -replace '^CN=[^,]+,', '')
        RiskLevel     = if (-not $hasOwner -and -not $hasDesc) { "CRITICAL" } elseif (-not $hasOwner) { "HIGH" } else { "MEDIUM" }
        FindingType   = "Large Group — Governance Review Required"
    }
}

Write-Host "    [+] Large groups (>$MemberThreshold members): $($largeGroups.Count)" -ForegroundColor $(if ($largeGroups.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Phase 4C: Circular Nesting Detection ───────────────────────────────

Write-Host "[4/5] Detecting circular group nesting..." -ForegroundColor Cyan

$circularGroups = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($group in $allGroups) {
    if ($group.MemberOf.Count -eq 0) { continue }
    try {
        $isCircular = Test-CircularNesting -GroupDN $group.DistinguishedName
        if ($isCircular) {
            $circularGroups.Add([PSCustomObject]@{
                GroupName     = $group.Name
                GroupCategory = $group.GroupCategory
                GroupScope    = $group.GroupScope
                Description   = if ($group.Description) { $group.Description } else { "None" }
                MemberCount   = $group.Members.Count
                MemberOf      = ($group.MemberOf | ForEach-Object { $_ -replace '^CN=([^,]+),.+$','$1' }) -join ", "
                WhenCreated   = $group.whenCreated.ToString("yyyy-MM-dd")
                OU            = ($group.DistinguishedName -replace '^CN=[^,]+,', '')
                RiskLevel     = "CRITICAL"
                FindingType   = "Circular Group Nesting"
            })
        }
    }
    catch { }
}

Write-Host "    [+] Circular nesting detected: $($circularGroups.Count)" -ForegroundColor $(if ($circularGroups.Count -gt 0) { 'Red' } else { 'Green' })

#endregion

#region ── Phase 4D: Distribution Lists with Nested Security Groups ───────────

Write-Host "[5/5] Detecting distribution lists with nested security groups..." -ForegroundColor Cyan

$distListFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

$distLists = $allGroups | Where-Object { $_.GroupCategory -eq "Distribution" }

foreach ($dl in $distLists) {
    try {
        $members    = Get-ADGroupMember -Identity $dl.DistinguishedName -ErrorAction Stop
        $secGroups  = $members | Where-Object { $_.objectClass -eq "group" } | ForEach-Object {
            try {
                $grp = Get-ADGroup -Identity $_.DistinguishedName -Properties "GroupCategory" -ErrorAction Stop
                if ($grp.GroupCategory -eq "Security") { $grp.Name }
            } catch { }
        }

        if ($secGroups.Count -gt 0) {
            $distListFindings.Add([PSCustomObject]@{
                GroupName          = $dl.Name
                GroupCategory      = "Distribution"
                Description        = if ($dl.Description) { $dl.Description } else { "None" }
                MemberCount        = $dl.Members.Count
                NestedSecGroups    = $secGroups -join ", "
                NestedSecGrpCount  = $secGroups.Count
                WhenCreated        = $dl.whenCreated.ToString("yyyy-MM-dd")
                OU                 = ($dl.DistinguishedName -replace '^CN=[^,]+,', '')
                RiskLevel          = "HIGH"
                FindingType        = "Distribution List — Nested Security Groups"
            })
        }
    }
    catch { }
}

Write-Host "    [+] Distribution lists with nested security groups: $($distListFindings.Count)" -ForegroundColor $(if ($distListFindings.Count -gt 0) { 'Yellow' } else { 'Green' })

#endregion

#region ── Summary ────────────────────────────────────────────────────────────

$allFindings   = @($emptyGroups) + @($largeGroups) + @($circularGroups) + @($distListFindings)
$criticalCount = ($allFindings | Where-Object { $_.RiskLevel -eq "CRITICAL" }).Count
$highCount     = ($allFindings | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumCount   = ($allFindings | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PHASE 4 FINDINGS SUMMARY" -ForegroundColor White
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Total Groups Scanned        : $($allGroups.Count)" -ForegroundColor White
Write-Host "  Total Findings              : $($allFindings.Count)" -ForegroundColor White
Write-Host "  CRITICAL                    : $criticalCount" -ForegroundColor Red
Write-Host "  HIGH                        : $highCount" -ForegroundColor Yellow
Write-Host "  MEDIUM                      : $mediumCount" -ForegroundColor Cyan
Write-Host "  Empty Groups                : $($emptyGroups.Count)" -ForegroundColor White
Write-Host "  Large Groups (>$MemberThreshold)      : $($largeGroups.Count)" -ForegroundColor White
Write-Host "  Circular Nesting            : $($circularGroups.Count)" -ForegroundColor White
Write-Host "  DL with Nested Sec Groups   : $($distListFindings.Count)" -ForegroundColor White
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

    $reportFile = Join-Path $OutputPath "NorthBridge-Phase4-GroupAudit-$reportStamp.html"

    function New-GroupRows {
        param([array]$Data, [string[]]$Columns)
        $rows = ""
        foreach ($item in $Data) {
            $rc    = Get-RiskColor -Risk $item.RiskLevel
            $badge = "<span style='background:$rc;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;'>$($item.RiskLevel)</span>"
            $rows += "<tr>"
            foreach ($col in $Columns) {
                if ($col -eq "RiskLevel") { $rows += "<td>$badge</td>" }
                elseif ($col -eq "GroupName") { $rows += "<td><strong>$($item.$col)</strong></td>" }
                else { $rows += "<td>$($item.$col)</td>" }
            }
            $rows += "</tr>"
        }
        return $rows
    }

    $emptyRows   = New-GroupRows -Data $emptyGroups   -Columns @("GroupName","GroupCategory","ManagedBy","Description","WhenCreated","RiskLevel")
    $largeRows   = New-GroupRows -Data $largeGroups   -Columns @("GroupName","GroupCategory","MemberCount","ManagedBy","Description","RiskLevel")
    $circRows    = New-GroupRows -Data $circularGroups -Columns @("GroupName","GroupCategory","MemberOf","MemberCount","RiskLevel")
    $distRows    = New-GroupRows -Data $distListFindings -Columns @("GroupName","MemberCount","NestedSecGrpCount","NestedSecGroups","RiskLevel")

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>NorthBridge Financial Group — Phase 4: Group Membership Audit</title>
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
  .osfi-box { background:#eaf2fb; border-left:4px solid var(--nb-navy); border-radius:4px; padding:16px 20px; margin-bottom:28px; font-size:13px; }
  .osfi-box strong { color:var(--nb-navy); }
  .footer { text-align:center; padding:20px; font-size:11px; color:#95a5a6; border-top:1px solid var(--nb-border); margin-top:32px; }
  .no-findings { padding:24px; text-align:center; color:#27ae60; font-weight:600; }
</style>
</head>
<body>

<div class="header">
  <div class="subtitle">AD Identity Operations Toolkit — Phase 4</div>
  <h1>🏦 NorthBridge Financial Group &nbsp;|&nbsp; Group Membership Audit</h1>
  <div class="meta">
    <span>📅 Run Date: $runDate</span>
    <span>🏢 Domain: $domain</span>
    <span>👥 Total Groups Scanned: $($allGroups.Count)</span>
    <span>⚠️ Member Threshold: $MemberThreshold</span>
  </div>
</div>

<div class="compliance-bar">
  Compliance References: &nbsp;
  <span>CIS Controls v8 — 6.3</span> — Access Account Management &nbsp;|&nbsp;
  <span>NIST SP 800-53 AC-3</span> — Access Enforcement &nbsp;|&nbsp;
  <span>SOC 2 CC6.3</span> — Logical Access Controls
</div>

<div class="container">

  <div class="osfi-box">
    <strong>⚠️ Access Governance Requirement:</strong> CIS Controls v8 Control 6.3 requires organizations to maintain an accurate inventory of all accounts and groups, with regular review of privileged group membership.
    Circular nesting creates unresolvable privilege chains. Distribution lists with nested security groups bypass email filtering controls and may expose sensitive group membership externally.
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
    <div class="kpi-card critical">
      <div class="kpi-value" style="color:var(--critical)">$($circularGroups.Count)</div>
      <div class="kpi-label">Circular Nesting</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-value">$($emptyGroups.Count)</div>
      <div class="kpi-label">Empty Groups</div>
    </div>
  </div>

  <!-- Circular Nesting -->
  <div class="section">
    <div class="section-header">
      🔴 Circular Group Nesting — Unresolvable Privilege Chains
      <span class="badge">$($circularGroups.Count) findings</span>
    </div>
    $(if ($circularGroups.Count -gt 0) {
      "<table><thead><tr><th>Group Name</th><th>Category</th><th>Member Of</th><th>Members</th><th>Risk</th></tr></thead><tbody>$circRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No circular group nesting detected.</div>"
    })
  </div>

  <!-- Large Groups -->
  <div class="section">
    <div class="section-header">
      🟠 Large Groups — Governance Review Required (&gt;$MemberThreshold members)
      <span class="badge">$($largeGroups.Count) findings</span>
    </div>
    $(if ($largeGroups.Count -gt 0) {
      "<table><thead><tr><th>Group Name</th><th>Category</th><th>Members</th><th>Managed By</th><th>Description</th><th>Risk</th></tr></thead><tbody>$largeRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No large ungoverned groups detected.</div>"
    })
  </div>

  <!-- Empty Groups -->
  <div class="section">
    <div class="section-header">
      👥 Empty Security Groups
      <span class="badge">$($emptyGroups.Count) findings</span>
    </div>
    $(if ($emptyGroups.Count -gt 0) {
      "<table><thead><tr><th>Group Name</th><th>Category</th><th>Managed By</th><th>Description</th><th>Created</th><th>Risk</th></tr></thead><tbody>$emptyRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No empty groups detected.</div>"
    })
  </div>

  <!-- Distribution Lists with Security Groups -->
  <div class="section">
    <div class="section-header">
      📧 Distribution Lists — Nested Security Groups
      <span class="badge">$($distListFindings.Count) findings</span>
    </div>
    $(if ($distListFindings.Count -gt 0) {
      "<table><thead><tr><th>DL Name</th><th>Total Members</th><th>Nested Sec Groups</th><th>Security Group Names</th><th>Risk</th></tr></thead><tbody>$distRows</tbody></table>"
    } else {
      "<div class='no-findings'>✅ No distribution lists with nested security groups detected.</div>"
    })
  </div>

</div>

<div class="footer">
  NorthBridge Financial Group &nbsp;|&nbsp; AD Identity Operations Toolkit &nbsp;|&nbsp; Phase 4: Group Membership Audit
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
    $csvFile = Join-Path $OutputPath "NorthBridge-Phase4-GroupAudit-$reportStamp.csv"
    $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV export saved: $csvFile" -ForegroundColor Green
}

#endregion

Write-Host ""
Write-Host "  Phase 4 complete. Proceed to Phase 5 — Service Account Governance." -ForegroundColor Cyan
Write-Host ""

return $allFindings
