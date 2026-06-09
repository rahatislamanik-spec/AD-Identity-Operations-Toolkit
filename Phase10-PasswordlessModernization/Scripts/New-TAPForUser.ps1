#Requires -Version 5.1

<#
.SYNOPSIS
Temporary Access Pass Provisioning Workflow

.DESCRIPTION
Simulates a controlled Temporary Access Pass (TAP) issuance
process for passwordless onboarding in a financial-services
environment.

This script does not connect to Microsoft Entra ID and does not
create a real TAP. It demonstrates governance workflow,
approval requirements, logging, and operational controls.

Author: Md Rahat Islam Anik
#>

param(
    [string]$UserPrincipalName = "jsmith@northbridgefinancial.com",
    [string]$TicketNumber = "INC-2026-1001",
    [string]$Approver = "IdentityOperationsLead",
    [string]$OutputPath = "..\SampleOutputs\TAPProvisioningLog.csv"
)

Write-Host ""
Write-Host "========================================"
Write-Host " Temporary Access Pass Provisioning"
Write-Host "========================================"
Write-Host ""

$TapRecord = [PSCustomObject]@{
    Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    UserPrincipalName = $UserPrincipalName
    TicketNumber      = $TicketNumber
    ApprovedBy        = $Approver
    TAPLifetimeHours  = 4
    SingleUse         = "Yes"
    Status            = "Approved"
}

if (Test-Path $OutputPath) {
    $TapRecord | Export-Csv -Path $OutputPath -Append -NoTypeInformation
}
else {
    $TapRecord | Export-Csv -Path $OutputPath -NoTypeInformation
}

Write-Host "TAP request approved."
Write-Host "User: $UserPrincipalName"
Write-Host "Ticket: $TicketNumber"
Write-Host "Lifetime: 4 Hours"
Write-Host "Single Use: Yes"
Write-Host ""
Write-Host "Audit log written to:"
Write-Host $OutputPath