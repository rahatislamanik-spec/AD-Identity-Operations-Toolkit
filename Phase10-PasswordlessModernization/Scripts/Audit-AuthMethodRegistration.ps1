#Requires -Version 5.1

<#
.SYNOPSIS
Authentication Method Registration Audit

.DESCRIPTION
Audits user authentication method registration coverage
for a simulated financial-services environment.

The report helps identify users who are not ready
for passwordless authentication rollout.

Author: Md Rahat Islam Anik
#>

param(
    [string]$OutputPath = "..\SampleOutputs\AuthMethodAudit.csv"
)

Write-Host ""
Write-Host "========================================"
Write-Host " Authentication Method Registration Audit"
Write-Host "========================================"
Write-Host ""

$Results = @()

$Results += [PSCustomObject]@{
    UserPrincipalName = "jsmith@northbridgefinancial.com"
    Department        = "Finance"
    AuthenticatorApp  = "Registered"
    FIDO2Key          = "Registered"
    PhoneMethod       = "Registered"
    RegistrationState = "Compliant"
}

$Results += [PSCustomObject]@{
    UserPrincipalName = "mnguyen@northbridgefinancial.com"
    Department        = "Operations"
    AuthenticatorApp  = "Registered"
    FIDO2Key          = "Not Registered"
    PhoneMethod       = "Registered"
    RegistrationState = "Partially Compliant"
}

$Results += [PSCustomObject]@{
    UserPrincipalName = "jdoe@northbridgefinancial.com"
    Department        = "HR"
    AuthenticatorApp  = "Not Registered"
    FIDO2Key          = "Not Registered"
    PhoneMethod       = "Not Registered"
    RegistrationState = "Non-Compliant"
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation

Write-Host "Audit completed."
Write-Host "Output written to:"
Write-Host $OutputPath