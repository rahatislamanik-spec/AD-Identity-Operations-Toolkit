#Requires -Version 5.1

<#
.SYNOPSIS
Passwordless Readiness Assessment

.DESCRIPTION
Evaluates users for passwordless authentication readiness in a simulated
financial-services environment.

Outputs readiness categories that can be used for pilot planning and
identity modernization reporting.

Author: Md Rahat Islam Anik
#>

param(
    [string]$OutputPath = "..\SampleOutputs\PasswordlessReadiness.csv"
)

Write-Host ""
Write-Host "========================================"
Write-Host " Passwordless Readiness Assessment"
Write-Host "========================================"
Write-Host ""

$Results = @()

$Results += [PSCustomObject]@{
    UserPrincipalName = "jsmith@northbridgefinancial.com"
    Department        = "Finance"
    MFARegistered     = "Yes"
    AuthenticatorApp  = "Yes"
    FIDO2Registered   = "Yes"
    PrivilegedAccount = "No"
    ReadinessStatus   = "Ready"
}

$Results += [PSCustomObject]@{
    UserPrincipalName = "mnguyen@northbridgefinancial.com"
    Department        = "Operations"
    MFARegistered     = "Yes"
    AuthenticatorApp  = "Yes"
    FIDO2Registered   = "No"
    PrivilegedAccount = "No"
    ReadinessStatus   = "Pilot Candidate"
}

$Results += [PSCustomObject]@{
    UserPrincipalName = "svc_sql@northbridgefinancial.com"
    Department        = "Infrastructure"
    MFARegistered     = "No"
    AuthenticatorApp  = "No"
    FIDO2Registered   = "No"
    PrivilegedAccount = "Yes"
    ReadinessStatus   = "Exception Review Required"
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation

Write-Host "Assessment completed."
Write-Host "Output written to:"
Write-Host $OutputPath