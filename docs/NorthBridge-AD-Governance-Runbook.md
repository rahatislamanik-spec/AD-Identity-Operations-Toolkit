# NorthBridge Financial Group — AD Governance Runbook

**AD Identity Operations Toolkit | Operational Reference**

---

## Purpose

This runbook documents the operational procedures, escalation paths, and execution guidelines for the AD Identity Operations Toolkit deployed in the NorthBridge Financial Group enterprise environment.

---

## Execution Schedule

| Phase | Script | Frequency | Owner |
|---|---|---|---|
| Phase 1 | Get-StaleAccounts.ps1 | Weekly | L2 Identity Team |
| Phase 2 | Get-PrivilegedAccountAudit.ps1 | Weekly | L3 IAM |
| Phase 3 | Get-PasswordPolicyCompliance.ps1 | Monthly | L2 Identity Team |
| Phase 4 | Get-GroupMembershipAudit.ps1 | Monthly | L2 Identity Team |
| Phase 5 | Get-ServiceAccountGovernance.ps1 | Monthly | L3 IAM |
| Phase 6 | Invoke-InactiveObjectCleanup.ps1 | Monthly (with approval) | L3 IAM + Change Advisory Board |
| Phase 7 | New-ExecutiveSummaryReport.ps1 | Monthly | L3 IAM |

---

## Escalation Path

| Severity | Finding | Escalation |
|---|---|---|
| Critical | Tier 0 account with non-expiring password | CISO within 4 hours |
| High | Kerberoastable service account | IAM Lead within 24 hours |
| Medium | Stale accounts >30 days | L2 Identity Team within 5 business days |
| Low | Empty security groups | Monthly cleanup cycle |

---

## Pre-Execution Checklist

- [ ] Confirm change window is approved via Change Advisory Board
- [ ] Run all scripts in `-WhatIf` mode first and review output
- [ ] Ensure AD audit logging is enabled
- [ ] Confirm backup of AD state prior to Phase 6 execution
- [ ] Notify affected department heads before account disablement

---

## Compliance Reference

- OSFI E-21 — Technology and Cyber Risk Management
- CIS Controls v8 — Center for Internet Security
- NIST SP 800-53 — Security and Privacy Controls

---

*NorthBridge Financial Group — Internal Use Only | Simulated Enterprise Environment*
