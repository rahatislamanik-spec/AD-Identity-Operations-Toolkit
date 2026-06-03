# 🏦 AD Identity Operations Toolkit
### NorthBridge Financial Group — Enterprise Active Directory Governance

![PowerShell](https://img.shields.io/badge/PowerShell-7.x-blue?logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202019%2F2022-lightgrey?logo=windows)
![Compliance](https://img.shields.io/badge/Compliance-OSFI%20E--21%20%7C%20CIS%20Controls-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

---

## 📋 Overview

The **AD Identity Operations Toolkit** is a production-grade PowerShell framework designed for enterprise Active Directory environments in regulated financial institutions. Built to address identity governance requirements aligned with **OSFI E-21**, **CIS Controls v8**, and **NIST SP 800-53**, this toolkit provides security operations teams with automated audit, reporting, and remediation workflows across the full AD identity lifecycle.

Developed against a simulated **NorthBridge Financial Group** enterprise environment — modelling the complexity of a Big 6 Canadian bank subsidiary: multi-domain forest, Tier 0/1/2 privilege separation, fine-grained password policies, and service account sprawl.

> ⚠️ All scripts include **dry-run mode** (`-WhatIf`). No destructive operations execute without explicit confirmation. Designed for use by L2/L3 Identity & Access Management teams.

---

## 🗂️ Repository Structure

```
AD-Identity-Operations-Toolkit/
│
├── Phase1-StaleAccountDetection/
│   └── Get-StaleAccounts.ps1
│
├── Phase2-PrivilegedAccountAudit/
│   └── Get-PrivilegedAccountAudit.ps1
│
├── Phase3-PasswordPolicyCompliance/
│   └── Get-PasswordPolicyCompliance.ps1
│
├── Phase4-GroupMembershipAudit/
│   └── Get-GroupMembershipAudit.ps1
│
├── Phase5-ServiceAccountGovernance/
│   └── Get-ServiceAccountGovernance.ps1
│
├── Phase6-InactiveObjectCleanup/
│   └── Invoke-InactiveObjectCleanup.ps1
│
├── Phase7-ExecutiveSummaryReport/
│   └── New-ExecutiveSummaryReport.ps1
│
├── Reports/                        # Auto-generated HTML reports (gitignored)
├── SampleOutputs/                  # Sanitized sample report screenshots
├── docs/
│   └── NorthBridge-AD-Governance-Runbook.md
└── README.md
```

---

## 🔐 Phase Breakdown

### Phase 1 — Stale Account Detection
Identifies user and computer accounts that have exceeded inactivity thresholds aligned with financial institution standards (30-day threshold vs. enterprise 90-day default). Flags accounts by OU, department, and last logon delta. Outputs interactive HTML report with sortable risk table.

**Key detections:** Accounts inactive >30 days · Never-logged-in accounts · Disabled accounts still holding group memberships · Computer accounts with stale `pwdLastSet`

---

### Phase 2 — Privileged Account Audit
Enumerates all Tier 0 and Tier 1 privileged principals across Domain Admins, Schema Admins, Enterprise Admins, Backup Operators, and Account Operators. Performs recursive nested group explosion to surface shadow privilege paths.

**Key detections:** Nested group privilege escalation · Admin accounts with no MFA indicator · Privileged accounts with non-expiring passwords · Service accounts in Tier 0 groups

---

### Phase 3 — Password Policy Compliance
Audits both default domain password policy and Fine-Grained Password Policies (FGPPs) across all PSOs. Maps policy coverage gaps and identifies accounts falling outside compliant policy scope.

**Key detections:** Accounts with `PasswordNeverExpires` · Accounts with `PasswordNotRequired` · PSO coverage gaps · Policy strength vs. OSFI E-21 minimums

---

### Phase 4 — Group Membership Audit
Analyses AD security group health across the environment. Detects circular nesting, orphaned groups, over-privileged distribution lists, and groups exceeding membership thresholds.

**Key detections:** Circular group nesting · Empty security groups · Groups >500 members without governance owner · Distribution lists with nested security groups

---

### Phase 5 — Service Account Governance
Enumerates all service accounts by convention and SPN registration. Flags Kerberoastable accounts, SPNs registered on user objects, and service accounts operating outside dedicated OUs.

**Key detections:** Kerberoastable accounts (SPN on user objects) · Service accounts in privileged groups · Accounts without `msDS-ManagedPassword` (non-gMSA) · SPN conflicts

---

### Phase 6 — Inactive Object Cleanup Workflow
Implements the full disable → move → delete remediation pipeline with staged execution and mandatory dry-run preview. All actions are logged to a structured audit trail for compliance review.

**Pipeline:** Discovery → Risk Classification → Dry-Run Preview → Staged Disable → OU Quarantine → 30-Day Hold → Deletion with audit log

---

### Phase 7 — Executive Summary Report
Aggregates findings from all phases into a single executive-ready HTML report with risk scoring, trend indicators, and OSFI E-21 control mapping. Designed for CISO and audit committee consumption.

**Output:** Risk-scored dashboard · Control gap heatmap · Remediation priority matrix · Export-ready PDF layout

---

## ⚙️ Requirements

| Component | Minimum Version |
|---|---|
| PowerShell | 5.1+ (7.x recommended) |
| RSAT: AD DS Tools | Windows Server 2019/2022 |
| ActiveDirectory Module | Included with RSAT |
| Permissions | Domain Read + MSOL (Phase 2 requires DA read) |
| OS | Windows Server 2019 / Windows 10-11 with RSAT |

---

## 🚀 Quick Start

```powershell
# Clone the repository
git clone https://github.com/rahatislamanik-spec/AD-Identity-Operations-Toolkit.git
cd AD-Identity-Operations-Toolkit

# Import the AD module (if not auto-loaded)
Import-Module ActiveDirectory

# Run Phase 1 in dry-run mode
.\Phase1-StaleAccountDetection\Get-StaleAccounts.ps1 -DaysInactive 30 -WhatIf

# Run Phase 1 and generate HTML report
.\Phase1-StaleAccountDetection\Get-StaleAccounts.ps1 -DaysInactive 30 -GenerateReport -OutputPath ".\Reports\"
```

---

## 🏛️ Compliance Mapping

| Control Area | Framework Reference | Phase Coverage |
|---|---|---|
| Privileged Access Management | OSFI E-21 §3.2 · CIS Control 5 | Phase 2, 5 |
| Account Lifecycle Management | OSFI E-21 §3.4 · CIS Control 6 | Phase 1, 6 |
| Password & Authentication Policy | OSFI E-21 §3.3 · NIST 800-53 IA-5 | Phase 3 |
| Access Reviews & Recertification | CIS Control 6.3 · SOC 2 CC6.3 | Phase 2, 4 |
| Service Account Security | CIS Control 5.6 · NIST 800-53 AC-6 | Phase 5 |
| Audit Logging | OSFI E-21 §4.1 · CIS Control 8 | Phase 6, 7 |

---

## 🔗 Related Portfolio Projects

| Project | Description |
|---|---|
| [Enterprise IT Security Operations Toolkit](https://github.com/rahatislamanik-spec/Enterprise-IT-Security-Operations-Toolkit) | M365 security automation — Exchange, Entra ID, Defender XDR |
| [Meridian Institute M365 Lab](https://github.com/rahatislamanik-spec/Meridian-Institute-M365-Lab) | End-to-end M365 tenant governance simulation |
| [Enterprise IT Network Diagnostics Toolkit](https://github.com/rahatislamanik-spec/Enterprise-IT-Network-Diagnostics-Toolkit) | Cross-platform PowerShell network diagnostics |

---

## 👤 Author

**Md Rahat Islam Anik**
Cloud Computing & Network Administration | George Brown College — May 2026
IT Systems Administrator · M365 & Identity Specialist · Security Operations

[![Portfolio](https://img.shields.io/badge/Portfolio-Live-blue)](https://rahatislamanik-spec.github.io/IT-Portfolio-Rahat-Islam-Anik)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://linkedin.com/in/rahatislamanik)
[![GitHub](https://img.shields.io/badge/GitHub-rahatislamanik--spec-black?logo=github)](https://github.com/rahatislamanik-spec)

---

*Built for enterprise identity governance in regulated Canadian financial institutions. All scripts operate in read-only mode by default. Destructive operations require explicit `-Confirm` flag.*
