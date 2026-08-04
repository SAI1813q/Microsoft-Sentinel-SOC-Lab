# #🚨 Detection Validation & Investigation

This section demonstrates the successful validation of each Microsoft Sentinel analytics rule. After executing attack simulations within the lab environment, Microsoft Sentinel generated alerts and automatically created incidents based on the configured incident creation settings.

Each alert includes enriched entities, related events, and investigation context, confirming that the corresponding detection logic functioned as expected.

---

# 📋 Detection Validation Summary

| Alert | Severity | Incident Created | Validation Status | Description |
|-------|----------|------------------|-------------------|-------------|
| **[Brute Force Login Detection](#-brute-force-login-detection)** | High | ✅ Yes | ✅ Validated | Generated after multiple failed Windows logon attempts exceeded the configured threshold. |
| **[Successful Login After Brute Force](#-successful-login-after-brute-force)** | High | ✅ Yes | ✅ Validated | Generated when a successful authentication followed repeated failed logon attempts. |
| **[New Local User Creation](#-new-local-user-creation)** | Medium | ✅ Yes | ✅ Validated | Generated when a new local user account was created on a monitored endpoint. |
| **[Encoded PowerShell Detection](#-encoded-powershell-detection)** | High | ✅ Yes | ✅ Validated | Generated after execution of a Base64-encoded PowerShell command. |
| **[Download Cradle Detection](#-download-cradle-detection)** | High | ✅ Yes | ✅ Validated | Generated when PowerShell attempted to download remote content from an external source. |
| **[Mimikatz Detection](#-mimikatz-detection)** | High | ✅ Yes | ✅ Validated | Generated after execution of the Mimikatz credential dumping tool. |
| **[PsExec Detection](#-psexec-detection)** | High | ✅ Yes | ✅ Validated | Generated when PsExec was used to execute commands remotely. |
| **[Registry Run Key Persistence](#-registry-run-key-persistence)** | High | ✅ Yes | ✅ Validated | Generated after persistence was established using Windows Run Registry Keys. |
| **[Event Log Cleared Detection](#-event-log-cleared-detection)** | High | ✅ Yes | ✅ Validated | Generated when Windows Event Logs were cleared to remove forensic evidence. |
| **[New Windows Service Installed](#-new-windows-service-installed)** | High | ✅ Yes | ✅ Validated | Generated after installation of a new Windows service. |
| **[Scheduled Task Creation](#-scheduled-task-creation)** | Medium | ✅ Yes | ✅ Validated | Generated when a new scheduled task was created on the monitored endpoint. |
| **[Suspicious Discovery Commands](#-suspicious-discovery-commands)** | Medium | ✅ Yes | ✅ Validated | Generated after execution of common Windows reconnaissance commands. |
| **[Domain Admin Group Modification](#-domain-admin-group-modification)** | Critical | ✅ Yes | ✅ Validated | Generated when a privileged Active Directory group membership was modified. |

---

# 🚨 Suspicious Discovery Commands

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying suspicious system discovery commands executed on a monitored Windows endpoint. The analytics rule detected the execution of native Windows reconnaissance utilities, automatically generated an alert, and correlated it into a Microsoft Defender incident for investigation.

---

## 📖 Attack Scenario

After gaining access to a system, attackers typically perform reconnaissance to understand the environment before moving laterally or escalating privileges. Common Windows utilities such as `hostname.exe`, `systeminfo.exe`, `wmic.exe`, and `ver.exe` are frequently abused because they are legitimate operating system binaries.

Microsoft Sentinel detected this activity through a Near Real-Time analytics rule and automatically created an investigation incident.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Suspicious Discovery Commands |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Not Set |
| **Assigned To** | Unassigned |
| **Detection Source** | Microsoft Sentinel |
| **Analytics Rule** | Suspicious Discovery Commands |
| **MITRE ATT&CK** | T1016, T1033, T1082, T1087 |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected the execution of one or more Windows discovery commands matching the analytics rule.

These commands are commonly executed during the reconnaissance phase of an attack to collect information about the operating system, host configuration, users, and network environment.

---

## Alert Workflow

```text
Attacker executes discovery command
            │
            ▼
Windows Security Event (4688)
            │
            ▼
Azure Monitor Agent
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel Analytics Rule
            │
            ▼
Alert Generated
            │
            ▼
Incident Automatically Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 3 |
| **Incident Name** | Suspicious Discovery Commands |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Sentinel automatically correlated the generated alert into a single incident.

This provides analysts with one investigation workspace containing:

- Alert information
- Attack story
- Investigation graph
- Impacted assets
- Evidence
- Activities

instead of requiring multiple independent investigations.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The attack story provides a visual relationship between the detected entities involved in the alert.

For this detection Microsoft Defender automatically associated:

- Device
- User Account
- Suspicious Process

allowing analysts to quickly understand how the entities are connected.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The investigation graph automatically maps the entities involved in the incident.

Observed entities include:

- Device (Vm1)
- User (Vm1\Sia123)
- Suspicious Process (HOSTNAME.EXE)

This visualization helps analysts pivot between related entities during an investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| Device | Vm1 |
| Risk Level | None |

---

## User

| Property | Value |
|----------|-------|
| User | Vm1\Sia123 |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender collected evidence associated with the detection.

| Property | Value |
|----------|-------|
| Entity Type | Process |
| Verdict | Suspicious |
| Impacted Asset | Vm1 |

The suspicious process was linked to the alert, providing investigators with additional context during analysis.

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the investigation.

For this incident:

- Alert automatically correlated into Incident 3
- Trigger performed by Microsoft Defender XDR
- Activity Status: Completed

This provides an audit trail showing how the incident was created.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- Verify whether the commands were executed by an administrator or a standard user.
- Review the process command line.
- Identify any subsequent lateral movement or credential access activity.
- Examine neighboring alerts within the same timeline.
- Determine whether the reconnaissance activity is authorized or malicious.

---

# 🎯 Security Impact

This detection provides early visibility into post-compromise reconnaissance activity.

Early detection allows defenders to investigate the attacker before they progress to:

- Credential Dumping
- Privilege Escalation
- Lateral Movement
- Persistence
- Data Exfiltration

Detecting discovery activity at this stage significantly improves the chances of containing an intrusion before major damage occurs.

---

⬆️ **[Back to Detection Validation Summary](#-detection-validation-summary)**

---




