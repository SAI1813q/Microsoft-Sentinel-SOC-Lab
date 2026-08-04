# 🚨 Detection Validation

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

## 📖 Overview

This alert was generated after executing common Windows discovery commands on a monitored endpoint. Microsoft Sentinel's Near Real-Time (NRT) analytics rule detected the process creation events and immediately generated an alert. Since incident creation was enabled during rule configuration, Microsoft Sentinel automatically created an incident and associated the alert with it.

---

## ⚔️ Attack Simulation

The detection was validated by executing native Windows reconnaissance commands from a Command Prompt on the monitored endpoint.

```cmd
hostname
systeminfo
wmic process list
```

These commands generated Windows Security Event ID **4688 (Process Creation)**, which matched the analytics rule conditions.

---

## 🚨 Generated Alert

| Property | Value |
|----------|-------|
| Alert Name | Suspicious Discovery Commands |
| Severity | Medium |
| Status | New |
| Detection Source | Near Real-Time (NRT) Analytics Rule |
| Service Source | Microsoft Sentinel |
| MITRE ATT&CK | Discovery (T1016, T1033, T1082, T1087) |

The alert contains information about the executed process, the user who initiated it, and the affected device, enabling analysts to quickly identify reconnaissance activity.

---

## 📂 Generated Incident

Since **Create incidents from alerts** was enabled during analytics rule configuration, Microsoft Sentinel automatically created an incident when the alert was generated.

The incident includes:

- Related alerts
- Affected device
- User account
- Timeline of events
- Investigation graph

Grouping related alerts into a single incident reduces alert fatigue while preserving the complete attack timeline for investigation.

---

## 🧩 Alert Entities

The generated alert identified the following entities:

| Entity | Value |
|---------|-------|
| Device | VM1 |
| User | VM1\Sia123 |

These entities enable Microsoft Sentinel to correlate related activity and provide additional investigation context.

---

## 🔎 Investigation Summary

From the alert, a SOC analyst can immediately determine:

- Which endpoint executed the reconnaissance commands.
- Which user account initiated the activity.
- Which analytics rule detected the behavior.
- When the activity occurred.
- The corresponding incident for further investigation.

The **Related Events** section provides detailed evidence, including the executed process name and command line, allowing analysts to validate the detection and assess whether the activity is legitimate or potentially malicious.

---

## ✅ Validation Result

The detection was successfully validated by manually executing Windows discovery commands on the monitored endpoint.

Expected outcome:

- ✅ Alert generated by Microsoft Sentinel.
- ✅ Incident automatically created.
- ✅ Device and User entities successfully mapped.
- ✅ Alert linked to the corresponding incident.
- ✅ Related process execution events available for investigation.

---

## 📸 Alert Evidence

### Generated Alert

> *(Insert alert overview screenshot)*

### Alert Details

> *(Insert alert details screenshot)*

### Generated Incident

> *(Insert incident overview screenshot)*

### Related Events

> *(Insert related events screenshot)*

### Investigation Timeline

> *(Insert timeline screenshot)*

---

⬆️ **[Back to Detection Validation Summary](#-detection-validation-summary)**

---
