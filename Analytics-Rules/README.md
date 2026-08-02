
# 🛡️ Analytics Rules

Microsoft Sentinel was configured with custom Scheduled Analytics Rules to detect a broad range of adversary techniques mapped to the MITRE ATT&CK framework. These detections leverage Windows Security Events, Sysmon logs, and custom KQL queries collected through Azure Monitor Agent (AMA) and Data Collection Rules (DCRs).

Each analytics rule continuously monitors incoming telemetry from the monitored endpoints. When predefined conditions are met, Microsoft Sentinel generates an alert, creates an incident, and triggers automated response workflows through Azure Logic Apps, enabling faster detection and response to potential security threats.

The detection rules implemented in this lab cover multiple stages of the cyber attack lifecycle, including Initial Access, Execution, Persistence, Credential Access, Discovery, Lateral Movement, Defense Evasion, and Privilege Escalation.

---

# 📋 Analytics Rule Summary

| Detection Rule | Severity | MITRE ATT&CK | Description |
|---------------|----------|--------------|-------------|
| **[Brute Force Login Detection](#-brute-force-login-detection)** | High | T1110 | Detects repeated failed Windows logon attempts that may indicate password guessing or brute-force attacks. |
| **[Successful Login After Brute Force](#-successful-login-after-brute-force)** | High | T1078 | Detects successful authentication immediately following multiple failed login attempts. |
| **[New Local User Creation](#-new-local-user-creation)** | Medium | T1136 | Detects creation of new local user accounts on Windows systems. |
| **[Encoded PowerShell Detection](#-encoded-powershell-detection)** | High | T1059.001 | Detects execution of Base64-encoded PowerShell commands. |
| **[Download Cradle Detection](#-download-cradle-detection)** | High | T1105 | Detects PowerShell commands used to download payloads from remote servers. |
| **[Mimikatz Detection](#-mimikatz-detection)** | High | T1003 | Detects execution of the Mimikatz credential dumping tool. |
| **[PsExec Detection](#-psexec-detection)** | High | T1021.002 | Detects PsExec usage for remote execution and lateral movement. |
| **[Registry Run Key Persistence](#-registry-run-key-persistence)** | High | T1547.001 | Detects persistence through Windows Run Registry Keys. |
| **[Event Log Cleared Detection](#-event-log-cleared-detection)** | High | T1070.001 | Detects attempts to clear Windows Event Logs to hide attacker activity. |
| **[New Windows Service Installed](#-new-windows-service-installed)** | High | T1543.003 | Detects installation of new Windows services that may establish persistence. |
| **[Scheduled Task Creation](#-scheduled-task-creation)** | Medium | T1053.005 | Detects creation of scheduled tasks for persistence or malicious execution. |
| **[Suspicious Discovery Commands](#-suspicious-discovery-commands)** | Medium | T1082, T1016, T1033 | Detects execution of common system discovery and reconnaissance commands. |
| **[Domain Admin Group Modification](#-domain-admin-group-modification)** | Critical | T1098 | Detects modifications to privileged Active Directory groups. |


# 🔐 Brute Force Login Detection

## 🎯 Objective

Detect repeated failed Windows authentication attempts that may indicate a brute-force or password guessing attack against local or domain accounts. This rule enables early identification of credential-based attacks before an attacker successfully gains access.

---

## 📖 Threat Overview

Brute-force attacks involve repeatedly attempting different password combinations until valid credentials are discovered. Attackers commonly target Remote Desktop Protocol (RDP), SMB, VPN services, and Active Directory accounts using automated tools to gain unauthorized access.

Monitoring failed authentication events allows Security Operations Center (SOC) analysts to quickly identify suspicious login behavior, investigate malicious source IP addresses, and take proactive actions before account compromise occurs.

---

## 🔥 Severity

**High**

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Brute Force | T1110 |

---

## 📂 Data Sources

- Windows Security Event Logs
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Microsoft Sentinel

---

## 📑 Detection Logic (KQL)

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

---

## ⚙️ Rule Configuration

| Setting | Value |
|----------|-------|
| **Rule Type** | Scheduled Analytics Rule |
| **Rule Name** | Brute Force Login Detection |
| **Severity** | High |
| **Status** | Enabled |
| **Query Frequency** | Every 5 Minutes |
| **Lookup Period** | Last 6 Minutes |
| **Alert Threshold** | Trigger alert if query returns more than 0 results |
| **Event Grouping** | Trigger an alert for each event |

---

## 🧩 Entity Mapping

The analytics rule maps the following entities to improve investigation and incident correlation.

| Entity | Identifier |
|---------|------------|
| Account | Account Name |
| IP Address | Source IP Address |

Entity mapping enriches Microsoft Sentinel incidents by automatically associating affected user accounts and source IP addresses with the generated alert, providing analysts with additional investigation context.

---

## 🔄 Detection Workflow

```text
Failed Windows Logon Attempt
            │
            ▼
Windows Security Log (Event ID 4625)
            │
            ▼
Azure Monitor Agent (AMA)
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel executes scheduled KQL query
            │
            ▼
5 or more failed logon attempts detected within 5 minutes
            │
            ▼
Alert Generated
            │
            ▼
Incident Created
            │
            ▼
Automation Rule Triggered
            │
            ▼
SOC Analyst Assigned & Investigation Begins
```

---

## 🚨 Alert Trigger Conditions

An alert is generated when all of the following conditions are met:

- Windows Security Event **4625 (Failed Logon)** is generated.
- Five or more failed authentication attempts occur within a **5-minute** time window.
- The scheduled KQL query returns one or more matching results.

---

## 📋 Incident Configuration

To improve alert management and reduce duplicate incidents, Microsoft Sentinel is configured to:

- Automatically create an incident when the rule is triggered.
- Group related alerts based on the affected **Account** entity.
- Correlate similar authentication failures into a single investigation.
- Maintain incident context for efficient triage.

---

## 🤖 Automated Response

When an incident is created:

- The configured **Automation Rule** is executed.
- Incident ownership is automatically assigned.
- Additional playbooks, such as email notifications, can be triggered to notify SOC analysts.

---

## ✅ Validation

The detection was validated by intentionally performing multiple failed Windows logon attempts against the monitored endpoint. Microsoft Sentinel successfully generated an alert, created an incident, and executed the configured automation rule after the detection threshold was reached.

---

## 🎯 Security Impact

This detection helps security teams:

- Detect brute-force and password guessing attacks.
- Identify targeted user accounts.
- Track malicious source IP addresses.
- Reduce the likelihood of unauthorized access.
- Improve incident response through automated alerting and investigation.

---

## 📸 Screenshots

### Rule Overview

> *(Insert Screenshot)*

### MITRE ATT&CK Mapping

> *(Insert Screenshot)*

### KQL Query

> *(Insert Screenshot)*

### Entity Mapping

> *(Insert Screenshot)*

### Query Scheduling

> *(Insert Screenshot)*

### Incident Settings

> *(Insert Screenshot)*

### Automation Rule

> *(Insert Screenshot)*

### Review & Create

> *(Insert Screenshot)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
