# 🛡️ Threat Coverage (MITRE ATT&CK)

## 📖 Overview

This section documents the MITRE ATT&CK coverage of the Microsoft Sentinel detections implemented in this SOC lab.

The project uses custom KQL-based analytics rules, multi-stage correlation rules, and selected Microsoft Sentinel rule templates to detect adversary behaviors across the attack lifecycle.

MITRE ATT&CK mapping is used to:

- Standardize detection engineering against a recognized adversary behavior framework.
- Provide tactical and technical context for security alerts.
- Support threat hunting and incident investigation.
- Identify detection coverage and gaps across the attack lifecycle.
- Improve correlation and prioritization of multi-stage attack activity.

> **Note:** Threat-intelligence-based detections that do not establish a specific ATT&CK technique are explicitly marked as **N/A** rather than being assigned an unsupported technique.

---

## 📊 MITRE ATT&CK Detection Coverage

### 🔐 Credential Access & Initial Access

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Brute Force Login Detection | Brute Force | T1110 | Credential Access |
| Successful Login After Brute Force | Valid Accounts | T1078 | Initial Access |
| Successful Login After Brute Force | Brute Force: Password Guessing | T1110.001 | Credential Access |
| Password Spray Detection | Brute Force: Password Spraying | T1110.003 | Credential Access |
| Mimikatz Detection | OS Credential Dumping | T1003 | Credential Access |
| Pass-the-Hash Detection | Use Alternate Authentication Material: Pass the Hash | T1550.002 | Lateral Movement |
| Potential Pass-the-Ticket Activity | Use Alternate Authentication Material: Pass the Ticket | T1550.003 | Lateral Movement |
| Kerberoasting Detection | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access |
| AS-REP Roasting Detection | Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 | Credential Access |

---

### ⚙️ Execution

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Encoded PowerShell Detection | Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| WMI Lateral Movement Detection | Windows Management Instrumentation | T1047 | Execution |
| Mshta Execution | System Binary Proxy Execution: Mshta | T1218.005 | Defense Evasion |
| Correlation 3: Mimikatz → PsExec | System Services: Service Execution | T1569.002 | Execution |

---

### 📌 Persistence

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| New Local User Creation | Create Account: Local Account | T1136.001 | Persistence |
| Registry Run Key Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| Scheduled Task Creation | Scheduled Task/Job: Scheduled Task | T1053.005 | Persistence |
| Create or Modify System Process | Create or Modify System Process: Windows Service | T1543.003 | Persistence |
| User Added to Domain Admins | Account Manipulation | T1098 | Persistence |
| User Added to Local Administrators | Account Manipulation | T1098 | Persistence |

---

### 🔎 Discovery

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Network Discovery | System Network Configuration Discovery | T1016 | Discovery |
| Active Directory Computer Enumeration | Remote System Discovery | T1018 | Discovery |

---

### ↔️ Lateral Movement

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| PsExec Detection | SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| SMB Admin Share Access | SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| Potential Pass-the-Ticket Activity | Use Alternate Authentication Material: Pass the Ticket | T1550.003 | Lateral Movement |
| Pass-the-Hash Detection | Use Alternate Authentication Material: Pass the Hash | T1550.002 | Lateral Movement |
| Rule Templates & Machine Learning Behavioral Analytics | Remote Services | T1021 | Lateral Movement |

---

### 🛡️ Defense Evasion

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Event Log Cleared Detection | Indicator Removal on Host: Clear Windows Event Logs | T1070.001 | Defense Evasion |
| Defender Disabled | Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| Firewall Disabled | Impair Defenses: Disable or Modify System Firewall | T1562.004 | Defense Evasion |
| Event Logging Service Shut Down | Impair Defenses: Disable Windows Event Logging | T1562.002 | Defense Evasion |
| Mshta Execution | System Binary Proxy Execution: Mshta | T1218.005 | Defense Evasion |
| Correlation 4: New Service → Event Log Cleared | Indicator Removal on Host: Clear Windows Event Logs | T1070.001 | Defense Evasion |
| Correlation 6: Defender Disabled → Firewall Disabled → Mimikatz | Impair Defenses | T1562 | Defense Evasion |
| Correlation 6: Defender Disabled → Firewall Disabled → Mimikatz | OS Credential Dumping | T1003 | Credential Access |

---

### 📥 Command and Control

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Download Cradle Detection | Ingress Tool Transfer | T1105 | Command and Control |
| PowerShell Download | Ingress Tool Transfer | T1105 | Command and Control |
| Certutil Download | Ingress Tool Transfer | T1105 | Command and Control |
| Correlation 5: Certutil Download → Mshta Execution | Ingress Tool Transfer | T1105 | Command and Control |
| Correlation 5: Certutil Download → Mshta Execution | System Binary Proxy Execution: Mshta | T1218.005 | Defense Evasion |

---

### 👑 Privilege Escalation

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| User Added to Local Administrators | Account Manipulation | T1098 | Privilege Escalation |
| Create or Modify System Process | Create or Modify System Process: Windows Service | T1543.003 | Privilege Escalation |
| Correlation 2: Encoded PowerShell → Registry Run Key | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Privilege Escalation |

---

## 🔗 Multi-Stage Correlation Coverage

| Correlation Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---|---|---|---|
| Correlation 1: Brute Force → Successful Login → New Local User | Brute Force: Password Guessing | T1110.001 | Credential Access |
| Correlation 1: Brute Force → Successful Login → New Local User | Valid Accounts | T1078 | Initial Access |
| Correlation 1: Brute Force → Successful Login → New Local User | Create Account: Local Account | T1136.001 | Persistence |
| Correlation 2: Encoded PowerShell → Registry Run Key | Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| Correlation 2: Encoded PowerShell → Registry Run Key | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| Correlation 3: Mimikatz → PsExec | OS Credential Dumping | T1003 | Credential Access |
| Correlation 3: Mimikatz → PsExec | System Services: Service Execution | T1569.002 | Execution |
| Correlation 4: New Service → Event Log Cleared | Create or Modify System Process: Windows Service | T1543.003 | Persistence |
| Correlation 4: New Service → Event Log Cleared | Indicator Removal on Host: Clear Windows Event Logs | T1070.001 | Defense Evasion |
| Correlation 5: Certutil Download → Mshta Execution | Ingress Tool Transfer | T1105 | Command and Control |
| Correlation 5: Certutil Download → Mshta Execution | System Binary Proxy Execution: Mshta | T1218.005 | Defense Evasion |
| Correlation 6: Defender Disabled → Firewall Disabled → Mimikatz | Impair Defenses | T1562 | Defense Evasion |
| Correlation 6: Defender Disabled → Firewall Disabled → Mimikatz | OS Credential Dumping | T1003 | Credential Access |

---

## 🤖 Rule Templates & Behavioral Analytics

Three pre-built Microsoft Sentinel templates are also configured in the lab:

| Template | Technique Coverage |
|---|---|
| Anomalous RDP Login Detections | Valid Accounts — T1078 |
| Anomalous SSH Login Detection | Remote Services — T1021 |
| Microsoft Defender Threat Intelligence Analytics | Account Manipulation — T1098 / Threat Intelligence |

> **Note:** These are pre-built Microsoft Sentinel templates and are not counted as custom-developed analytics rules.

---

## 🌐 Threat Intelligence Detection

### Suspicious Outbound Connection

The **Suspicious Outbound Connection** rule correlates successful outbound connections from `DeviceNetworkEvents` with active IP indicators in `ThreatIntelligenceIndicator`.

**MITRE ATT&CK Mapping:**

> **N/A — Threat Intelligence-based Detection**

The rule does not establish a specific ATT&CK technique from the available telemetry. It identifies communication with an IP address matching an active threat-intelligence indicator without proving a specific C2 protocol, exfiltration behavior, or tool-transfer technique.

---

## 📈 ATT&CK Tactic Coverage Summary

| ATT&CK Tactic | Coverage |
|---|---|
| Initial Access | ✅ |
| Execution | ✅ |
| Persistence | ✅ |
| Privilege Escalation | ✅ |
| Defense Evasion | ✅ |
| Credential Access | ✅ |
| Discovery | ✅ |
| Lateral Movement | ✅ |
| Command and Control | ✅ |

---

## 📊 Coverage Statistics

| Metric | Value |
|---|---:|
| Custom Analytics Rules Developed | 31 |
| Multi-Stage Correlation Rules | 6 |
| Total Custom Detection Rules | **37** |
| Pre-Built Template Rules | 3 |
| Unique MITRE ATT&CK Techniques Covered | **31** |
| ATT&CK Tactics Covered | **9** |

> **Counting method:** Custom Analytics Rules = 31 standalone rules. Correlation Rules = 6. The three pre-built Microsoft Sentinel templates are excluded from the custom-developed rule count. The MITRE technique count represents unique ATT&CK technique IDs across the documented custom rules and correlations; duplicate mappings across multiple rules are counted once.

---

## 🎯 Why MITRE ATT&CK Mapping?

Mapping detections to MITRE ATT&CK provides several benefits:

- **Standardized Detection Engineering** — Aligns detection logic with a recognized adversary behavior framework.
- **Threat Hunting** — Helps analysts search for related activity based on attacker techniques.
- **Incident Investigation** — Provides tactical and technical context for generated alerts.
- **Detection Gap Analysis** — Helps identify areas where additional detection logic is required.
- **Attack-Chain Visibility** — Correlation rules connect individual techniques into higher-confidence multi-stage detections.
- **SOC Prioritization** — Helps analysts understand where detected behavior fits within the broader attack lifecycle.

---

## 🔄 Detection Coverage Workflow

```text
Adversary Technique
        │
        ▼
Windows / Active Directory / Defender Telemetry
        │
        ▼
Azure Monitor Agent / Defender XDR
        │
        ▼
Log Analytics Workspace
        │
        ▼
Microsoft Sentinel
        │
        ▼
KQL Analytics Rule
        │
        ├──────────────► Individual Technique Detection
        │
        └──────────────► Multi-Stage Correlation
                              │
                              ▼
                       Alert / Incident
                              │
                              ▼
                    MITRE ATT&CK Context
                              │
                              ▼
                    SOC Investigation
                              │
                              ▼
                    Automation / Response
```text

```
## 🧪 Detection Validation

Detection validation includes controlled simulations and testing of behaviors such as:

- Brute-force authentication
- Successful login following failed authentication
- Local account creation
- Encoded PowerShell execution
- Credential dumping
- PsExec execution
- Registry Run Key persistence
- Scheduled task creation
- Windows service installation
- Event log clearing
- Active Directory enumeration
- Pass-the-Hash
- Pass-the-Ticket
- Kerberoasting
- AS-REP Roasting
- Defender modification
- Firewall modification
- Certutil downloads
- Mshta execution
- Multi-stage correlation sequences

Validation screenshots and rule-specific testing details are maintained within the individual analytics-rule documentation.

---

## 🔗 Related Documentation

- **[Analytics Rules](../Analytics-Rules/README.md)** — Detection logic, KQL queries, rule configuration, entity mappings, MITRE mappings, and validation.
- **[Detection](../Detection/README.md)** — Detection validation and alert evidence.
- **[Automation & Playbooks](../Automation%20%26%20Playbooks/README.md)** — Sentinel automation rules and Logic Apps workflows.
- **[Workbook & Dashboard](../Workbook%20%26%20Dashboard/README.md)** — SOC dashboards and visualization.
- **[Architecture](../Architecture/README.md)** — Azure SOC architecture and telemetry flow.

---

## 📌 Summary

The SOC lab combines individual analytics rules with multi-stage correlation to provide ATT&CK-aligned detection coverage across **9 tactics and 31 unique techniques**.

The detection architecture focuses on identifying attacker behavior across authentication, execution, persistence, credential access, discovery, lateral movement, defense evasion, privilege escalation, and command-and-control activity.

Threat-intelligence detections that cannot be confidently assigned to a specific ATT&CK technique are explicitly marked **N/A** instead of being artificially mapped.
