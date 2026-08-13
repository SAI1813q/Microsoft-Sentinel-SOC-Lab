
# 📊 Microsoft Sentinel Workbooks

The project includes custom Microsoft Sentinel Workbooks designed to provide centralized visibility into security events, threat detections, incident activity, and SOC response operations.

The dashboards are built using **Azure Workbooks + KQL** and are connected to the Microsoft Sentinel Log Analytics workspace.

---

# 🏗️ Workbook Architecture

```text
                    Microsoft Sentinel
                           │
                           ▼
                  Log Analytics Workspace
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
        Security Events            Sentinel Incidents
             │                           │
             ▼                           ▼
          KQL Queries              Automation Rules
             │                           │
             └─────────────┬─────────────┘
                           │
                           ▼
                    Azure Workbooks
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
   SOC Overview      Threat Detection    Incident Response
     Dashboard          Dashboard          & Automation
```

---
## 📁 Workbook Overview

| Workbook | Purpose | Key Areas |
|---|---|---|
| [SOC Overview Dashboard](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Workbook%20&%20Dashboard/README.md#-soc-overview-workbook) | Provides a high-level view of the SOC environment | Incidents, severity, affected hosts, attack activity |
| [Threat Detection Dashboard](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Workbook%20&%20Dashboard/README.md#-threat-detection-dashboard) | Provides visibility into security detections and attacker activity | Authentication, endpoint threats, lateral movement |
| [Incident Response & Automation Dashboard](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Workbook%20&%20Dashboard/README.md#%EF%B8%8F-3-incident-response--automation-dashboard) | Tracks incident handling and SOC automation | Incident lifecycle, assignments, playbooks, response activity |

---

# 📊 SOC Overview Workbook

This Microsoft Sentinel workbook provides a centralized view of security activity across the SOC environment. It summarizes incidents, severity, affected hosts, targeted accounts, alert rules, and incident trends to support continuous security monitoring and investigation.

---

## 🎯 Purpose

The **SOC Overview Workbook** provides SOC analysts with a high-level view of the security posture of the environment.

It helps analysts quickly identify:

- 🚨 Overall incident volume
- ⚠️ High-severity incidents
- 🖥️ Most affected hosts
- 👤 Most targeted accounts
- 🔎 Top triggered analytics rules
- 📈 Incident activity over time
- 📊 Incident and severity distribution

**Time Range:** Last 30 Days

---

## 📊 SOC Summary

The workbook begins with a high-level summary of Microsoft Sentinel incidents.

| Metric | Description |
|---|---|
| 🚨 **Total Incidents** | Total number of incidents generated during the selected time range |
| 🔴 **High Severity** | Number of high-severity incidents |
| 🟢 **Active Incidents** | Incidents that are currently open or active |
| ✅ **Closed Incidents** | Incidents that have been closed |

### Current Dashboard Snapshot

| Metric | Count |
|---|---:|
| 🚨 Total Incidents | **260** |
| 🟢 Active Incidents | **258** |
| 🔴 High Severity | **175** |
| ✅ Closed Incidents | **2** |

---

## 🖥️ Top Affected Hosts

This section identifies the computers associated with the highest volume of security activity.

| Host | Activity Count |
|---|---:|
| 🖥️ `DC.root.project` | 287,318 |
| 🖥️ `Vm1.root.project` | 44,936 |

This helps analysts identify systems generating significant security telemetry and prioritize investigation of potentially targeted or compromised assets.

---

## 📋 Incident Status

The Incident Status section provides a breakdown of incidents based on their current state.

| Status | Count |
|---|---:|
| 🆕 New | 258 |
| ✅ Closed | 2 |

This provides a quick indication of the current SOC workload and the number of incidents requiring analyst attention.

---

## 📈 Incident Trends

The Incident Trends section tracks the number of incidents generated over time.

This allows analysts to:

- 📊 Identify spikes in security activity
- 📈 Monitor changes in incident volume
- 🕒 Correlate increases in incidents with simulated attack activity
- 🔎 Identify periods requiring further investigation

### Observed Incident Activity

| Date | Incidents |
|---|---:|
| 07/24/2026 | 64 |
| 07/25/2026 | 14 |
| 07/28/2026 | 15 |
| 07/29/2026 | 23 |
| 07/30/2026 | 9 |
| 07/31/2026 | 6 |
| 08/01/2026 | 122 |
| 08/06/2026 | 7 |

The significant increase on **08/01/2026** represents a notable spike in detected security activity and can be used as an investigation point.

---

## ⚠️ Severity Distribution

This section shows how incidents are distributed across severity levels.

| Severity | Count |
|---|---:|
| 🟡 Medium | 84 |
| 🔴 High | 175 |
| 🔵 Informational | 1 |

The distribution allows analysts to quickly assess the overall severity of detected activity and prioritize high-impact incidents.

---

## 🔎 Top Alert Rules

This section identifies the analytics rules generating the highest number of incidents.

| Analytics Rule | Count |
|---|---:|
| 🔀 WMI Lateral Movement Detection | 55 |
| 📂 SMB Admin Share Access | 46 |
| 🔐 Pass-the-Hash Detection | 21 |
| 🌐 Network Discovery | 19 |
| 🥷 Mimikatz Detection | 16 |
| 👤 User Added to Local Administrators | 15 |
| 📥 Download Cradle Detection | 13 |
| 🔍 Suspicious Discovery Commands | 12 |
| 🔍 Suspicious Discovery Commands | 11 |
| 🔥 Firewall Disabled | 7 |

These detections represent different stages and techniques of adversary activity, including:

- 🔀 Lateral movement
- 🔐 Credential abuse
- 👤 Privilege-related activity
- 🌐 Network discovery
- 🥷 Credential dumping
- 📥 Malicious payload retrieval
- 🔥 Security control modification

---

## 👤 Top Targeted Accounts

This section identifies accounts associated with the highest volume of detected activity.

| Account | Count |
|---|---:|
| 👤 `220029` | 220,029 |
| 👤 `-\Administrator` | 41,694 |
| 👤 `PROJECT\Administrator` | 26,094 |
| 👤 `ROOT\Administrator` | 15,228 |
| 👤 `ROOT\DC$` | 3,856 |
| 👤 `ROOT.PROJECT\DC$` | 3,751 |
| 👤 `ROOT\VM1$` | 2,966 |
| 👤 `\ADMINISTRATOR` | 2,957 |
| 👤 `\ADMIN` | 2,956 |
| 👤 `\USER` | 1,405 |

Monitoring targeted accounts helps identify accounts repeatedly involved in authentication attempts and security events.

---

## 🧠 SOC Investigation Workflow

The workbook supports the following investigation flow:

**📊 SOC Overview**  
↓  
**🚨 Review Incident Volume**  
↓  
**⚠️ Check Severity**  
↓  
**🖥️ Identify Affected Hosts**  
↓  
**👤 Identify Targeted Accounts**  
↓  
**🔎 Review Top Alert Rules**  
↓  
**📈 Investigate Activity Spikes**  
↓  
**🕵️ Investigate Related Incidents**  
↓  
**🛡️ Respond and Remediate**

---

## 🛡️ SOC Use Cases

The workbook can be used by SOC analysts for:

- 🚨 **Incident Monitoring** — Monitor current and historical Sentinel incidents.
- ⚠️ **Severity Prioritization** — Identify high-severity security activity.
- 🖥️ **Asset Monitoring** — Identify hosts generating significant security activity.
- 👤 **Account Monitoring** — Identify accounts repeatedly targeted by attacks.
- 🔎 **Detection Monitoring** — Determine which analytics rules are triggering most frequently.
- 📈 **Trend Analysis** — Identify spikes and changes in security activity.
- 🕵️ **Investigation Support** — Use dashboard findings to pivot into Sentinel incidents and KQL investigations.

---

## 📸 Workbook Screenshots

### 📊 SOC Summary

![SOC Summary](./Images/SOC-Summary.png)

### 📈 Incident Trends & Severity Distribution

![Incident Trends](./Images/Incident-Trends.png)

### 🔎 Top Alert Rules & Targeted Accounts

![Top Alert Rules](./Images/Top-Alert-Rules.png)

---

## 🏁 Outcome

The SOC Overview Workbook provides a centralized monitoring layer for the Microsoft Sentinel environment.

It enables analysts to move from **high-level SOC visibility** to **specific hosts, accounts, detections, and incident trends**, supporting faster prioritization and investigation of security events.

---

[⬆️ Back to Top](#Workbook-Overview)


---


# 🔎 Threat Detection Dashboard

The **Threat Detection Dashboard** provides a focused view of security detections generated from Windows Security Events. It helps SOC analysts monitor authentication activity, identify potential attack sources, review targeted accounts, and track endpoint and lateral-movement activity.

---

## 🎯 Purpose

The dashboard is designed to provide visibility into common attack behaviors observed across the monitored Windows environment.

It helps analysts quickly identify:

- 🔐 Authentication failures and successful logons
- 🌐 Top source IP addresses
- 👤 Most targeted accounts
- 💻 Suspicious endpoint activity
- 📝 Registry-based persistence
- ⏰ Scheduled task creation
- 🔀 Lateral movement activity
- 🧹 Event log clearing

**Time Range:** Last 30 Days

---

## 📊 Detection Summary

The Detection Summary provides a high-level view of authentication activity observed during the selected time range.

| Metric | Count |
|---|---:|
| ❌ Failed Logons | **216,681** |
| ✅ Successful Logons | **15,094** |

The large volume of failed logons provides visibility into authentication-based attack activity, while successful logons can be compared against failed authentication patterns to identify potentially suspicious access.

---

## 🔐 Authentication Activity

This section visualizes authentication behavior over time.

### ❌ Failed Login Trend

The Failed Login Trend tracks unsuccessful authentication attempts across the environment.

It can help analysts:

- 📈 Identify spikes in failed authentication
- 🔎 Detect possible brute-force activity
- 🌐 Investigate suspicious source addresses
- 👤 Identify accounts receiving repeated authentication attempts
- 🕒 Correlate authentication spikes with other security events

### ✅ Successful Login Trend

The Successful Login Trend tracks successful authentication events over time.

Analysts can compare successful and failed authentication activity to identify potentially suspicious login patterns and investigate successful access following repeated failed attempts.

---

## 🌐 Attack Activity

The Attack Activity section provides visibility into the sources and accounts involved in authentication-related activity.

### 🌐 Top Source IPs

This visualization identifies the source IP addresses generating the highest volume of authentication activity.

The dashboard includes sources such as:

- `88.214.25.121`
- `88.214.25.124`
- `194.165.16.165`
- `194.165.16.163`
- `194.165.16.162`

This helps analysts identify external or internal systems generating significant authentication activity and prioritize suspicious sources for investigation.

### 👤 Top Target Accounts

This visualization identifies accounts receiving the highest volume of authentication activity.

Examples include:

- `-\Administrator`
- `VADMINISTRATOR`
- `\BACKUP`
- `\admin`

Monitoring targeted accounts can help identify accounts that may be exposed to password spraying, brute-force attempts, or other authentication-based attacks.

---

## 💻 Endpoint Threats

The Endpoint Threats section monitors suspicious activity observed on Windows endpoints.

### 💻 PowerShell Activity

Tracks PowerShell execution activity across the monitored environment.

This can help analysts identify unusual PowerShell activity and investigate potentially suspicious command execution.

### 🔥 Firewall Disabled

Detects activity associated with Windows Firewall being disabled.

Disabling security controls can indicate an attempt to reduce host protections before performing additional malicious activity.

### 📝 Registry Persistence

Tracks registry activity associated with persistence mechanisms.

Registry-based persistence can allow malicious programs or commands to execute automatically when a user logs in or the system starts.

### ⏰ Scheduled Tasks Created

Monitors the creation of scheduled tasks.

Attackers can abuse scheduled tasks to establish persistence or execute commands at a specified time or system event.

---

## 🔀 Lateral Movement

The Lateral Movement section focuses on activity that may indicate an attacker attempting to move between systems.

### 🖥️ PsExec Activity

Tracks PsExec-related activity that may indicate remote command execution.

PsExec can be legitimately used by administrators but can also be abused by attackers for lateral movement and remote execution.

### 🧹 Event Log Cleared

Monitors events associated with Windows event log clearing.

Clearing event logs can be used by attackers to remove evidence of malicious activity and hinder security investigations.

---

## 🧠 SOC Investigation Workflow

The dashboard supports the following investigation process:

**🔎 Review Detection Summary**  
↓  
**🔐 Analyze Failed & Successful Logons**  
↓  
**🌐 Identify Top Source IPs**  
↓  
**👤 Identify Targeted Accounts**  
↓  
**💻 Investigate Endpoint Threats**  
↓  
**🔀 Review Lateral Movement Activity**  
↓  
**🚨 Pivot to Related Sentinel Incidents**  
↓  
**🕵️ Perform KQL Investigation**  
↓  
**🛡️ Respond and Remediate**

---

## 🛡️ SOC Use Cases

The Threat Detection Dashboard supports the following SOC activities:

- 🔐 **Authentication Monitoring** — Monitor failed and successful logon activity.
- 🌐 **Source Analysis** — Identify systems generating large volumes of authentication events.
- 👤 **Account Monitoring** — Identify frequently targeted accounts.
- 💻 **Endpoint Monitoring** — Review suspicious PowerShell, firewall, registry, and scheduled-task activity.
- 📝 **Persistence Detection** — Identify registry and scheduled-task persistence mechanisms.
- 🔀 **Lateral Movement Detection** — Monitor PsExec-related activity.
- 🧹 **Defense Evasion Monitoring** — Identify event log clearing.
- 🕵️ **Threat Investigation** — Pivot from dashboard observations into Sentinel incidents and KQL queries.

---

## 📸 Dashboard Screenshots

### 🔐 Detection Summary & Authentication Activity

![Detection Summary and Authentication Activity](./Images/Threat-Detection-Summary.png)

### 🌐 Attack Activity & Endpoint Threats

![Attack Activity and Endpoint Threats](./Images/Threat-Detection-Activity.png)

### 🔀 Lateral Movement

![Lateral Movement](./Images/Lateral-Movement.png)

---

## 🏁 Outcome

The **Threat Detection Dashboard** provides SOC analysts with a focused view of authentication and endpoint security activity.

It connects **authentication behavior, attack sources, targeted accounts, endpoint threats, persistence mechanisms, and lateral movement indicators** into a single monitoring view, helping analysts identify suspicious activity and quickly pivot into deeper investigation within Microsoft Sentinel.

---


[⬆️ Back to Top](#Workbook-Overview)

---
# 🤖 Incident Response & Automation Dashboard

The **Incident Response & Automation Dashboard** provides a high-level view of incident handling, automated incident assignment, playbook execution, and incident lifecycle activity within Microsoft Sentinel.

---

## 🎯 Purpose

This dashboard helps SOC analysts monitor how security incidents are being handled and how automation is being used to support the incident response process.

It provides visibility into:

- 🚨 Open and closed incidents
- 👤 Automatically assigned incidents
- 🤖 Playbook execution
- 📊 Incident status and severity
- ⚙️ Automation rule activity
- ▶️ Playbook activity
- 🕒 Incident response trends
- ✅ Incident closure activity

**Time Range:** Last 30 Days

---

## 📊 Response Summary

The Response Summary provides a high-level overview of the current incident response workload.

| Metric | Count |
|---|---:|
| 🚨 **Open Incidents** | **216** |
| 👤 **Auto Assigned Incidents** | **4** |
| 🤖 **Playbooks Triggered** | **1** |
| ✅ **Closed Incidents** | **2** |

These metrics provide a quick view of the number of incidents requiring analyst attention and the level of automation currently being used.

---

## 🚨 Incident Management

This section provides a visual breakdown of the current incident lifecycle.

### 📋 Incident Status

The Incident Status visualization shows the distribution of incidents between new and closed states.

| Status | Count |
|---|---:|
| 🆕 New | **258** |
| ✅ Closed | **2** |
| 📊 Total | **260** |

This helps analysts understand the current incident workload and identify the number of incidents that remain unresolved.

### ⚠️ Severity Distribution

The Severity Distribution visualization shows the severity of generated incidents.

| Severity | Count |
|---|---:|
| 🔴 High | **175** |
| 🟡 Medium | **84** |
| 🔵 Informational | **1** |
| 📊 Total | **260** |

The distribution helps SOC analysts prioritize high-severity incidents for investigation and response.

---

## ⚙️ Automation Overview

The Automation Overview section provides visibility into incident assignment and playbook execution.

### 🔧 Automation Rules

This visualization compares incidents that have not been assigned with incidents that were automatically assigned.

| Assignment Type | Count |
|---|---:|
| ⚪ Not Assigned | **214** |
| 🤖 Automatically Assigned | **4** |

This allows analysts to measure how effectively automation rules are being used to distribute incidents for investigation.

### ▶️ Playbook Executions

The Playbook Executions visualization tracks playbook execution activity over time.

**Total Executions:** **4**

Playbook execution monitoring helps verify that automated response workflows are being triggered and executed as expected.

---

## 🤖 Playbook Activity

This section identifies the types of playbook-driven response activity observed in the environment.

The dashboard currently shows activity associated with:

- 🔨 **Brute Force**
- 🥷 **Mimikatz Detection**

This provides visibility into which detections are triggering automated response workflows.

---

## 👤 Automatic Incident Assignment

The Automatic Incident Assignment section identifies the recipients associated with automatically assigned incidents.

The dashboard currently shows automatic assignment activity for:

- 👤 **Akash Bonagiri**
- 📧 **akshakash91744@gmail.com**

This helps verify that incident assignment automation is functioning and that generated incidents are being routed to the intended recipients.

---

## 🕒 Response Timeline

The Response Timeline section provides visibility into incident response and closure activity over time.

### 📈 Incident Response Trend

The Incident Response Trend tracks incident response activity across the selected time range.

It can help analysts:

- 📊 Identify increases in response activity
- 📈 Monitor changes in incident handling volume
- 🕒 Correlate response activity with incident spikes
- 🔎 Identify periods requiring additional investigation

### ✅ Incident Closure Trend

The Incident Closure Trend tracks incident closure activity over time.

This helps analysts monitor:

- ✅ Closed incidents
- 📉 Closure activity
- 🕒 Incident lifecycle progression
- 📊 Overall response performance

---

## 🧠 SOC Investigation & Response Workflow

The dashboard supports the following incident response workflow:

**🚨 Incident Generated**  
↓  
**📋 Incident Classified**  
↓  
**⚠️ Severity Reviewed**  
↓  
**👤 Incident Automatically Assigned**  
↓  
**🤖 Playbook Triggered**  
↓  
**🔎 Analyst Investigation**  
↓  
**🛡️ Response & Remediation**  
↓  
**✅ Incident Closure**

---

## 🛡️ SOC Use Cases

The Incident Response & Automation Dashboard supports:

- 🚨 **Incident Monitoring** — Track open, new, and closed incidents.
- ⚠️ **Severity Prioritization** — Identify high-severity incidents requiring immediate attention.
- 👤 **Automated Assignment Monitoring** — Verify that incidents are being assigned automatically.
- 🤖 **Playbook Monitoring** — Track automated response workflow execution.
- 🔧 **Automation Validation** — Confirm that automation rules are functioning as expected.
- 📈 **Response Trend Analysis** — Monitor incident response activity over time.
- ✅ **Closure Monitoring** — Track incident closure activity and lifecycle progression.
- 🕵️ **SOC Investigation** — Use dashboard findings to pivot into individual Sentinel incidents.

---

## 📸 Dashboard Screenshots

### 🚨 Response Summary & Incident Management

![Response Summary and Incident Management](./Images/Incident-Response-Summary.png)

### ⚙️ Automation & Playbook Activity

![Automation and Playbook Activity](./Images/Automation-Activity.png)

### 🕒 Response Timeline

![Response Timeline](./Images/Response-Timeline.png)

---

## 🏁 Outcome

The **Incident Response & Automation Dashboard** provides visibility into the incident lifecycle and the effectiveness of automated response workflows.

It allows SOC analysts to monitor **incident workload, severity, assignment, playbook execution, response activity, and closure trends** from a centralized Microsoft Sentinel workbook.

The dashboard demonstrates how automation can reduce manual SOC workload while providing visibility into the incident response process.

---

[⬆️ Back to Top](#Workbook-Overview)

---
