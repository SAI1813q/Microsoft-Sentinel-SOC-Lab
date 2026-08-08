
# 📊 Microsoft Sentinel Workbooks

The project includes custom Microsoft Sentinel Workbooks designed to provide centralized visibility into security events, threat detections, incident activity, and SOC response operations.

The dashboards are built using **Azure Workbooks + KQL** and are connected to the Microsoft Sentinel Log Analytics workspace.

---

## 📁 Workbook Overview

| Workbook | Purpose | Key Areas |
|---|---|---|
| [SOC Overview Dashboard](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Workbook%20&%20Dashboard/README.md#%EF%B8%8F-1-soc-overview-dashboard) | Provides a high-level view of the SOC environment | Incidents, severity, affected hosts, attack activity |
| [Threat Detection Dashboard](#-2-threat-detection-dashboard) | Provides visibility into security detections and attacker activity | Authentication, endpoint threats, lateral movement |
| [Incident Response & Automation Dashboard](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Workbook%20&%20Dashboard/README.md#%EF%B8%8F-3-incident-response--automation-dashboard) | Tracks incident handling and SOC automation | Incident lifecycle, assignments, playbooks, response activity |

---

# 🛡️ 1. SOC Overview Dashboard

The **SOC Overview Dashboard** provides a centralized view of the overall security posture and incident activity within the Microsoft Sentinel environment.

### Key Metrics

- Total incidents
- Active incidents
- Closed incidents
- High-severity incidents
- Incident status distribution
- Top affected hosts
- Incident trends
- Severity distribution

### Attack Activity

The dashboard also provides visibility into:

- Top source IP addresses
- Most targeted accounts
- Authentication activity
- Attack trends over time

### Endpoint Threats

The Endpoint Threats section provides visibility into important endpoint-based detections:

- PowerShell Activity
- Firewall Disabled
- Registry Persistence
- Scheduled Tasks Created

### Lateral Movement

The dashboard also tracks lateral movement-related activity:

- PsExec Activity
- Event Log Cleared

### Purpose

This workbook acts as the **SOC command-center dashboard**, allowing an analyst to quickly understand:

> **What is happening, how severe it is, what systems are affected, and which accounts are being targeted.**
---

[⬆️ Back to Top](#Workbook-Overview)


---


# 🔎 2. Threat Detection Dashboard

The **Threat Detection Dashboard** focuses specifically on security detections generated from Windows Security Events and Microsoft Sentinel analytics rules.

## Detection Summary

The dashboard provides visibility into:

- Failed logons
- Successful logons
- Authentication activity
- Failed login trends
- Successful login trends

This allows analysts to identify authentication anomalies and potential brute-force activity.

## Attack Activity

### Top Source IPs

Displays the IP addresses generating the highest volume of security activity.

### Top Target Accounts

Displays accounts most frequently targeted by authentication attempts.

This helps identify potentially targeted privileged or administrative accounts.

## Endpoint Threats

The Endpoint Threats section contains detection trends for:

| Detection | Purpose |
|---|---|
| PowerShell Activity | Monitor suspicious PowerShell execution |
| Firewall Disabled | Detect attempts to disable Windows Firewall |
| Registry Persistence | Detect persistence through registry mechanisms |
| Scheduled Tasks Created | Identify scheduled-task-based persistence |

## Lateral Movement

The dashboard monitors activity associated with lateral movement techniques:

- PsExec Activity
- Event Log Clearing

### Purpose

This workbook is designed for the **detection and investigation phase of SOC operations**, allowing analysts to move from high-level trends into specific attack techniques and detection categories.

---

[⬆️ Back to Top](#Workbook-Overview)

---
# ⚙️ 3. Incident Response & Automation Dashboard

The **Incident Response & Automation Dashboard** provides visibility into the incident lifecycle and automation capabilities implemented in Microsoft Sentinel.

## Response Summary

Key metrics include:

- Open incidents
- Automatically assigned incidents
- Playbooks triggered
- Closed incidents

## Incident Management

The dashboard visualizes:

- Incident status
- Severity distribution
- New vs. closed incidents
- High and medium severity incidents

## Automation Overview

The automation section tracks:

- Automation rule activity
- Automatically assigned incidents
- Unassigned incidents
- Playbook executions

## Playbook Activity

The dashboard provides visibility into playbook execution associated with security incidents.

Examples include automation associated with:

- Brute-force detection
- Mimikatz detection
- Incident assignment
- Incident enrichment

## Response Timeline

The workbook also provides:

- Incident response trends
- Incident closure trends
- Automation execution activity

### Purpose

This workbook demonstrates how the SOC moves from:

**Detection → Incident Creation → Assignment → Automation → Response → Closure**

rather than treating detection as the end of the process.

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

[⬆️ Back to Top](#Workbook-Overview)

---
