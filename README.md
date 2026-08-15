# 🛡️ Microsoft Sentinel SOC Lab

An Azure-based Security Operations Center (SOC) lab focused on Microsoft Sentinel detection engineering, KQL-based threat detection, MITRE ATT&CK mapping, attack simulation, incident investigation, and SOC automation.

---

## 🎯 Project Overview

This project demonstrates the design and implementation of a cloud-based SOC using Microsoft Sentinel, Azure Monitor Agent (AMA), Data Collection Rules (DCRs), Log Analytics, Windows virtual machines, and Active Directory.

Security telemetry is centralized in Log Analytics and monitored through Microsoft Sentinel, where custom analytics rules, multi-stage correlations, automation rules, Logic Apps, and workbooks are used to simulate SOC detection and response workflows.

---

## 📊 Project Highlights

| Capability | Implementation |
|---|---:|
| Custom Analytics Rules | **31** |
| Multi-Stage Correlation Rules | **6** |
| Custom Detection Rules | **37** |
| MITRE ATT&CK Techniques | **31** |
| ATT&CK Tactics | **9** |
| Sentinel Automation Rules | **6** |
| Azure Logic Apps | **2** |

---

## 🏗️ Architecture

The lab collects Windows security telemetry through Azure Monitor Agent and Data Collection Rules into a centralized Log Analytics Workspace connected to Microsoft Sentinel.

**Architecture Flow:**

<img width="1536" height="1024" alt="ChatGPT Image Aug 15, 2026, 12_03_31 AM" src="https://github.com/user-attachments/assets/5877c3ca-a0a6-4d4e-91e0-14ba2b460477" />


**Windows VMs / Active Directory → AMA → DCR → Log Analytics → Microsoft Sentinel → Analytics Rules → Incidents → Automation / Response**

📖 **[View Architecture Documentation](Architecture/README.md)**

---

## 🔍 Detection Engineering

Developed **31 custom KQL-based analytics rules** to detect adversary behaviors across multiple stages of the attack lifecycle.

Detection coverage includes:

- Brute-force authentication
- Successful login after brute force
- Local account creation
- Encoded PowerShell
- Credential dumping
- Mimikatz
- PsExec
- Registry Run Keys
- Scheduled Tasks
- Windows Services
- Event Log Clearing
- Active Directory Enumeration
- Pass-the-Hash
- Pass-the-Ticket
- Kerberoasting
- AS-REP Roasting
- Defender modification
- Firewall modification
- Certutil downloads
- Mshta execution
- Threat-intelligence-based detections

📖 **[View Analytics Rules](Analytics-Rules/README.md)**

---

## 🔗 Multi-Stage Correlation

Built **6 multi-stage correlation rules** that combine related security events to identify higher-confidence attack chains.

Examples include:

- Brute Force → Successful Login → New Local User
- Encoded PowerShell → Registry Run Key
- Mimikatz → PsExec
- New Service → Event Log Cleared
- Certutil Download → Mshta Execution
- Defender Disabled → Firewall Disabled → Mimikatz

📖 **[View Correlation Rules](Correlation%20Rules/README.md)**

---

## 🧠 MITRE ATT&CK Coverage

The detections are mapped to **31 unique MITRE ATT&CK techniques across 9 tactics**.

Coverage includes:

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Command and Control

Threat-intelligence detections that cannot be confidently mapped to a specific ATT&CK technique are documented as **N/A** rather than using an unsupported mapping.

📖 **[View MITRE ATT&CK Coverage](Threat%20Coverage%20%28MITRE%20ATT%26CK%29/README.md)**

---

## 🧪 Attack Simulation & Detection Validation

Controlled attack simulations were performed to validate detection logic and investigate generated Sentinel alerts.

Validation included techniques and tools such as:

- Atomic Red Team
- Mimikatz
- PsExec
- Rubeus
- PowerShell
- Windows native utilities
- Active Directory attack simulations

Detection validation includes investigating generated alerts, reviewing event telemetry, tuning KQL queries, and validating multi-stage correlation logic.

📖 **[View Detection Documentation](Detection/README.md)**

---

## 🤖 SOC Automation & Response

Implemented **6 Microsoft Sentinel Automation Rules and 2 Azure Logic Apps** to support SOC investigation and response workflows.

Automation capabilities include:

- Incident assignment
- Triage tagging
- Investigation task creation
- Automated notifications
- Incident enrichment
- Response and containment workflows

📖 **[View Automation & Playbooks](Automation%20%26%20Playbooks/README.md)**

---

## 📊 Workbooks & Dashboards

Developed Microsoft Sentinel workbooks and dashboards to provide visibility into:

- Authentication activity
- Security detections
- Incidents
- Affected entities
- SOC monitoring metrics

📖 **[View Workbooks & Dashboards](Workbook%20%26%20Dashboard/README.md)**

---

## 🗂️ Project Structure


- **Architecture/** — Azure SOC architecture and telemetry flow
- **Analytics-Rules/** — KQL detection rules and individual analytics rule configuration
- **Correlation-Rules/** — Multi-stage correlation rules combining related detections into attack chains
- **Detection/** — Attack simulation and detection validation
- **Threat Coverage (MITRE ATT&CK)/** — MITRE ATT&CK technique and tactic coverage
- **Automation & Playbooks/** — Sentinel Automation Rules and Azure Logic Apps
- **Workbook & Dashboard/** — SOC monitoring and visualization
- **Project Overview/** — Project goals and scope
- **Project Phases/** — Implementation phases
- **Project Workflow/** — End-to-end SOC workflow
- **Objectives/** — Project objectives
- **Lessons Learned/** — Implementation lessons and findings
- **Future Improvements/** — Planned enhancements
---

## 🛠️ Technologies

- Microsoft Sentinel
- Microsoft Azure
- Log Analytics Workspace
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCRs)
- Kusto Query Language (KQL)
- Windows
- Active Directory
- Azure Logic Apps
- MITRE ATT&CK
- Atomic Red Team

---

## 📚 Documentation

| Section | Description |
|---|---|
| 🏗️ [Architecture](Architecture/README.md) | Azure resources, SOC architecture, and telemetry flow |
| 🔍 [Analytics Rules](Analytics-Rules/README.md) | KQL detections, rule configuration, and correlations |
| 🔗 [Correlation Rules](Correlation%20Rules/README.md) | Multi-stage attack-chain detection and correlation logic |
| 🧪 [Detection](Detection/README.md) | Attack simulation and detection validation |
| 🧠 [MITRE ATT&CK](Threat%20Coverage%20%28MITRE%20ATT%26CK%29/README.md) | ATT&CK technique and tactic coverage |
| 🤖 [Automation & Playbooks](Automation%20%26%20Playbooks/README.md) | Automation Rules and Logic Apps |
| 📊 [Workbook & Dashboard](Workbook%20%26%20Dashboard/README.md) | SOC dashboards and monitoring |
| 📋 [Project Overview](Project%20Overview/README.md) | Project scope and objectives |
| 🔄 [Project Workflow](Project%20Workflow/README.md) | End-to-end implementation workflow |

---

## ⚠️ Disclaimer

This project is a controlled cybersecurity lab created for learning and demonstration purposes. Attack simulations were performed against authorized lab infrastructure and should not be conducted against systems without authorization.
