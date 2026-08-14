# 🛡️ Microsoft Sentinel SOC Lab

An Azure-based Security Operations Center (SOC) lab built with Microsoft Sentinel to simulate enterprise security monitoring, detection engineering, attack investigation, MITRE ATT&CK mapping, incident response, and SOC automation.

![SOC Architecture](<img width="1536" height="1024" alt="ChatGPT Image Aug 15, 2026, 12_03_31 AM" src="https://github.com/user-attachments/assets/72d51c5a-92ca-41eb-9488-132c95a66443" />
)

---

## 🎯 Project Overview

This project demonstrates the design and implementation of a cloud-based SOC using Microsoft Sentinel, Azure Monitor Agent (AMA), Log Analytics, Windows Server and Windows 10 virtual machines, including an Active Directory domain controller, send Windows Security Event telemetry through Azure Monitor Agent and Data Collection Rules into a centralized Log Analytics Workspace connected to Microsoft Sentinel.

The lab simulates real-world attack techniques and builds detections, correlations, investigations, dashboards, and automated response workflows around them.

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
| Brute-Force Events Investigated | **68,000+** |

---

## 🏗️ SOC Architecture

The lab collects security telemetry from Windows endpoints and Active Directory through Azure Monitor Agent and Data Collection Rules into a centralized Log Analytics workspace connected to Microsoft Sentinel.

![SOC Architecture](Architecture/images/architecture.png)

**Architecture flow:**

`Windows / AD → AMA → DCR → Log Analytics → Microsoft Sentinel → Analytics Rules → Incidents → Automation / Response`

📖 **[View Architecture Documentation](Architecture/README.md)**

---

## 🔍 Detection Engineering

Developed **31 custom KQL-based analytics rules** covering multiple stages of the attack lifecycle, including:

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

Built **6 correlation rules** to increase detection confidence by combining related behaviors into attack chains.

Examples include:

- Brute Force → Successful Login → New Local User
- Encoded PowerShell → Registry Run Key
- Mimikatz → PsExec
- New Service → Event Log Cleared
- Certutil Download → Mshta Execution
- Defender Disabled → Firewall Disabled → Mimikatz

📖 **[View Correlation Rules](Analytics-Rules/README.md)**

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

📖 **[View MITRE ATT&CK Coverage](Threat%20Coverage%20%28MITRE%20ATT%26CK%29/README.md)**

---

## 🤖 SOC Automation & Response

Implemented **6 Microsoft Sentinel Automation Rules and 2 Azure Logic Apps** to support SOC workflows such as:

- Incident assignment
- Triage tagging
- Investigation task creation
- Automated notifications
- Incident enrichment
- Response and containment workflows

📖 **[View Automation & Playbooks](Automation%20%26%20Playbooks/README.md)**

---

## 🧪 Attack Simulation & Detection Validation

The lab uses controlled attack simulations to validate detection logic and investigate generated alerts.

Tools and techniques include:

- Atomic Red Team
- Mimikatz
- PsExec
- Rubeus
- PowerShell
- Windows native utilities
- Active Directory attack simulations

📖 **[View Detection Validation](Detection/README.md)**

---

## 📈 SOC Monitoring & Investigation

Investigated **68,000+ brute-force RDP events** and built Sentinel workbooks to visualize authentication activity, detections, incidents, affected entities, and SOC monitoring metrics.

📖 **[View Workbooks & Dashboards](Workbook%20%26%20Dashboard/README.md)**

---

## 🗂️ Project Structure

```text
Microsoft-Sentinel-SOC-Lab/
│
├── Architecture/
│   └── README.md
│
├── Analytics-Rules/
│   └── README.md
│
├── Detection/
│   └── README.md
│
├── Threat Coverage (MITRE ATT&CK)/
│   └── README.md
│
├── Automation & Playbooks/
│   └── README.md
│
└── Workbook & Dashboard/
    └── README.md

```
---

## 🛠️ Technologies

- Microsoft Sentinel
- Microsoft Azure
- Log Analytics
- Azure Monitor Agent (AMA)
- Data Collection Rules (DCR)
- Kusto Query Language (KQL)
- Windows Server / Windows
- Active Directory
- Sysmon
- Azure Logic Apps
- MITRE ATT&CK
- Atomic Red Team

---

## 📚 Documentation

| Section | Description |
|---|---|
| 🏗️ [Architecture](Architecture/README.md) | SOC architecture, Azure resources, and telemetry flow |
| 🔍 [Analytics Rules](Analytics-Rules/README.md) | KQL detections and rule configuration |
| 🧪 [Detection](Detection/README.md) | Attack simulation and detection validation |
| 🧠 [MITRE ATT&CK](Threat%20Coverage%20%28MITRE%20ATT%26CK%29/README.md) | ATT&CK technique and tactic coverage |
| 🤖 [Automation & Playbooks](Automation%20%26%20Playbooks/README.md) | Automation Rules and Logic Apps |
| 📊 [Workbook & Dashboard](Workbook%20%26%20Dashboard/README.md) | SOC dashboards and monitoring |

---

## ⚠️ Disclaimer

This project is a controlled cybersecurity lab created for learning and demonstration purposes. Attack simulations were performed against lab infrastructure and should not be conducted against systems without authorization.
