# 🔄 Project Workflow

This section explains the complete lifecycle of log collection, threat detection, incident creation, and automated response within the Microsoft Sentinel SOC Lab.

---

## Workflow Overview

```text
                     ┌───────────────────────┐
                     │   Attack Simulation   │
                     │(Atomic Red Team,      │
                     │Mimikatz, PsExec, etc.)│
                     └──────────┬────────────┘
                                │
                                ▼
                     ┌───────────────────────┐
                     │ Windows Endpoints &   │
                     │ Domain Controller     │
                     └──────────┬────────────┘
                                │
                                ▼
                     ┌───────────────────────┐
                     │ Azure Monitor Agent   │
                     │        (AMA)          │
                     └──────────┬────────────┘
                                │
                                ▼
                     ┌───────────────────────┐
                     │ Data Collection Rules │
                     │        (DCR)          │
                     └──────────┬────────────┘
                                │
                                ▼
                     ┌───────────────────────┐
                     │ Log Analytics         │
                     │ Workspace             │
                     └──────────┬────────────┘
                                │
               ┌────────────────┴────────────────┐
               ▼                                 ▼
      ┌──────────────────┐              ┌─────────────────┐
      │ Microsoft        │              │ Workbooks &     │
      │ Sentinel         │              │ Dashboards      │
      └────────┬─────────┘              └─────────────────┘
               │
               ▼
      ┌──────────────────┐
      │ Analytics Rules  │
      └────────┬─────────┘
               │
               ▼
      ┌──────────────────┐
      │ Correlation      │
      │ Rules            │
      └────────┬─────────┘
               │
               ▼
      ┌──────────────────┐
      │ Incidents        │
      └────────┬─────────┘
               │
               ▼
      ┌──────────────────┐
      │ Logic App        │
      │ Playbooks        │
      └────────┬─────────┘
               │
               ▼
      ┌──────────────────┐
      │ Email            │
      │ Notification     │
      └──────────────────┘
```

---

## 🗺️ Workflow Explanation

## 1. 🎯 Attack Simulation

The lab simulates real-world attacker behavior using multiple offensive security tools to generate telemetry for detection engineering.

### 🧰 Tools Used

- Atomic Red Team
- Mimikatz
- PsExec
- Rubeus
- Native Windows Commands

These attacks generate Windows Security Events, Sysmon Events, and System Logs.

---

## 2. 📡 Azure Monitor Agent (AMA)

Azure Monitor Agent is installed on every Windows endpoint and Domain Controller.

Its responsibilities include:

- Collecting Security Events
- Collecting System Logs
- Collecting Application Logs
- Collecting Sysmon Events

The agent securely forwards telemetry to Azure Monitor.

---

 ## 3. 📋 Data Collection Rules (DCR)

Data Collection Rules define which events should be ingested into Log Analytics.

Configured DCRs include:

- Windows Security Logs
- Windows System Logs
- Windows Application Logs
- Sysmon Operational Logs

Filtering unnecessary events reduces storage costs while improving query performance.

---

## 4. 🗄️ Log Analytics Workspace

All collected telemetry is stored in a centralized Log Analytics Workspace.

This workspace acts as the primary data source for Microsoft Sentinel.

The workspace enables:

- Log searching
- KQL hunting
- Threat investigations
- Analytics Rules
- Workbooks

---

## 5. 🛡️ Microsoft Sentinel

Microsoft Sentinel provides the cloud-native SIEM and SOAR capabilities for the lab.

Primary functions include:

- Threat Detection
- Incident Management
- Hunting Queries
- Automation
- Visualization

---

## 6. 🔎 Analytics Rules

Custom KQL-based Analytics Rules continuously monitor incoming telemetry.

Examples include:

- Brute Force Detection
- Mimikatz Detection
- PsExec Detection
- Registry Run Key Persistence
- Encoded PowerShell
- Scheduled Task Creation
- Event Log Cleared
- Kerberoasting Detection
- Download Cradle Detection

Each rule is mapped to the MITRE ATT&CK Framework.

---

## 7. 🔗 Correlation Rules

Correlation Rules combine multiple suspicious activities into a single high-confidence incident.

Examples include:

- Brute Force → Successful Login → New Local User
- Mimikatz → PsExec
- New Service → Event Log Cleared
- Encoded PowerShell → Registry Run Key Persistence

This significantly reduces false positives while improving detection fidelity.

---

## 8. 🚨 Incident Creation

When an Analytics Rule or Correlation Rule is triggered, Microsoft Sentinel automatically creates an incident.

Each incident contains:

- Alert Details
- Entities
- Severity
- MITRE ATT&CK Mapping
- Timeline
- Investigation Graph

---

## 9. 🤖 Automated Response

Logic Apps automate incident response by performing predefined actions.

Current automation includes:

- Email Notification
- Incident Enrichment
- Incident Updates

Automation reduces analyst response time and improves operational efficiency.

---

## 10. 🕵️  Investigation & Monitoring

SOC analysts investigate incidents using:

- Sentinel Investigation Graph
- KQL Queries
- Workbooks
- Incident Timeline
- Entity Mapping

These tools provide complete visibility into attacker activity throughout the environment.

---

# 🔄 End-to-End Process

1. Attacker executes malicious activity.
2. Windows generates security events.
3. Azure Monitor Agent collects telemetry.
4. Data Collection Rules forward logs to Azure.
5. Logs are stored in Log Analytics Workspace.
6. Microsoft Sentinel analyzes incoming data.
7. Analytics Rules detect suspicious behavior.
8. Correlation Rules combine related alerts.
9. Microsoft Sentinel creates an Incident.
10. Logic Apps trigger automated response.
11. SOC analyst investigates and responds.

---

# ✅ Outcome

This workflow demonstrates the complete Security Operations Center lifecycle, from attack simulation and telemetry collection to detection engineering, incident creation, automated response, and threat investigation using Microsoft Sentinel.
