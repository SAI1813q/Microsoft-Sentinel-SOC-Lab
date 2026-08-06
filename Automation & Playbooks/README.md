
# 🤖 Playbooks & Automation

## 📖 Overview

Microsoft Sentinel Playbooks and Automation Rules extend the capabilities of a traditional SIEM by introducing **Security Orchestration, Automation, and Response (SOAR)**. They automate repetitive incident response tasks, reduce manual effort, and ensure security events are handled consistently according to predefined workflows.

This project implements both **Microsoft Sentinel Automation Rules** and **Azure Logic Apps** to automate incident triage and analyst notification. Automation Rules are used to update incident properties, assign owners, and add contextual information, while Logic Apps provide external notifications and integrate Microsoft Sentinel with other services.

Each automation documented below includes its purpose, configuration, execution workflow, validation, and supporting screenshots.

---

# 📋 Playbooks & Automation Summary

| Type | Automation / Playbook | Purpose | Status |
|------|------------------------|---------|:------:|
| ⚙️ Automation Rule | [User Added to Local Administrators](User-Added-To-Local-Administrators/README.md) | Automatically assigns privilege escalation incidents to the designated SOC analyst and updates the incident status. | ✅ |
| ⚙️ Automation Rule | [Brute Force Mitigation](Brute-Force-Mitigation/README.md) | Automatically assigns brute-force incidents to an analyst for investigation. | ✅ |
| ⚙️ Automation Rule | [Firewall Disabled](Firewall-Disabled/README.md) | Automatically creates an investigation task when firewall tampering is detected. | ✅ |
| ⚙️ Automation Rule | [Known IP Address](Known-IP-Address/README.md) | Automatically updates incident status for known or trusted IP detections. | ✅ |
| ⚙️ Automation Rule | [Account Compromise](Account-Compromise/README.md) | Automatically applies contextual tags to suspected account compromise incidents. | ✅ |
| ⚙️ Automation Rule | [Add Triage Tag](Add-Triage-Tag/README.md) | Automatically applies triage tags to correlation incidents for improved visibility. | ✅ |
| 📩 Logic App | [SOC Email Notification](Notification-Playbook/README.md) | Sends an automated email notification to the SOC analyst whenever a Microsoft Sentinel incident is created. | ✅ |

---

## 📊 Automation Summary

| Category | Count |
|----------|------:|
| Automation Rules | 6 |
| Logic Apps | 1 |
| Automated Notifications | 1 |
| Automated Incident Assignment | 2 |
| Automated Tagging Rules | 2 |
| Investigation Task Automation | 1 |

---
