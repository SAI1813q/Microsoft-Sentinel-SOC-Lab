
# 🛡️ Threat Coverage (MITRE ATT&CK)

## 📖 Overview

To ensure standardized threat detection and investigation, every Microsoft Sentinel Analytics Rule developed in this project has been mapped to the **MITRE ATT&CK Framework**. Mapping detections to MITRE ATT&CK enables security analysts to understand the adversary's objectives, identify attack patterns, and prioritize incident response based on the stage of the attack lifecycle.

The analytics rules implemented in this lab provide detection coverage across multiple ATT&CK tactics, including **Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, and Lateral Movement**.

---

# 📊 MITRE ATT&CK Detection Coverage

| Analytics Rule | MITRE ATT&CK Technique | Technique ID | Tactic |
|---------------|------------------------|--------------|--------|
| Brute Force Login Detection | Brute Force | T1110 | Credential Access |
| Successful Login After Brute Force | Password Guessing,Valid Accounts | T1110.001,T1078| Credential Access |
| New Local User Creation | Create Account | T1136.001 | Persistence |
| Encoded PowerShell Detection | PowerShell | T1059.001 | Execution |
| Download Cradle Detection | Ingress Tool Transfer | T1105 | Command and Control |
| Mimikatz Detection | OS Credential Dumping | T1003 | Credential Access |
| PsExec Detection | SMB/Windows Admin Shares | T1021.002 | Lateral Movement |
| Registry Run Key Persistence | Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| Scheduled Task Creation | Scheduled Task | T1053.005 | Persistence |
| Event Log Cleared Detection | Clear Windows Event Logs | T1070.001 | Defense Evasion |
| New Windows Service Installed | Create or Modify System Process: Windows Service | T1543.003 | Persistence |
| Suspicious Discovery Commands | System Network Configuration Discovery | T1016 | Discovery |
| Suspicious Discovery Commands | System Owner/User Discovery | T1033 | Discovery |
| Suspicious Discovery Commands | System Information Discovery | T1082 | Discovery |
| Suspicious Discovery Commands | Account Discovery | T1087 | Discovery |
| Kerberoasting Detection | Kerberoasting | T1558.003 | Credential Access |
| AS-REP Roasting Detection | AS-REP Roasting | T1558.004 | Credential Access |
| Domain Admin Group Modification | Account Manipulation | T1098 | Persistence |

---

# 📈 ATT&CK Tactic Coverage Summary

| ATT&CK Tactic | Coverage |
|--------------|:--------:|
| Execution | ✅ |
| Persistence | ✅ |
| Credential Access | ✅ |
| Discovery | ✅ |
| Lateral Movement | ✅ |
| Defense Evasion | ✅ |
| Command and Control | ✅ |

---

# 📊 Coverage Statistics

| Metric | Value |
|--------|------:|
| Analytics Rules Developed | 16+ |
| MITRE ATT&CK Techniques Covered | 15+ |
| ATT&CK Tactics Covered | 7 |
| Detection Validation Completed | 100% |

---

# 🎯 Why MITRE ATT&CK Mapping?

Mapping detections to the MITRE ATT&CK Framework provides several benefits:

- Standardizes detection engineering using an industry-recognized framework.
- Helps SOC analysts understand attacker behavior throughout the attack lifecycle.
- Simplifies threat hunting by organizing detections according to adversary techniques.
- Enables quick identification of detection gaps and opportunities for improvement.
- Improves incident triage by providing tactical and technical context for every alert.

---

## 🔗 Related Documentation

Each analytics rule includes detailed MITRE ATT&CK mappings, detection logic, entity mappings, rule configuration, and validation screenshots.

➡️ **[View Analytics Rules](../Analytics-Rules/README.md)**

---
