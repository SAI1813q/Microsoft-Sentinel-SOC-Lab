
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
