
# 🔗 Correlation Rules

## 📖 Overview

This section documents the multi-stage correlation rules implemented in Microsoft Sentinel to identify related security events that, when observed together, provide stronger evidence of an attack than individual detections alone.

The correlation rules combine multiple analytics detections using KQL-based logic and temporal relationships to identify higher-confidence attack chains.

---

## 📊 Correlation Rules

| # | Correlation Rule | Attack Chain | Rule |
|---|---|---|---|
| 1 | Brute Force → Successful Login → New Local User | Credential Attack → Account Creation | [View Rule](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Correlation%20Rules/README.md#-correlation-1-brute-force--successful-login--new-local-user) |
| 2 | Encoded PowerShell → Registry Run Key | Execution → Persistence | [View Rule](#-correlation-2--encoded-powershell--registry-run-key) |
| 3 | Mimikatz → PsExec | Credential Dumping → Service Execution | [View Rule](#-correlation-3--mimikatz--psexec) |
| 4 | New Service → Event Log Cleared | Service Creation → Evidence Removal | [View Rule](#-correlation-4--new-service--event-log-cleared) |
| 5 | Certutil Download → Mshta Execution | Payload Transfer → Proxy Execution | [View Rule](#-correlation-5--certutil-download--mshta-execution) |
| 6 | Defender Disabled → Firewall Disabled → Mimikatz | Defense Impairment → Credential Dumping | [View Rule](#-correlation-6--defender-disabled--firewall-disabled--mimikatz) |



---
# 🔗 Correlation 1: Brute Force → Successful Login → New Local User

## 🎯 Objective
This core analytics rule correlates three distinct stages of a multi-phase attack chain: multiple failed login attempts (Brute Force), a subsequent successful login using those compromised credentials, and the immediate creation of a new local user account for persistence. It serves as a cornerstone detection for end-to-end account compromise and privilege lifecycle tracking.

---

## 📖 Threat Overview
Advanced threat actors rarely rely on a single isolated action. A common kill chain involves cracking an account password via automated brute-force techniques (Event ID `4625`), authenticating successfully into the system with the guessed credentials (Event ID `4624`), and immediately creating a backdoored local user account (Event ID `4720`) to maintain persistent access. Correlating these sequential events within a tight time window dramatically reduces false positives and highlights high-fidelity active intrusions.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 160644" src="https://github.com/user-attachments/assets/af238672-eec3-4a46-a6b6-684d45669dfe" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access | Valid Accounts | T1078 |
| Persistence | Create Account: Local Account | T1136.001 |


---

## 📂 Data Sources
* Windows Security Event Logs:
  * Event ID `4625` (An account failed to log on)
  * Event ID `4624` (An account was successfully logged on)
  * Event ID `4720` (A user account was created)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following advanced KQL query uses multiple `let` statements and inner joins to link brute-force attempts (10+ failures in 10 minutes) with a successful logon and subsequent account creation within defined time windows:

    let BruteForce = 
    SecurityEvent
    | where EventID == 4625
    | summarize FailedAttempts = count() by Account, Computer, bin(TimeGenerated, 10m)
    | where FailedAttempts >= 10;
    let SuccessLogin = 
    SecurityEvent
    | where EventID == 4624
    | project LoginTime = TimeGenerated, Account, Computer;
    let NewUser = 
    SecurityEvent
    | where EventID == 4720
    | project UserCreatedTime = TimeGenerated, Account, Computer;
    BruteForce
    | join kind=inner SuccessLogin on Account, Computer
    | where LoginTime between (TimeGenerated .. TimeGenerated + 10m)
    | join kind=inner NewUser on Account, Computer
    | where UserCreatedTime between (LoginTime .. LoginTime + 10m)
    | project Account, Computer, FailedAttempts, LoginTime, UserCreatedTime

<img width="1920" height="1020" alt="Screenshot 2026-08-04 160757" src="https://github.com/user-attachments/assets/555fd850-ede8-4c90-a471-daaffe5558af" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Evaluates sequential cross-event correlation logic over historical time blocks. |
| **Run Query Every** | 5 Minutes | Continuously checks for multi-stage attack patterns. |
| **Lookup Data From** | Last 6 Minutes | Includes a 1-minute overlap buffer to capture trailing ingested logs safely. |
| **Severity** | High | A brute-force attack followed by successful access and local account creation indicates active compromise. |
| **Status** | Enabled | Ensures the correlation rule is actively running. |

<img width="1920" height="1020" alt="Screenshot 2026-08-04 160954" src="https://github.com/user-attachments/assets/cb20efb6-3ca4-4b3e-ba2d-7835f2309b18" />


---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide comprehensive correlation context.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |

### Why map these entities?
* **Account:** Identifies the target user account compromised during the brute-force attack and used to spawn the new user.
* **Host:** Highlights the specific endpoint or domain controller where the entire sequence took place.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 160813" src="https://github.com/user-attachments/assets/d23e059a-c63e-459d-b6ed-0e946b8286e4" />

---

## 🔄 Detection Workflow

    Attacker performs brute-force attack against target account (>= 10 failures)
                │
                ▼
    Attacker logs in successfully using cracked credentials
                │
                ▼
    Attacker creates a new local user account for persistence within 10 minutes
                │
                ▼
    Microsoft Sentinel Scheduled Rule correlates events across 4625, 4624, and 4720 logs
                │
                ▼
    Alert Generated combining the complete attack chain
                │
                ▼
    Incident Created (Grouped by matching entities)
                │
                ▼
    Automated Response Triggered (Add Triage Tag)
                │
                ▼
    SOC Analyst Assigned & Host Isolation / Account Revocation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* 10 or more failed login events (`4625`) occur for an account on a host within a 10-minute bin.
* A successful login (`4624`) for that same account/host occurs within 10 minutes of the brute force window.
* A new user account creation event (`4720`) occurs within 10 minutes of the successful login.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Multi-stage attacks represent high-priority intrusions. Disabling alert grouping ensures that every unique correlated attack chain triggers an immediate, individual incident ticket for the SOC without merging related alerts.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 162315" src="https://github.com/user-attachments/assets/fcef389a-4ad3-4c85-af41-d69c2a1d7d8c" />

---

## 🤖 Automated Responses
This core correlation rule is integrated with the following automation:
* **Add Triage Tag:** Automatically appends triage tags upon incident creation to prioritize analytical review.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 161206" src="https://github.com/user-attachments/assets/28ae47a9-43c6-453d-8ddc-4758d6a34797" />

---

## ✅ Validation
This rule can be validated in a test lab by simulating the exact sequence: executing 10+ failed password attempts on a test account, logging in successfully with the correct password immediately after, and creating a new local user via `net user`. Sentinel will join the timeline and trigger the correlated high-severity alert.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 161213" src="https://github.com/user-attachments/assets/e19198d5-93dd-4782-bb83-ff28a59d597d" />

---

## 🎯 Security Impact
This correlation rule helps security teams:
* Detect end-to-end multi-phase account takeovers rather than treating logs in isolation.
* Uncover stealthy persistence attempts immediately following credential compromise.
* Prioritize high-fidelity triage tickets backed by multiple correlated Windows security events.

---



⬆️ [Back to Correlation Rules](#-correlation-rules)

---

# 🔗 Correlation 2: Encoded PowerShell → Registry Run Key

## 🎯 Objective
This core correlation rule tracks a sophisticated multi-stage attack sequence: execution via obfuscated or encoded PowerShell commands followed closely by the establishment of persistence via Registry Run Keys. It connects execution mechanics with survival mechanisms to flag active threats.

---

## 📖 Threat Overview
Attackers frequently use encoded PowerShell commands (using flags like `-enc` or `-encodedcommand`) to bypass script block logging, evade signature detection, and download or execute malicious payloads. To ensure survivability across reboots, they then modify the Windows Registry (such as keys under `CurrentVersion\Run`) to automatically execute that payload every time the system starts. Correlating these two telemetry streams catches the transition from initial execution to persistent compromise.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 161718" src="https://github.com/user-attachments/assets/d03a01f8-724b-4c1f-b66f-ef537ff37715" />


---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence, Privilege Escalation | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 |




---

## 📂 Data Sources
* Windows Security Event Logs:
  * Event ID `4688` (Process Creation - monitoring PowerShell execution syntax)
  * Event ID `4657` (A registry value was modified - tracking modifications under `CurrentVersion\Run`)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following advanced KQL query correlates encoded PowerShell process executions with subsequent registry modifications within a 10-minute window on the same host and account:

    let PowerShell = 
    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any ("-enc","-encodedcommand","EncodedCommand")
    | project PSTime = TimeGenerated, Computer, Account;
    let RunKey = 
    SecurityEvent
    | where EventID == 4657
    | where ObjectName has @"CurrentVersion\Run"
    | project RunKeyTime = TimeGenerated, Computer, Account;
    PowerShell
    | join kind=inner RunKey on Computer, Account
    | where RunKeyTime between (PSTime .. PSTime + 10m)
    | project Computer, Account, PSTime, RunKeyTime

<img width="1920" height="1020" alt="Screenshot 2026-08-04 161802" src="https://github.com/user-attachments/assets/11a21ba0-e3df-44ee-99f5-450b223b179a" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Evaluates complex cross-event timing windows across security logs. |
| **Run Query Every** | 5 Minutes | Continuously scans for correlated execution and persistence indicators. |
| **Lookup Data From** | Last 6 Minutes | Incorporates a 1-minute overlap buffer to accommodate log ingestion latency. |
| **Severity** | High | Encoded execution paired with registry persistence is a definitive sign of malicious compromise. |
| **Status** | Enabled | Ensures the correlation rule is actively evaluating incoming telemetry. |


<img width="1920" height="1020" alt="Screenshot 2026-08-04 161825" src="https://github.com/user-attachments/assets/9362df6e-738b-4bfc-a33f-68b8c3c9f3cd" />

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |

### Why map these entities?
* **Host:** Identifies the endpoint where the encoded script ran and the registry was modified.
* **Account:** Identifies the user security context executing the attack chain.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 161811" src="https://github.com/user-attachments/assets/0373f567-e8a0-4c8b-b25f-f856da1b5202" />

---

## 🔄 Detection Workflow

    Attacker executes obfuscated/encoded PowerShell command (-enc)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Attacker writes persistence entry to Registry Run Key (Event ID 4657) within 10 minutes
                │
                ▼
    Microsoft Sentinel Scheduled Rule correlates 4688 and 4657 events
                │
                ▼
    Alert Generated combining execution and persistence phases
                │
                ▼
    Incident Created (Alert grouping disabled for immediate individual visibility)
                │
                ▼
    Automated Response Triggered (Add Triage Tag)
                │
                ▼
    SOC Analyst Assigned & Endpoint Isolation / Registry Cleanup Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Event ID **4688** logs a PowerShell process creation containing encoding flags (`-enc`, `-encodedcommand`).
* Event ID **4657** logs a modification to a Registry Run Key (`CurrentVersion\Run`) by the same account on the same computer within **10 minutes** of the PowerShell execution.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Correlating encoded execution directly with registry persistence represents a critical, high-fidelity intrusion. Disabling alert grouping ensures every unique detection triggers an immediate, standalone incident ticket for the SOC.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 162110" src="https://github.com/user-attachments/assets/646712f9-818f-43a4-8bb2-788523adbd94" />

---


## 🤖 Automated Responses
This correlation rule is linked to the following automation:
* **Add Triage Tag:** Automatically tags the incident upon creation to streamline analyst triage workflows.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 161841" src="https://github.com/user-attachments/assets/a8ce1afc-be95-4e0c-b548-afcf71b50aee" />

---

## ✅ Validation
This rule can be validated in a controlled lab environment by executing an encoded PowerShell command (e.g., base64 encoding a benign command) followed immediately by adding a test entry to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Sentinel will correlate the timestamps and generate a high-severity alert.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 161847" src="https://github.com/user-attachments/assets/378e7a4b-1b97-46a4-ba6f-1d286bfa5b38" />

---

## 🎯 Security Impact
This correlation rule helps security teams:
* Connect obfuscated execution vectors directly to persistence mechanisms.
* Cut through noise by verifying multi-stage attacker behavior.
* Rapidly isolate compromised endpoints before payloads execute on reboot.


---

⬆️ [Back to Correlation Rules](#-correlation-rules)

---

# 🔗 Correlation 3: Mimikatz → PsExec

## 🎯 Objective
This core correlation rule tracks a high-severity, multi-stage adversary campaign: credential dumping using tools like Mimikatz, followed closely by internal movement or remote execution using PsExec. It links credential access directly to lateral movement across the network.

---

## 📖 Threat Overview
Once threat actors escalate privileges, their primary objective is often harvesting plaintext credentials or hashes using tools like Mimikatz, `sekurlsa`, or `lsadump` (Event ID `4688`). Armed with these valid credentials, they frequently leverage administrative utilities like PsExec (`psexec`) to execute commands and move laterally to other systems on the network. Correlating credential dumping with remote execution catches active lateral movement in progress.

---

## 🔥 Severity
**High**


<img width="1920" height="1020" alt="Screenshot 2026-08-04 163838" src="https://github.com/user-attachments/assets/d6ab8947-112b-4e85-a16c-55d9f501bf99" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | OS Credential Dumping | T1003 |
| Execution | System Services: Service Execution | T1569.002 |


---



## 📂 Data Sources
* Windows Security Event Logs:
  * Event ID `4688` (Process Creation - monitoring for Mimikatz strings and PsExec execution)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following advanced KQL query correlates credential dumping activity with subsequent PsExec execution within a 15-minute timeframe on the same computer and account:

    let Mimikatz = 
    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any ("mimikatz","sekurlsa","lsadump")
    | project MimikatzTime = TimeGenerated, Computer, Account;
    let PsExec = 
    SecurityEvent
    | where EventID == 4688
    | where Process has "psexec"
    | project PsExecTime = TimeGenerated, Computer, Account;
    Mimikatz
    | join kind=inner PsExec on Computer, Account
    | where PsExecTime between (MimikatzTime .. MimikatzTime + 15m)
    | project Computer, Account, MimikatzTime, PsExecTime

<img width="1920" height="1020" alt="Screenshot 2026-08-04 163907" src="https://github.com/user-attachments/assets/1f8aa82b-c1db-4df6-a114-74d3843532f8" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Evaluates complex cross-event timing windows across security logs. |
| **Run Query Every** | 5 Minutes | Continuously scans for correlated credential dumping and lateral movement behavior. |
| **Lookup Data From** | Last 6 Minutes | Incorporates a 1-minute overlap buffer to accommodate log ingestion latency. |
| **Severity** | High | Credential theft paired with remote execution indicates an active, severe network breach. |
| **Status** | Enabled | Ensures the correlation rule is actively evaluating incoming telemetry. |

<img width="1920" height="1020" alt="Screenshot 2026-08-04 163930" src="https://github.com/user-attachments/assets/f56acb9f-1915-4e64-84ea-60d54eb96fc9" />

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |

### Why map these entities?
* **Host:** Identifies the endpoint where credentials were dumped and lateral movement was initiated.
* **Account:** Identifies the user security context executing the attack chain.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 163916" src="https://github.com/user-attachments/assets/fcc97168-3027-423c-a443-2ad0e1636323" />


---

## 🔄 Detection Workflow

    Attacker executes credential dumping utility (Mimikatz / sekurlsa)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Attacker launches PsExec for lateral movement within 15 minutes
                │
                ▼
    Microsoft Sentinel Scheduled Rule correlates Mimikatz and PsExec process events
                │
                ▼
    Alert Generated combining credential access and lateral movement phases
                │
                ▼
    Incident Created (Alert grouping disabled for immediate individual visibility)
                │
                ▼
    Automated Response Triggered (Add Triage Tag)
                │
                ▼
    SOC Analyst Assigned & Network Isolation / Credential Rotation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Event ID **4688** logs a process execution matching credential dumping strings (`mimikatz`, `sekurlsa`, `lsadump`).
* Event ID **4688** logs a PsExec process execution (`psexec`) by the same account on the same computer within **15 minutes** of the credential dumping event.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Correlating credential dumping directly with lateral movement tools represents a critical, high-priority intrusion. Disabling alert grouping ensures every unique detection triggers an immediate, standalone incident ticket for the SOC without merging related alerts.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 163945" src="https://github.com/user-attachments/assets/198eb5b9-1d17-49c3-9b10-ca03abb223d4" />

---

## 🤖 Automated Responses
This correlation rule is linked to the following automation:
* **Add Triage Tag:** Automatically tags the incident upon creation to streamline analyst triage workflows.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 163950" src="https://github.com/user-attachments/assets/c2345f87-ce46-48bb-819b-761f1d3640c6" />


---

## ✅ Validation
This rule can be validated in a controlled lab environment by running safe simulated checks or testing string detection for credential tools followed by administrative execution binaries. Sentinel will correlate the timestamps and generate a high-severity alert.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 164043" src="https://github.com/user-attachments/assets/ef85f600-629d-465d-9874-213ed00b945e" />

---

## 🎯 Security Impact
This correlation rule helps security teams:
* Connect credential theft vectors directly to lateral movement paths.
* Intercept attackers before they propagate across domain controllers.
* Prioritize high-fidelity triage tickets backed by multiple correlated security events.

---



⬆️ [Back to Correlation Rules](#-correlation-rules)


---

# 🔗 Correlation 4: New Service → Event Log Cleared

## 🎯 Objective
This core correlation rule tracks a malicious post-exploitation chain: the installation of a new system service for persistence, followed closely by the clearing or tampering of event logs (Event ID 1102) to wipe forensic evidence. It connects system compromise directly with defense evasion.

---

## 📖 Threat Overview
When adversaries successfully install a new Windows service (Event IDs `4697` or `7045`) to maintain persistent backdoors, they immediately seek to cover their tracks. By clearing the audit logs (such as Event ID `1102` - The audit log was cleared), they attempt to blind security teams and hide the service installation artifacts. Correlating service installation with subsequent log clearing highlights active cover-up behavior.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164349" src="https://github.com/user-attachments/assets/0eb48829-9291-458f-a71c-d77f6b06b424" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Persistence, Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 |
| Defense Evasion | Indicator Removal on Host: Clear Windows Event Logs | T1070.001 |



---

## 📂 Data Sources
* Windows Security Event Logs:
  * Event ID `4697` / `7045` (A new service was installed)
  * Event ID `1102` (The audit log was cleared)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following advanced KQL query correlates new service installations with subsequent event log clearing within a 30-minute timeframe on the same computer:

    let ServiceInstall = 
    SecurityEvent
    | where EventID in (4697,7045)
    | project ServiceTime = TimeGenerated, Computer, Account;
    let LogCleared = 
    SecurityEvent
    | where EventID == 1102
    | project ClearTime = TimeGenerated, Computer, Account;
    ServiceInstall
    | join kind=inner LogCleared on Computer
    | where ClearTime between (ServiceTime .. ServiceTime + 30m)
    | project Computer, Account, ServiceTime, ClearTime

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164419" src="https://github.com/user-attachments/assets/4d1c6ca9-b26a-41bc-a3e5-d7f71aae27ad" />



---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Evaluates incoming telemetry streams instantly to catch persistence and log clearing concurrently. |
| **Severity** | High | Service installation paired with clearing event logs represents a severe indicator of an active attack. |
| **Status** | Enabled | Ensures the correlation rule is actively running. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |

### Why map these entities?
* **Account:** Identifies the user account responsible for installing the service and clearing logs.
* **Host:** Highlights the endpoint where the service persistence and log deletion occurred.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164428" src="https://github.com/user-attachments/assets/9f3328fd-97c2-42f6-9318-a3367ad21945" />

---

## 🔄 Detection Workflow

    Attacker installs a new Windows service for persistence
                │
                ▼
    Target Host logs Event ID 4697 or 7045
                │
                ▼
    Attacker clears audit logs (Event ID 1102) within 30 minutes to cover tracks
                │
                ▼
    Microsoft Sentinel NRT Rule correlates service installation and log clearing events
                │
                ▼
    Alert Generated combining persistence and defense evasion phases
                │
                ▼
    Incident Created (Alert grouping disabled)
                │
                ▼
    Automated Response Triggered (Add Triage Tag)
                │
                ▼
    SOC Analyst Assigned & Forensic Investigation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Event ID **4697** or **7045** logs a new service installation.
* Event ID **1102** logs that the audit log was cleared on the same computer within **30 minutes** of the service installation.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Correlating persistence mechanisms directly with log clearing is a critical indicator of compromise. Disabling alert grouping ensures every unique detection triggers an immediate, standalone incident ticket for the SOC.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164443" src="https://github.com/user-attachments/assets/d609a9de-166a-4b72-8c13-d0bf03455d61" />


---

## 🤖 Automated Responses
This correlation rule is linked to the following automation:
* **Add Triage Tag:** Automatically tags the incident upon creation to streamline analyst triage workflows.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164449" src="https://github.com/user-attachments/assets/2a8b10dc-7f4f-4a2c-954d-d5aee2ff4bae" />


---

## ✅ Validation
This rule can be validated in a controlled lab environment by installing a test service and subsequently clearing the security event log using administrative tools. Sentinel will correlate the sequence and generate a high-severity alert.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 164531" src="https://github.com/user-attachments/assets/58dc2845-4eb8-4403-a922-cc6ad75349b8" />


---

## 🎯 Security Impact
This correlation rule helps security teams:
* Uncover hidden persistence methods even when attackers attempt to wipe logs.
* Detect deliberate defense evasion tactics following system modifications.
* Ensure immediate visibility into post-compromise cleanup activities.

---


⬆️ [Back to Correlation Rules](#-correlation-rules)

---
# 🔗 Correlation 5: Certutil Download → Mshta Execution

## 🎯 Objective
This core correlation rule tracks a multi-stage adversary execution chain: using `certutil.exe` to download a remote payload (Ingress Tool Transfer / Command and Control), followed closely by executing that payload using `mshta.exe`. It connects file staging directly with living-off-the-land execution.

---

## 📖 Threat Overview
Attackers frequently abuse native Windows binaries (LOLBins) to bypass security controls. A common stealthy technique involves using `certutil.exe` with flags like `-urlcache` or `http://` URLs to download external payloads to the target machine. Once downloaded, they execute the payload using `mshta.exe` to run malicious HTML applications or script code. Correlating these two sequential events provides high-fidelity detection for staged payload delivery and execution.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164623" src="https://github.com/user-attachments/assets/d662a1c9-99ba-43af-b07f-e6060506abb0" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Command and Control | Ingress Tool Transfer | T1105 |
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 |

---

## 📂 Data Sources
* Windows Security Event Logs:
  * Event ID `4688` (Process Creation - monitoring `certutil.exe` download parameters and `mshta.exe` execution)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following advanced KQL query correlates `certutil` download activity with subsequent `mshta` process execution within a 10-minute window on the same host and account:

    let Certutil = 
    SecurityEvent
    | where EventID == 4688
    | where Process has "certutil.exe"
    | where CommandLine has_any ("http://","https://","-urlcache")
    | project CertutilTime = TimeGenerated, Computer, Account;
    let Mshta = 
    SecurityEvent
    | where EventID == 4688
    | where Process has "mshta.exe"
    | project MshtaTime = TimeGenerated, Computer, Account;
    Certutil
    | join kind=inner Mshta on Computer, Account
    | where MshtaTime between (CertutilTime .. CertutilTime + 10m)
    | project Computer, Account, CertutilTime, MshtaTime

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164642" src="https://github.com/user-attachments/assets/4c3b5933-2e18-4dd1-ad91-1a4f609c7964" />


---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Evaluates complex cross-event timing windows across security logs. |
| **Run Query Every** | 5 Minutes | Continuously scans for correlated payload staging and execution behavior. |
| **Lookup Data From** | Last 6 Minutes | Incorporates a 1-minute overlap buffer to accommodate log ingestion latency. |
| **Severity** | High | Using native tools for download and execution represents an active, high-risk intrusion attempt. |
| **Status** | Enabled | Ensures the correlation rule is actively evaluating incoming telemetry. |

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164728" src="https://github.com/user-attachments/assets/ee081c7b-0ff6-443a-ae6d-a0fc246d7d9c" />


---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |

### Why map these entities?
* **Host:** Identifies the endpoint where the file was downloaded via certutil and executed via mshta.
* **Account:** Identifies the user security context executing the attack chain.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164652" src="https://github.com/user-attachments/assets/ead89bf8-eba1-4eaa-8050-3edd7513c5a9" />


---

## 🔄 Detection Workflow

    Attacker uses certutil.exe to download a remote payload (-urlcache / http)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Attacker executes the payload using mshta.exe within 10 minutes
                │
                ▼
    Microsoft Sentinel Scheduled Rule correlates certutil and mshta process events
                │
                ▼
    Alert Generated combining staging and execution phases
                │
                ▼
    Incident Created (Alert grouping disabled for immediate individual visibility)
                │
                ▼
    Automated Response Triggered (Add Triage Tag)
                │
                ▼
    SOC Analyst Assigned

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Event ID **4688** logs `certutil.exe` execution with download flags (`http://`, `https://`, `-urlcache`).
* Event ID **4688** logs `mshta.exe` process execution by the same account on the same computer within **10 minutes** of the certutil download.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Correlating native tool downloads directly with script execution engines represents a critical, high-priority indicator of compromise. Disabling alert grouping ensures every unique detection triggers an immediate, standalone incident ticket for the SOC.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164737" src="https://github.com/user-attachments/assets/0e78a614-b1a2-4cf6-ba7e-5f13720e9628" />


---

## 🤖 Automated Responses
This correlation rule is linked to the following automation:
* **Add Triage Tag:** Automatically tags the incident upon creation to streamline analyst triage workflows.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164742" src="https://github.com/user-attachments/assets/646af3ca-a1f8-4b98-932d-2f394cb830bc" />


---

## ✅ Validation
This rule can be validated in a controlled lab environment by executing a benign certutil download command followed immediately by launching mshta. Sentinel will correlate the timestamps and generate a high-severity alert.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164747" src="https://github.com/user-attachments/assets/f3001e52-2e05-4936-9c59-3828683f4703" />


---

## 🎯 Security Impact
This correlation rule helps security teams:
* Detect abuse of Living-off-the-Land Binaries (LOLBins) for payload delivery.
* Catch multi-stage execution chains before malicious scripts execute.
* Prioritize high-fidelity triage tickets backed by multiple correlated security events.

---



⬆️ [Back to Correlation Rules](#-correlation-rules)

---
# 🔗 Correlation 6: Defender Disabled → Firewall Disabled → Mimikatz

## 🎯 Objective
This core correlation rule tracks a complex, multi-phase attack chain combining defense evasion and credential access: disabling Microsoft Defender protections, disabling the Windows Firewall, and subsequently executing credential dumping tools like Mimikatz. It flags an attacker systematically stripping endpoint defenses before harvesting credentials.

---

## 📖 Threat Overview
Before executing noisy or high-privilege activities such as credential harvesting, advanced threat actors actively attempt to disable security controls to avoid detection. This campaign involves turning off real-time antivirus protection via PowerShell (`Set-MpPreference`), disabling firewall profiles via `netsh`, and then executing credential dumping utilities (`mimikatz`, `sekurlsa`, `lsadump`). Correlating these steps highlights a coordinated, premeditated intrusion.

---

## 🔥 Severity
**High**


<img width="1920" height="1020" alt="Screenshot 2026-08-04 164837" src="https://github.com/user-attachments/assets/bfecf593-fb22-4e82-9345-2d208ecd5321" />


---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defense Evasion | Impair Defenses: Disable or Modify System Firewall | T1562.004 |
| Credential Access | OS Credential Dumping | T1003 |

---

## 📂 Data Sources
* Windows Security Event Logs:
  * Event ID `4688` (Process Creation - monitoring Defender settings modification, firewall toggles, and credential dumping commands)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following advanced KQL query uses multiple `let` statements and inner joins to sequentially correlate Defender tampering, firewall disabling, and credential dumping within tight time windows:

    let DefenderDisabled = 
    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any ("Set-MpPreference","DisableRealtimeMonitoring","WinDefend")
    | project DefenderTime = TimeGenerated, Computer, Account;
    let FirewallDisabled = 
    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any (
        "netsh advfirewall set allprofiles state off",
        "Set-NetFirewallProfile"
    )
    | project FirewallTime = TimeGenerated, Computer, Account;
    let Mimikatz = 
    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any ("mimikatz","sekurlsa","lsadump")
    | project MimikatzTime = TimeGenerated, Computer, Account;
    DefenderDisabled
    | join kind=inner FirewallDisabled on Computer, Account
    | where FirewallTime between (DefenderTime .. DefenderTime + 10m)
    | join kind=inner Mimikatz on Computer, Account
    | where MimikatzTime between (FirewallTime .. FirewallTime + 15m)
    | project Computer, Account, DefenderTime, FirewallTime, MimikatzTime

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164858" src="https://github.com/user-attachments/assets/5ddb0ff0-1b11-4839-a372-5101f7c3343b" />

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164906" src="https://github.com/user-attachments/assets/907a7d5c-0a84-41ac-add2-e4457b8cc1c2" />



---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Evaluates continuous incoming telemetry streams instantly for multi-stage threat detection. |
| **Severity** | High | Tampering with core security defenses combined with credential theft represents an immediate, critical threat. |
| **Status** | Enabled | Ensures the correlation rule is actively running. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |

### Why map these entities?
* **Host:** Identifies the target endpoint where defenses were stripped and credentials were targeted.
* **Account:** Identifies the user security context executing the tampering and dumping sequence.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164915" src="https://github.com/user-attachments/assets/4e59c277-3f29-4b57-8b77-6a73f5bc7db2" />



---

## 🔄 Detection Workflow

    Attacker disables Microsoft Defender protections via command line
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Attacker disables Windows Firewall within 10 minutes
                │
                ▼
    Attacker executes Mimikatz for credential dumping within 15 minutes
                │
                ▼
    Microsoft Sentinel NRT Rule correlates across all three event stages
                │
                ▼
    Alert Generated combining defense evasion and credential access phases
                │
                ▼
    Incident Created (Alert grouping disabled for immediate individual visibility)
                │
                ▼
    Automated Response Triggered (Add Triage Tag)
                │
                ▼
    SOC Analyst Assigned 

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Event ID **4688** logs a command disabling Defender protections (`Set-MpPreference`, etc.).
* Event ID **4688** logs a firewall deactivation command within **10 minutes** on the same computer and account.
* Event ID **4688** logs a credential dumping execution (`mimikatz`, etc.) within **15 minutes** of the firewall modification.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Stripping multiple security controls before dumping credentials is a definitive high-priority indicator of compromise. Disabling alert grouping ensures every unique detection triggers an immediate, standalone incident ticket for the SOC.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164937" src="https://github.com/user-attachments/assets/94a1e140-9d3b-4033-b311-19f8e9c83580" />


---

## 🤖 Automated Responses
This correlation rule is linked to the following automation:
* **Add Triage Tag:** Automatically tags the incident upon creation to streamline analyst triage workflows.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 164942" src="https://github.com/user-attachments/assets/b2da55bf-30d4-4fc2-b4bb-323652473db2" />

---

## ✅ Validation
This rule can be validated in a secure test environment by executing safe verification steps matching the process command lines. Sentinel will successfully correlate the multi-stage sequence across the time windows and generate a high-severity alert.


<img width="1920" height="1020" alt="Screenshot 2026-08-04 164948" src="https://github.com/user-attachments/assets/a5b8d1db-d411-4667-98dc-94dafc180fd1" />

---

## 🎯 Security Impact
This correlation rule helps security teams:
* Detect premeditated defense tampering before severe credential theft occurs.
* Catch complex multi-phase kill chains instantly via NRT evaluation.
* Ensure immediate, unbundled incident generation for critical adversary campaigns.

---

⬆️ [Back to Correlation Rules](#-correlation-rules)

