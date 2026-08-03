
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
| **[User Added to Domain Admins](#user-added-to-domain-admins)** | High | T1098 | Detects unauthorized account additions to the highly privileged Domain Admins group. |
| **[PowerShell Download](#powershell-download)** | High | T1105 | Detects PowerShell execution used specifically to download files from remote locations. |
| **[Suspicious Command Shell](#suspicious-command-shell)** | Medium | T1059.003 | Detects anomalous or obfuscated usage of the native Windows command shell (cmd.exe). |
| **[Password Spray Detection](#password-spray-detection)** | High | T1110.003 | Detects authentication attempts against multiple unique users utilizing a single password. |
| **[Defender Disabled](#defender-disabled)** | High | T1562.001 | Detects modifications in the registry or via command line to disable Microsoft Defender. |
| **[Mshta Execution](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Analytics-Rules/README.md#-mshta-execution)** | High | T1218.005 | Detects execution of mshta.exe to run malicious scripts, bypassing application control mechanisms. |
| **[Impossible Travel](#impossible-travel)** | High | T1078.004 | Detects user logins from geographically distant locations in an impossibly short timeframe. |
| **[Firewall Disabled](#firewall-disabled)** | Medium | T1562.004 | Detects system modifications that turn off or impair the Windows Defender Firewall. |
| **[Certutil Download](#certutil-download)** | High | T1105 | Detects the abuse of the certutil.exe administrative tool to download malicious external files. |
| **[Network Discovery](#network-discovery)** | Medium | T1082 | Detects execution of commands aimed at mapping internal network topologies and connections. |
| **[Suspicious Outbound Connection](#suspicious-outbound-connection)** | Medium | T1071 | Detects unusual outbound network connections potentially indicating Command and Control (C2) traffic. |
| **[Create or Modify System Process](#create-or-modify-system-process)** | Medium | T1543 | Detects the creation or modification of system-level processes to establish persistence. |
| **[Event Logging Service Shut Down](#event-logging-service-shut-down)** | Medium | T1562.001 | Detects the manual termination of the Windows Event logging service to hide malicious activity. |
| **[User Added to Local Administrators](#user-added-to-local-administrators)** | High | T1098 | Detects unauthorized additions of user accounts to the local Administrators group on an endpoint. |

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

---

## 🤖 Automated Response

When an incident is created:

- The configured **Automation Rule** is executed.
- Incident ownership is automatically assigned.
- Additional playbooks, such as email notifications, can be triggered to notify SOC analysts.

---

## ✅ Validation

The detection was validated by intentionally performing multiple failed Windows logon attempts against the monitored endpoint. Microsoft Sentinel successfully generated an alert, created an incident, and executed the configured automation rule after the detection threshold was reached.

---

## 🎯 Security Impact

This detection helps security teams:

- Detect brute-force and password guessing attacks.
- Identify targeted user accounts.
- Track malicious source IP addresses.
- Reduce the likelihood of unauthorized access.
- Improve incident response through automated alerting and investigation.

---

## 📸 Screenshots

### Rule Overview

> *(Insert Screenshot)*

### MITRE ATT&CK Mapping

> *(Insert Screenshot)*

### KQL Query

> *(Insert Screenshot)*

### Entity Mapping

> *(Insert Screenshot)*

### Query Scheduling

> *(Insert Screenshot)*

### Incident Settings

> *(Insert Screenshot)*

### Automation Rule

> *(Insert Screenshot)*

### Review & Create

> *(Insert Screenshot)*

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

---

## 🤖 Automated Response

When an incident is created:

- The configured Automation Rule (**Account Compromise Suspected**) is executed.
- Incident tags are automatically appended for easier SOC filtering and triage.
- Playbooks can subsequently trigger logic to block the malicious IP or force a credential reset in Entra ID.

---

## ✅ Validation

The detection was validated by intentionally performing multiple failed RDP logon attempts against a monitored endpoint using an incorrect password, immediately followed by logging in successfully with the correct password. Microsoft Sentinel successfully correlated the events, generated an alert, created an incident, and executed the automation tagging rule.

---

## 🎯 Security Impact

This detection is critical for security operations as it helps teams:
- Confirm that a perimeter defense or authentication barrier has been successfully breached.
- Immediately identify and isolate the specific compromised user account before the attacker can escalate privileges or move laterally.
- Provide concrete evidence of the exact time of compromise and the adversary's source IP address for further threat hunting and blocklisting.

 ---
 
## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot)*

### KQL Query
> *(Insert Screenshot)*

### Entity Mapping
> *(Insert Screenshot)*

### Incident Settings
> *(Insert Screenshot)*

### Automation Rule
> *(Insert Screenshot)*

### Review & Create
> *(Insert Screenshot)*

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

---

## ✅ Validation

This detection can be validated by opening an administrative Command Prompt or PowerShell session on a monitored endpoint and executing the command: `net user /add TestUser Password123!`. Within 5 minutes, Microsoft Sentinel should successfully ingest Event ID 4720 and generate the corresponding incident.

---

## 🎯 Security Impact

This detection helps security teams:
- Identify unauthorized backdoors established by threat actors.
- Detect privilege escalation attempts or rogue administrative activity.
- Quickly isolate affected hosts before an attacker can utilize the new account for lateral movement.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-02 125146.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-02 125201.png)*

### KQL Query
> *(Insert Screenshot 2026-08-02 125211.png)*

### Entity Mapping
> *(Insert Screenshot 2026-08-02 125218.png)*

### Query Scheduling
> *(Insert Screenshot 2026-08-02 125228.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-02 125251.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-02 125258.png)*

### Review & Create
> *(Insert Screenshot 2026-08-02 125306.png)*

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

---

## ✅ Validation

This detection can be validated by opening a Command Prompt on a monitored endpoint and executing a benign Base64 encoded PowerShell command, such as:
`powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA` (which decodes to `Write-Host "Hello World"`).
Within 5 minutes, Microsoft Sentinel should detect the 4688 event and generate the corresponding incident.

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

---

## ✅ Validation
This detection can be validated by identifying an account with "Do not require Kerberos preauthentication" checked in Active Directory (e.g., `sqlsvc`), and running a tool like Impacket's `GetNPUsers.py` or Rubeus (`Rubeus.exe asreproast /user:sqlsvc`) from an attacking machine. Sentinel will capture the 4768 event and generate the incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify adversaries attempting to extract encrypted password hashes from the network.
* Highlight misconfigured or highly vulnerable service accounts that require remediation (enabling Kerberos preauthentication).
* Detect the reconnaissance and initial credential access phase of an attack sequence before lateral movement occurs.

---

## 📸 Screenshots

### Entity Mapping (Updated)
> *(Insert Screenshot 2026-08-03 181157.png)*

### Incident Settings (Updated)
> *(Insert Screenshot 2026-08-03 181216.png)*

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

---

## ✅ Validation
This detection can be validated by running an SPN extraction and TGS request tool like Rubeus (`Rubeus.exe kerberoast /user:sqlsvc`) or Impacket (`GetUserSPNs.py`) from an attacking machine within the lab environment against the `sqlsvc` account. Microsoft Sentinel will capture the 4769 event and generate the incident.

---

## 🎯 Security Impact
This detection helps security teams:
* Identify internal reconnaissance and credential harvesting against service accounts.
* Track the exact source IP address of the compromised machine performing the attack.
* Highlight weak points in the domain's service account structure (e.g., service accounts with weak passwords that are vulnerable to offline cracking).

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 181932.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 181943.png)*

### KQL Query & Entity Mapping
> *(Insert Screenshot 2026-08-03 182004.png)*
> *(Insert Screenshot 2026-08-03 182020.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 182037.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 182047.png)*

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

---

## ✅ Validation
This detection can be validated by logging into a Domain Controller with administrative privileges, opening Active Directory Users and Computers (ADUC) or an elevated PowerShell prompt, and temporarily adding a test user account to the Domain Admins group. Microsoft Sentinel will capture the 4728 event and immediately generate an incident. *(Ensure the test user is removed immediately after validation).*

---

## 🎯 Security Impact
This detection helps security teams:
* Identify the final stages of privilege escalation attack chains.
* Detect rogue administrators or insider threats granting unauthorized access.
* Maintain strict auditing and compliance over the domain's most privileged security group.

---

## 📸 Screenshots

### Rule Overview
> *(Insert Screenshot 2026-08-03 183346.png)*

### MITRE ATT&CK Mapping
> *(Insert Screenshot 2026-08-03 183400.png)*

### KQL Query
> *(Insert Screenshot 2026-08-03 183426.png)*

### Entity Mapping
> *(Insert image_6666f7.png)*

### Incident Settings
> *(Insert Screenshot 2026-08-03 183455.png)*

### Automation Rule
> *(Insert Screenshot 2026-08-03 183502.png)*

### Review & Create
> *(Insert Screenshot 2026-08-03 183512.png)*

---

⬆️ **[Back to Analytics Rule Summary](#-analytics-rule-summary)**

---
