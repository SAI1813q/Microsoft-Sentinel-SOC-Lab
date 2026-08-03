
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
---
