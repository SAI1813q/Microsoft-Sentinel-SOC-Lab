# #🚨 Detection Validation & Investigation

This section demonstrates the successful validation of each Microsoft Sentinel analytics rule. After executing attack simulations within the lab environment, Microsoft Sentinel generated alerts and automatically created incidents based on the configured incident creation settings.

Each alert includes enriched entities, related events, and investigation context, confirming that the corresponding detection logic functioned as expected.

---

# 📋 Detection Validation Summary

| Alert | Severity | Incident Created | Validation Status | Description |
|-------|----------|------------------|-------------------|-------------|
| **[Brute Force Login Detection](#-brute-force-login-detection)** | High | ✅ Yes | ✅ Validated | Generated after multiple failed Windows logon attempts exceeded the configured threshold. |
| **[Successful Login After Brute Force](#-successful-login-after-brute-force)** | High | ✅ Yes | ✅ Validated | Generated when a successful authentication followed repeated failed logon attempts. |
| **[New Local User Creation](#-new-local-user-creation)** | Medium | ✅ Yes | ✅ Validated | Generated when a new local user account was created on a monitored endpoint. |
| **[Encoded PowerShell Detection](#-encoded-powershell-detection)** | High | ✅ Yes | ✅ Validated | Generated after execution of a Base64-encoded PowerShell command. |
| **[Download Cradle Detection](#-download-cradle-detection)** | High | ✅ Yes | ✅ Validated | Generated when PowerShell attempted to download remote content from an external source. |
| **[Mimikatz Detection](#-mimikatz-detection)** | High | ✅ Yes | ✅ Validated | Generated after execution of the Mimikatz credential dumping tool. |
| **[PsExec Detection](#-psexec-detection)** | High | ✅ Yes | ✅ Validated | Generated when PsExec was used to execute commands remotely. |
| **[Registry Run Key Persistence](#-registry-run-key-persistence)** | High | ✅ Yes | ✅ Validated | Generated after persistence was established using Windows Run Registry Keys. |
| **[Event Log Cleared Detection](#-event-log-cleared-detection)** | High | ✅ Yes | ✅ Validated | Generated when Windows Event Logs were cleared to remove forensic evidence. |
| **[New Windows Service Installed](#-new-windows-service-installed)** | High | ✅ Yes | ✅ Validated | Generated after installation of a new Windows service. |
| **[Scheduled Task Creation](#-scheduled-task-creation)** | Medium | ✅ Yes | ✅ Validated | Generated when a new scheduled task was created on the monitored endpoint. |
| **[Suspicious Discovery Commands](#-suspicious-discovery-commands)** | Medium | ✅ Yes | ✅ Validated | Generated after execution of common Windows reconnaissance commands. |
| **[Domain Admin Group Modification](#-domain-admin-group-modification)** | Critical | ✅ Yes | ✅ Validated | Generated when a privileged Active Directory group membership was modified. |
| **[AS-REP Roasting Detection](#-as-rep-roasting-detection)** | High | ✅ Yes | ✅ Validated | Generated when an AS-REQ without Kerberos pre-authentication was detected, indicating a potential AS-REP Roasting attack targeting accounts with pre-authentication disabled. |

---

# 🚨 Suspicious Discovery Commands

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying suspicious system discovery commands executed on a monitored Windows endpoint. The analytics rule detected the execution of native Windows reconnaissance utilities, automatically generated an alert, and correlated it into a Microsoft Defender incident for investigation.

---

## 📖 Attack Scenario

After gaining access to a system, attackers typically perform reconnaissance to understand the environment before moving laterally or escalating privileges. Common Windows utilities such as `hostname.exe`, `systeminfo.exe`, `wmic.exe`, and `ver.exe` are frequently abused because they are legitimate operating system binaries.

Microsoft Sentinel detected this activity through a Near Real-Time analytics rule and automatically created an investigation incident.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Suspicious Discovery Commands |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Not Set |
| **Assigned To** | Unassigned |
| **Detection Source** | Microsoft Sentinel |
| **Analytics Rule** | Suspicious Discovery Commands |
| **MITRE ATT&CK** | T1016, T1033, T1082, T1087 |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected the execution of one or more Windows discovery commands matching the analytics rule.

These commands are commonly executed during the reconnaissance phase of an attack to collect information about the operating system, host configuration, users, and network environment.

---

## Alert Workflow

```text
Attacker executes discovery command
            │
            ▼
Windows Security Event (4688)
            │
            ▼
Azure Monitor Agent
            │
            ▼
Log Analytics Workspace
            │
            ▼
Microsoft Sentinel Analytics Rule
            │
            ▼
Alert Generated
            │
            ▼
Incident Automatically Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 3 |
| **Incident Name** | Suspicious Discovery Commands |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Sentinel automatically correlated the generated alert into a single incident.

This provides analysts with one investigation workspace containing:

- Alert information
- Attack story
- Investigation graph
- Impacted assets
- Evidence
- Activities

instead of requiring multiple independent investigations.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The attack story provides a visual relationship between the detected entities involved in the alert.

For this detection Microsoft Defender automatically associated:

- Device
- User Account
- Suspicious Process

allowing analysts to quickly understand how the entities are connected.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The investigation graph automatically maps the entities involved in the incident.

Observed entities include:

- Device (Vm1)
- User (Vm1\Sia123)
- Suspicious Process (HOSTNAME.EXE)

This visualization helps analysts pivot between related entities during an investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| Device | Vm1 |
| Risk Level | None |

---

## User

| Property | Value |
|----------|-------|
| User | Vm1\Sia123 |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender collected evidence associated with the detection.

| Property | Value |
|----------|-------|
| Entity Type | Process |
| Verdict | Suspicious |
| Impacted Asset | Vm1 |

The suspicious process was linked to the alert, providing investigators with additional context during analysis.

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the investigation.

For this incident:

- Alert automatically correlated into Incident 3
- Trigger performed by Microsoft Defender XDR
- Activity Status: Completed

This provides an audit trail showing how the incident was created.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- Verify whether the commands were executed by an administrator or a standard user.
- Review the process command line.
- Identify any subsequent lateral movement or credential access activity.
- Examine neighboring alerts within the same timeline.
- Determine whether the reconnaissance activity is authorized or malicious.

---

# 🎯 Security Impact

This detection provides early visibility into post-compromise reconnaissance activity.

Early detection allows defenders to investigate the attacker before they progress to:

- Credential Dumping
- Privilege Escalation
- Lateral Movement
- Persistence
- Data Exfiltration

Detecting discovery activity at this stage significantly improves the chances of containing an intrusion before major damage occurs.

---

⬆️ **[Back to Detection Validation Summary](#-detection-validation-summary)**

---

# 🚨 AS-REP Roasting Detection

---

## 📖 Detection Overview

**AS-REP Roasting** is a Kerberos-based credential access attack that targets Active Directory user accounts configured with the **"Do not require Kerberos preauthentication"** option. Unlike standard Kerberos authentication, these accounts allow attackers to request an Authentication Service Response (AS-REP) from the Domain Controller without first proving knowledge of the account's password.

The returned AS-REP contains encrypted authentication data that can be extracted and subjected to offline password-cracking attacks using tools such as **Hashcat** or **John the Ripper**. If the password is successfully cracked, the attacker may gain unauthorized access to the compromised account, potentially leading to privilege escalation, lateral movement, and further compromise of the Active Directory environment.

This Microsoft Sentinel analytics rule detects **Kerberos Authentication Service Requests (Event ID 4768)** where **PreAuthType = 0**, indicating that Kerberos pre-authentication was not required and a potentially vulnerable account was targeted.

---

## 🎯 Attack Scenario

An attacker first identifies Active Directory accounts that have **Kerberos pre-authentication disabled**. This reconnaissance can be performed using offensive tools such as **Rubeus**, **PowerView**, or **Impacket GetNPUsers**.

Once a vulnerable account is identified, the attacker sends an Authentication Service Request (AS-REQ) to the Domain Controller. Because the account does not require Kerberos pre-authentication, the Domain Controller immediately returns an **Authentication Service Response (AS-REP)** containing encrypted credential material.

The attacker then extracts the Kerberos hash from the AS-REP response and performs offline password cracking. If the password is recovered, the compromised account can be used for authentication, privilege escalation, persistence, or lateral movement throughout the Active Directory environment.

Microsoft Sentinel continuously monitors Kerberos authentication events and generates a high-severity alert whenever an AS-REQ request is observed without Kerberos pre-authentication, enabling security analysts to detect AS-REP Roasting attempts before credentials are compromised.

### 🎯 MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---------|-----------|----|
| Credential Access | Steal or Forge Kerberos Tickets | T1558 |
| Credential Access | AS-REP Roasting | T1558.004 |

---

## 🚨 Alert Generated

### 📋 Alert Summary

| Property | Value |
|----------|-------|
| Alert Name | AS-REP Roasting Detection |
| Severity | High |
| Status | New |
| Category | Credential Access |
| Detection Source | NRT Rules |
| Service Source | Microsoft Sentinel |
| Workspace | LAW-Project1 |
| Generated On | Jul 30, 2026 6:31:13 PM |
| First Activity | Jul 30, 2026 6:28:17 PM |
| Last Activity | Jul 30, 2026 6:28:17 PM |

### 📝 Alert Description

Microsoft Sentinel generated a **High Severity** alert after detecting a Kerberos Authentication Service Request (AS-REQ) where **Kerberos pre-authentication was disabled**. This behavior is a well-known indicator of an **AS-REP Roasting** attack, in which attackers attempt to obtain Kerberos authentication material for offline password cracking.

### 🔄 Alert Workflow

```text
Attacker
      │
      ▼
AS-REQ without Pre-Authentication
      │
      ▼
Windows Security Event ID 4768
      │
      ▼
Azure Monitor Agent (AMA)
      │
      ▼
Log Analytics Workspace
      │
      ▼
Microsoft Sentinel Analytics Rule
      │
      ▼
Alert Generated
      │
      ▼
Incident Created
```

> 📸 **Screenshot:** Alert Overview

---

## 📋 Incident Created

### 📊 Incident Summary

| Property | Value |
|----------|-------|
| Incident ID | 89 |
| Incident Name | AS-REP Roasting Detection |
| Severity | High |
| Status | Active |
| Classification | Unclassified |
| Assigned To | Unassigned |
| Alerts | 1 |
| Assets | 1 |

### 🔍 Incident Correlation

Microsoft Defender XDR automatically correlated the generated alert into **Incident ID 89**, consolidating the related security event into a single incident for investigation. This correlation provides analysts with centralized visibility into the alert, associated entities, and supporting telemetry.

> 📸 **Screenshot:** Incident Overview

---

## 🕵️ Attack Story

The **Attack Story** provides a visual representation of the incident by mapping the relationships between the generated alert and the impacted asset. It enables analysts to quickly understand how the suspicious Kerberos authentication activity relates to the affected device.

### 👀 Observed Entity

| Entity Type | Value |
|-------------|-------|
| Device | DC.root.project |

> 📸 **Screenshot:** Attack Story

---

## 🕸️ Investigation Graph

The **Investigation Graph** visually connects the alert with associated entities, allowing analysts to pivot between the affected device and related security events. This graphical representation accelerates incident triage and helps identify additional indicators of compromise.

### 🔗 Associated Entity

| Entity | Value |
|--------|-------|
| Device | DC.root.project |

> 📸 **Screenshot:** Investigation Graph

---

## 💻 Impacted Assets

### 🖥️ Device Information

| Property | Value |
|----------|-------|
| Device Name | DC.root.project |
| Domain | root.project |
| Risk Level | None |

### 👤 User Information

No user entities were automatically associated with this incident.

> 📸 **Screenshot:** Assets

---

## 🧾 Evidence & Response

No automated evidence collection or response actions were associated with this incident. However, the captured Kerberos authentication event provides valuable forensic information regarding the attempted AS-REP Roasting activity.

### 📑 Event Details

| Field | Value |
|-------|-------|
| Target User | sqlsvc |
| Domain | root.project |
| Service | krbtgt |
| PreAuthType | 0 |
| Ticket Encryption Type | AES256 (0x12) |
| Source IP Address | ::ffff:10.0.0.4 |

The **PreAuthType = 0** value confirms that Kerberos pre-authentication was disabled for the target account, making it susceptible to AS-REP Roasting attacks.

> 📸 **Screenshot:** Event XML

---

## 📅 Activities

The **Activities** tab records actions automatically performed during incident creation and alert correlation.

| Time | Activity | Performed By | Status |
|------|----------|--------------|--------|
| Jul 30, 2026 6:31 PM | Alert automatically correlated to Incident 89 | Microsoft Defender XDR | Completed |

The activity timeline confirms that Microsoft Defender XDR successfully correlated the alert into a single incident without requiring manual analyst intervention.

> 📸 **Screenshot:** Activities

---

## 🔎 SOC Analyst Investigation

Following validation of the alert, the SOC analyst should perform the following investigative actions:

- Verify whether the **sqlsvc** account legitimately has Kerberos pre-authentication disabled.
- Review the account configuration within Active Directory Users and Computers.
- Investigate the originating source IP address (**10.0.0.4**).
- Search for additional Event ID **4768** authentication requests involving the same account.
- Determine whether multiple AS-REQ requests originated from the same host.
- Review authentication logs for evidence of successful logon attempts after the AS-REP request.
- Investigate potential lateral movement or privilege escalation activities.
- Enable Kerberos pre-authentication for the affected account unless a documented business requirement exists.

---

## 🛡️ Security Impact

AS-REP Roasting is a highly effective **Credential Access** technique because it enables attackers to obtain Kerberos authentication material without possessing valid credentials. Since password cracking occurs offline, organizations may remain unaware of the attack unless Kerberos authentication events are actively monitored.

By detecting Authentication Service Requests where **PreAuthType = 0**, Microsoft Sentinel enables defenders to identify vulnerable accounts, reduce credential exposure, and mitigate the risk of unauthorized access before attackers successfully recover account passwords.

---

⬆️ **[Back to Detection Validation Summary](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)**

---

# 🚨 Brute Force Login Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying repeated failed Windows authentication attempts against a privileged user account. The analytics rule monitors failed logon events and generates an alert when the number of failed authentication attempts from a single source exceeds the configured threshold, indicating a potential brute force attack.

Microsoft Sentinel automatically correlates the alert into a Microsoft Defender XDR incident, enabling security analysts to investigate the attack using enriched telemetry, affected assets, evidence, and incident timelines.

---

## 📖 Attack Scenario

Brute force attacks are one of the most common techniques used by attackers to gain unauthorized access to user accounts. During this attack, the adversary repeatedly attempts to authenticate using different passwords until the correct credentials are discovered.

In this lab, multiple failed Windows logon attempts targeted the **Administrator** account from a single external IP address. Microsoft Sentinel detected the abnormal authentication pattern using a scheduled analytics rule and automatically generated a security incident for investigation.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | brute force |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Not Set |
| **Assigned To** | Unassigned |
| **Detection Source** | Microsoft Sentinel |
| **Analytics Rule** | Brute Force Login Detection |
| **MITRE ATT&CK** | T1110 |

---

## Alert Description

The alert was generated after Microsoft Sentinel detected multiple failed Windows logon attempts against the **Administrator** account originating from the same external IP address.

Repeated authentication failures are commonly associated with password guessing and brute force attacks, where attackers attempt to compromise valid user credentials by repeatedly submitting different passwords.

---

## Alert Workflow

```text
Attacker performs repeated login attempts
                │
                ▼
Windows Security Event (4625)
                │
                ▼
Azure Monitor Agent
                │
                ▼
Log Analytics Workspace
                │
                ▼
Microsoft Sentinel Analytics Rule
                │
                ▼
Alert Generated
                │
                ▼
Incident Automatically Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 76 |
| **Incident Name** | brute force |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Sentinel automatically correlated the generated alert into a single Microsoft Defender XDR incident.

The incident provides analysts with a centralized investigation workspace containing:

- Alert details
- Attack Story
- Investigation Graph
- Impacted Assets
- Evidence & Response
- Activity Timeline

This correlation simplifies the investigation process by consolidating all related telemetry into one incident.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual representation of the entities involved in the brute force attack.

Microsoft Defender XDR automatically associated:

- User Account
- Suspicious IP Address
- Brute Force Alert

This relationship enables analysts to quickly understand the attack flow and identify the source responsible for the authentication attempts.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph displays the relationships between the affected entities identified during the investigation.

Observed entities include:

- User Account (**dc.root.project\administrator**)
- Suspicious IP Address (**45.142.193.145**)

The graphical representation helps analysts pivot between related entities and investigate additional suspicious activity.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted asset.

## User

| Property | Value |
|----------|-------|
| **User** | dc.root.project\administrator |

No devices, cloud applications, mailboxes, or additional resources were associated with this incident.

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender collected evidence associated with the incident.

| Property | Value |
|----------|-------|
| **Entity Type** | IP Address |
| **Entity** | 45.142.193.145 |
| **Verdict** | Suspicious |

The source IP address was automatically identified as suspicious and linked to the incident, providing additional context for the investigation.

---

## 📸 Evidence & Response

> *(Insert Evidence & Response Screenshot)*

---

# 📋 Activities

The **Activities** tab records automated actions performed during incident creation and enrichment.

For this incident:

- Alert automatically correlated into Incident **76**
- Trigger performed by Microsoft Defender XDR
- Activity Status: **Completed**

The activity log provides an audit trail showing how the incident was automatically generated and enriched.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During the investigation, the analyst should:

- Verify whether the failed authentication attempts originated from a legitimate source.
- Review the authentication history for the targeted **Administrator** account.
- Investigate the suspicious source IP address (**45.142.193.145**) for additional malicious activity.
- Determine whether successful authentication occurred after the failed attempts.
- Search for related alerts involving the same user or IP address.
- Review endpoint activity for signs of privilege escalation or lateral movement.
- Block or isolate the source IP if the activity is confirmed to be malicious.
- Recommend enabling account lockout policies and enforcing Multi-Factor Authentication (MFA) where applicable.

---

# 🎯 Security Impact

Brute force attacks target user credentials through repeated authentication attempts and are commonly used as an initial access technique. If successful, attackers may obtain valid credentials that can be leveraged for privilege escalation, persistence, lateral movement, or unauthorized access to sensitive resources.

By detecting excessive failed logon attempts at an early stage, Microsoft Sentinel enables security teams to investigate and mitigate password guessing attacks before credentials are compromised, significantly reducing the risk of account takeover and further compromise of the environment.

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---# 🚨 Mimikatz → PsExec Correlation Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a high-confidence attack sequence where **Mimikatz** activity is followed by **PsExec** execution on the same endpoint.

The correlation analytics rule automatically linked both activities and generated a **High severity alert**, allowing SOC analysts to investigate the complete attack chain involving credential access and lateral movement.

---

## 📖 Attack Scenario

Attackers commonly use **Mimikatz** to obtain credentials after compromising a Windows system. These credentials can then be abused with tools such as **PsExec** to execute commands remotely and move laterally across the environment.

Microsoft Sentinel correlated the Mimikatz and PsExec activity because both events were associated with the same account and computer within the configured correlation window.

This provides stronger detection confidence than investigating the two activities separately.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | correlation 3 |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Credential Access, Lateral Movement |
| **Analytics Rule** | correlation 3 |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected **Mimikatz** activity followed shortly by **PsExec** activity.

The correlation rule identified the sequence as:

**Mimikatz → PsExec**

The activity involved:

- 👤 **Account:** `ROOT\SecManager`
- 💻 **Computer:** `Vm1.root.project`

---

## Alert Workflow

```text
Attacker gains access
          │
          ▼
Executes Mimikatz
(Credential Access)
          │
          ▼
Credentials potentially obtained
          │
          ▼
Executes PsExec
(Remote Execution)
          │
          ▼
Microsoft Sentinel Correlation Rule
          │
          ▼
High Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

## 📸 Alert Details

> *(Insert Alert Details Screenshot)*

---

## 📸 Query Results

> *(Insert Query Results Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 86 |
| **Incident Name** | correlation 3 |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 2 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically grouped **two related alerts** into Incident 86.

The incident combines both stages of the attack:

- 🔑 **Mimikatz** — Credential Access
- 🖥️ **PsExec** — Remote Execution / Lateral Movement

This provides analysts with a centralized investigation workspace containing the related alerts, entities, assets, and activities.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 Device: `Vm1.root.project`
- 👤 User: `ROOT\SecManager`
- 🚨 Correlated Alerts

This allows analysts to quickly understand the relationship between the affected account and endpoint.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **Device** | `Vm1.root.project` |
| **User** | `ROOT\SecManager` |

The graph allows the SOC analyst to pivot between related entities during the investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device** | `Vm1.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\SecManager` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender did not identify additional evidence in the Evidence & Response section at the time of investigation.

However, the query results provided important forensic information.

| Property | Value |
|----------|-------|
| **Account** | `ROOT\SecManager` |
| **Computer** | `Vm1.root.project` |
| **Mimikatz Time** | Jul 29, 2026 10:46:28 PM |
| **PsExec Time** | Jul 29, 2026 10:51:29 PM |

The timestamps show that the PsExec activity occurred approximately **5 minutes after** the Mimikatz activity.

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert automatically correlated into Incident 86
- 🚨 Second related alert automatically correlated
- 🏷️ Incident tagged **Triage Required**
- 🤖 Activities performed by Microsoft Defender XDR automation

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify whether Mimikatz execution was authorized.
- 👤 Identify the user responsible for the activity.
- 💻 Review activity on `Vm1.root.project`.
- 🔐 Investigate how Mimikatz was executed.
- 🧾 Determine whether credentials were successfully accessed or dumped.
- 🖥️ Review PsExec activity following the Mimikatz execution.
- 🌐 Identify any additional systems targeted through PsExec.
- 🔍 Search for similar Mimikatz and PsExec activity across the environment.
- ⬆️ Check for privilege escalation and persistence.
- 🔑 Reset compromised credentials if malicious activity is confirmed.
- 🚨 Isolate affected endpoints when required.

---

# 🎯 Security Impact

Credential access followed by remote execution can indicate an active attack chain.

Correlating **Mimikatz** and **PsExec** allows Microsoft Sentinel to provide stronger context and helps SOC analysts identify potentially malicious activity earlier.

If successful, this attack chain could lead to:

- 🔑 Credential Compromise
- ⬆️ Privilege Escalation
- 🔄 Lateral Movement
- 🛡️ Persistence
- 🏢 Domain Compromise
- 💣 Ransomware Deployment
- 📤 Data Exfiltration

Early detection and investigation can help defenders contain the attacker before the activity progresses further.

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---

# 🚨 Download Cradle Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a **Download Cradle** execution. A download cradle is a common technique where an attacker uses legitimate system tools, such as PowerShell, to download a malicious payload from a remote server to the compromised endpoint.

The analytics rule automatically identified the suspicious PowerShell command parameters and generated a **Medium severity alert**, allowing SOC analysts to investigate the potential command and control (C2) activity and payload delivery.

---

## 📖 Attack Scenario

Attackers frequently use "living off the land" binaries (LOLBins) like PowerShell to execute download cradles. Instead of dropping a bulky executable directly on the disk, the attacker executes a lightweight command that reaches out to an external server to fetch the second-stage payload. 

Microsoft Sentinel detected this activity by monitoring PowerShell execution logs for specific cmdlets and arguments, such as `Invoke-WebRequest` combined with an `-OutFile` parameter.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Download Cradle Detection |
| **Severity** | Medium |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Command and Control |
| **Analytics Rule** | Download Cradle Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected PowerShell commands used to download payloads from remote servers. 

The specific command line observed was:
`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "Invoke-WebRequest https://example.com -OutFile C:\Temp\test.html"`

The activity involved:

- 👤 **Account:** `Vm1\Sia123`
- 💻 **Computer:** `Vm1`

---

## Alert Workflow

```text
Attacker gains access / executes command
          │
          ▼
Executes PowerShell Download Cradle
(Command and Control)
          │
          ▼
Network request to external URL
          │
          ▼
Payload downloaded to local disk
          │
          ▼
Microsoft Sentinel Analytics Rule
          │
          ▼
Medium Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

## 📸 Alert Details

> *(Insert Alert Details Screenshot)*

---

## 📸 Query Results

> *(Insert Query Results Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 59 |
| **Incident Name** | Download Cradle Detection |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 59 based on the scheduled detection alert from Microsoft Sentinel. 

This incident provides the analyst with the necessary workspace to investigate the command execution, the target URL, and the impacted endpoint.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Comman...`

This allows analysts to quickly understand the execution chain on the affected endpoint.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **Device** | `Vm1` |
| **Process** | `powershell.exe` |

The graph allows the SOC analyst to visually pivot between the host and the executed process during the investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `Vm1` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `Vm1\Sia123` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious process execution as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `Vm1\Sia123` |
| **Computer** | `Vm1` |
| **Time Generated** | Jul 25, 2026 11:07:57 PM |
| **Command Line** | `... -Command "Invoke-WebRequest https://example.com -OutFile C:\Temp\test.html"` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Download Cradle Detection' was added to the incident.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the legitimacy of the target URL (`https://example.com`).
- 🌐 Review network and proxy logs to determine if the connection to the URL was successful and if data was downloaded.
- 📁 Inspect the file system for the presence of the downloaded file (`C:\Temp\test.html`) and analyze it for malicious content.
- 👤 Confirm if the user `Vm1\Sia123` authorized this activity.
- ⚙️ Identify the parent process that spawned the PowerShell instance to uncover the initial access vector.
- 🔍 Search for execution of the downloaded file (e.g., child processes spawned from the downloaded payload).
- 🚨 Isolate the affected endpoint (`Vm1`) if malicious payload execution is confirmed.

---

# 🎯 Security Impact

A download cradle indicates that an attacker (or unauthorized software) is attempting to pull additional tools or payloads into the environment. 

Detecting this behavior allows SOC analysts to intercept an attack in its early stages before the primary payload is executed.

If successful, this attack chain could lead to:

- 📥 Execution of Malware (Ransomware, RATs, Info Stealers)
- 📡 Establishing Command and Control (C2) Communication
- 🔄 Lateral Movement preparation
- 🛡️ Establishing Persistence within the environment

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)


---
# 🚨 Encoded PowerShell Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the execution of **Base64-encoded PowerShell commands**. Using the `-EncodedCommand` parameter is a common defense evasion technique employed by attackers to hide malicious scripts, bypass string-based security filters, and obfuscate their activity from defenders.

The analytics rule automatically identified the suspicious PowerShell execution and generated a **High severity alert**, allowing SOC analysts to investigate the obfuscated command and determine its true intent.

---

## 📖 Attack Scenario

Attackers frequently use PowerShell to execute payloads, establish persistence, or move laterally. To avoid detection by antivirus solutions and command-line logging, they convert their plain-text scripts into Base64 format. When executed using the `-EncodedCommand` (or similar aliases like `-e` or `-enc`) flag, PowerShell decodes and runs the script directly in memory.

Microsoft Sentinel detected this activity by monitoring process execution logs for PowerShell instances launched with these specific encoding parameters.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Encoded PowerShell |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Execution |
| **Analytics Rule** | Encoded PowerShell Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected the execution of Base64-encoded PowerShell commands.

The specific command line observed included the `-EncodedCommand` parameter followed by a Base64 string:
`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SQB...`

The activity involved:

- 👤 **Account:** `Vm1\Sia123`
- 💻 **Computer:** `Vm1`

---

## Alert Workflow

```text
Attacker gains access / establishes foothold
          │
          ▼
Executes Obfuscated Script
(Defense Evasion / Execution)
          │
          ▼
PowerShell -EncodedCommand executed
          │
          ▼
Script decoded and run in memory
          │
          ▼
Microsoft Sentinel Analytics Rule
          │
          ▼
High Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

## 📸 Alert Details

> *(Insert Alert Details Screenshot)*

---

## 📸 Query Results

> *(Insert Query Results Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 35 |
| **Incident Name** | Encoded PowerShell |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 35 based on the scheduled detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the encoded command execution, the origin of the process, and the affected endpoint.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Encod...`

This allows analysts to quickly understand the execution chain on the affected endpoint and identify the suspicious process.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **Device** | `Vm1` |
| **Process** | `powershell.exe` |

The graph allows the SOC analyst to visually pivot between the host and the executed encoded process during the investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `Vm1` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `Vm1\Sia123` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious process execution as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `Vm1\Sia123` |
| **Computer** | `Vm1` |
| **Time Generated** | Jul 24, 2026 5:13:49 PM |
| **Command Line** | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand <Base64_String>` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Encoded PowerShell' was automatically correlated to incident 35.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Extract the Base64 string from the command line and decode it (e.g., using CyberChef) to reveal the actual executed script.
- ⚙️ Identify the parent process that spawned the PowerShell instance to uncover how the encoded command was delivered (e.g., cmd.exe, a malicious macro in Word, a scheduled task).
- 👤 Confirm if the user `Vm1\Sia123` or an administrator was performing authorized administrative tasks that use encoded commands (though rare).
- 🔍 Analyze the decoded script to understand its intent (e.g., downloading further payloads, modifying registry keys, dumping credentials).
- 🚨 Isolate the affected endpoint (`Vm1`) if the decoded script proves to be malicious.
- 🌐 Check network logs for any external connections initiated by the PowerShell process if the decoded script acts as a downloader.

---

# 🎯 Security Impact

Encoded PowerShell commands are a strong indicator of defense evasion and obfuscation. 

Detecting this behavior allows SOC analysts to uncover hidden malicious activity that might otherwise bypass standard string-matching defenses.

If successful and left undetected, this execution could lead to:

- 🥷 Defense Evasion (bypassing AV/EDR detections)
- 📥 Silent Execution of Malware or Ransomware
- 📡 Establishing Command and Control (C2)
- 🔄 Lateral Movement
- 🛡️ Establishing Persistence within the environment

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---

# 🚨 Firewall Disabled Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying system modifications that turn off or impair the Windows Defender Firewall. 

The analytics rule automatically identified the execution of network shell (`netsh.exe`) commands explicitly designed to disable firewall profiles and generated a **Medium severity alert**. This allows SOC analysts to investigate potential defense evasion activities on the endpoint.

---

## 📖 Attack Scenario

Attackers frequently attempt to disable host-based firewalls immediately after compromising a system. By turning off the Windows Defender Firewall, adversaries can bypass network filtering, establish unhindered Command and Control (C2) communications, exfiltrate data, and allow lateral movement tools (like PsExec, WMI, or RDP) to function without restriction.

Microsoft Sentinel detected this activity by monitoring endpoint process execution logs for specific `netsh.exe` command-line arguments that alter the `advfirewall` state.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | firewall disabled |
| **Severity** | Medium |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Defense Evasion |
| **Analytics Rule** | firewall disabled |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected system modifications that turn off or impair the Windows Defender Firewall.

The specific command line observed was:
`"C:\Windows\system32\netsh.exe" advfirewall set allprofiles state off`

The activity involved:

- 👤 **Account:** `ROOT\SecManager`
- 💻 **Computer:** `Vm1.root.project`

---

## Alert Workflow

```text
Attacker gains access / establishes foothold
          │
          ▼
Executes netsh.exe command
(Defense Evasion)
          │
          ▼
Windows Defender Firewall Disabled
          │
          ▼
Endpoint logging captures process execution
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
          │
          ▼
Medium Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

> *(Insert Alert Overview Screenshot)*

---

## 📸 Alert Details

> *(Insert Alert Details Screenshot)*

---

## 📸 Query Results

> *(Insert Query Results Screenshot)*

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 220 |
| **Incident Name** | firewall disabled |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 8 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 220 based on the Near Real-Time (NRT) detection alerts from Microsoft Sentinel. 

Notably, this incident grouped **8 active alerts** for the same activity into a single incident, indicating repeated execution of the command or multiple rule triggers. This provides the analyst with a centralized workspace to investigate the defense evasion attempt.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\SecManager`
- 💻 **Device:** `Vm1.root.project`
- ⚙️ **Process:** `"C:\Windows\system32\netsh.exe" advfirewall set allprofiles state ...`

This allows analysts to quickly understand the relationship between the compromised account, the affected endpoint, and the execution chain.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\SecManager` |
| **Device** | `Vm1.root.project` |
| **Process** | `netsh.exe` |

The graph allows the SOC analyst to visually pivot between the user account, host, and the executed process during the investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `Vm1.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\SecManager` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious process execution as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `ROOT\SecManager` |
| **Computer** | `Vm1.root.project` |
| **Time Generated** | Aug 6, 2026 7:46:13 PM |
| **Command Line** | `"C:\Windows\system32\netsh.exe" advfirewall set allprofiles state off` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 8 Alerts for 'firewall disabled' were automatically correlated to incident 220 over a short time span.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify if the user `ROOT\SecManager` was performing authorized administrative troubleshooting or maintenance that required disabling the firewall.
- ⚙️ Identify the parent process of `netsh.exe` to determine how the command was launched (e.g., via a malicious script, an interactive shell, or an exploitation framework).
- 🌐 Monitor the endpoint for suspicious inbound or outbound network connections immediately following the firewall being disabled.
- 🔍 Search for additional signs of compromise on `Vm1.root.project`, such as new services being created, unauthorized lateral movement (RDP/SMB), or malware dropped onto the disk.
- 🚨 Isolate the affected endpoint (`Vm1.root.project`) to prevent lateral movement if the activity is deemed malicious.
- 🛡️ Re-enable the Windows Defender Firewall via policy enforcement or remediation scripts.

---

# 🎯 Security Impact

Disabling the host firewall is a critical defense evasion tactic that removes a primary layer of endpoint protection.

Detecting this behavior allows SOC analysts to intercept an attacker who is preparing the environment for further malicious actions.

If successful and left undetected, this execution could lead to:

- 🥷 Defense Evasion
- 📡 Unrestricted Command and Control (C2) Communication
- 🔄 Successful Lateral Movement across the network
- 📤 Data Exfiltration without network-level blocking
- 💣 Ransomware Deployment to unprotected segments

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
