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

---
