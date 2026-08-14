# #🚨 Detection Validation & Investigation

This section demonstrates the successful validation of each Microsoft Sentinel analytics rule. After executing attack simulations within the lab environment, Microsoft Sentinel generated alerts and automatically created incidents based on the configured incident creation settings.

Each alert includes enriched entities, related events, and investigation context, confirming that the corresponding detection logic functioned as expected.

---

# 📋 Detection Validation Summary

| Alert | Severity | Incident Created | Validation Status | Description |
|-------|----------|------------------|-------------------|-------------|
| **[Brute Force Login Detection](#-brute-force-login-detection)** | High | ✅ Yes | ✅ Validated | Generated after multiple failed Windows logon attempts exceeded the configured threshold. |
| **[New Local User Creation](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-user-created-detection)** | Medium | ✅ Yes | ✅ Validated | Generated when a new local user account was created on a monitored endpoint. |
| **[Encoded PowerShell Detection](#-encoded-powershell-detection)** | High | ✅ Yes | ✅ Validated | Generated after execution of a Base64-encoded PowerShell command. |
| **[Download Cradle Detection](#-download-cradle-detection)** | High | ✅ Yes | ✅ Validated | Generated when PowerShell attempted to download remote content from an external source. |
| **[Mimikatz Detection](#-mimikatz-detection)** | High | ✅ Yes | ✅ Validated | Generated after execution of the Mimikatz credential dumping tool. |
| **[PsExec Detection](#-psexec-detection)** | High | ✅ Yes | ✅ Validated | Generated when PsExec was used to execute commands remotely. |
| **[Event Log Cleared Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-log-cleared-detection)** | High | ✅ Yes | ✅ Validated | Generated when Windows Event Logs were cleared to remove forensic evidence. |
| **[Scheduled Task Creation](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-scheduled-task-created-detection)** | Medium | ✅ Yes | ✅ Validated | Generated when a new scheduled task was created on the monitored endpoint. |
| **[Suspicious Discovery Commands](#-suspicious-discovery-commands)** | Medium | ✅ Yes | ✅ Validated | Generated after execution of common Windows reconnaissance commands. |
| **[Domain Admin Group Modification](#-domain-admin-group-modification)** | Critical | ✅ Yes | ✅ Validated | Generated when a privileged Active Directory group membership was modified. |
| **[AS-REP Roasting Detection](#-as-rep-roasting-detection)** | High | ✅ Yes | ✅ Validated | Generated when an AS-REQ without Kerberos pre-authentication was detected, indicating a potential AS-REP Roasting attack targeting accounts with pre-authentication disabled. |
| **[Correlation 3](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-mimikatz--psexec-correlation-detection)** | High | ✅ Yes | ✅ Validated | Generated after correlating high-confidence multi-stage attack sequences. |
| **[Firewall Disabled](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-firewall-disabled-detection)** | Medium | ✅ Yes | ✅ Validated | Generated after system modifications that turn off or impair the Windows Defender Firewall. |
| **[Kerberoasting Detection](#-kerberoasting-detection)** | High | ✅ Yes | ✅ Validated | Generated when attempts to request Kerberos service tickets for offline password cracking were detected. |
| **[Mshta Execution](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-mshta-execution-detection)** | High | ✅ Yes | ✅ Validated | Generated after suspicious execution of `mshta.exe` utilizing local scripts or remote payloads. |
| **[Pass-the-Hash Detection](#-pass-the-hash-detection)** | High | ✅ Yes | ✅ Validated | Generated after detecting anomalous NTLM network authentication patterns indicating lateral movement. |
| **[Network Discovery](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-network-discovery-detection)** | Medium | ✅ Yes | ✅ Validated | Generated after execution of commands aimed at mapping internal network topologies and connections. |
| **[Password Spray Detection](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-password-spray-detection)** | High | ✅ Yes | ✅ Validated | Generated when password spraying was detected across multiple accounts from a single IP address. |
| **[PowerShell Download](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-powershell-download-detection)** | High | ✅ Yes | ✅ Validated | Generated when PowerShell execution was used specifically to download files from remote locations. |
| **[SMB Admin Share Access](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-smb-admin-share-access-detection)** | High | ✅ Yes | ✅ Validated | Generated when access to administrative SMB shares (e.g., C$, ADMIN$, IPC$) was detected for lateral movement. |
| **[User Added to Local Administrators](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-user-added-to-local-administrators-detection)** | High | ✅ Yes | ✅ Validated | Generated whenever a user was added to an administrative group or made an administrator. |
| **[WMI Lateral Movement Detection](#-wmi-lateral-movement-detection)** | High | ✅ Yes | ✅ Validated | Generated after identifying suspicious WMI process execution patterns indicative of remote execution. |
| **[Active Directory Computer Enumeration Detected](#-active-directory-computer-enumeration-detected)** | Medium | ✅ Yes | ✅ Validated | Generated when discovery or enumeration queries are executed to map out computers within Active Directory. |
| **[Certutil Download](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-certutil-download-detection)** | High | ✅ Yes | ✅ Validated | Generated when the native `certutil.exe` utility is abused to download files or payloads from remote servers. |

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 182058" src="https://github.com/user-attachments/assets/67e9d47d-e1aa-4ad3-a94b-7090980fdf41" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 184255" src="https://github.com/user-attachments/assets/25d5592b-340f-4b1c-8034-c93caea77946" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 184235" src="https://github.com/user-attachments/assets/8c1707f4-40ed-42a0-8e9d-d63a2f0c1eb3" />


---



# 🔍 Investigation Graph

The investigation graph automatically maps the entities involved in the incident.

Observed entities include:

- Device (Vm1)
- User (Vm1\Sia123)
- Suspicious Process (HOSTNAME.EXE)

This visualization helps analysts pivot between related entities during an investigation.



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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 184316" src="https://github.com/user-attachments/assets/e4d09793-250f-411c-8b6a-e9059aced9be" />


---

## 📸 Impacted User

<img width="1920" height="1020" alt="Screenshot 2026-08-04 184321" src="https://github.com/user-attachments/assets/f74ea261-de15-4ad5-96c2-a8222c75e3d2" />

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 184338" src="https://github.com/user-attachments/assets/0b481a03-ec2d-42ac-95f1-74e2c972a313" />


---

# 📋 Activities

The Activities tab records automated actions performed during the investigation.

For this incident:

- Alert automatically correlated into Incident 3
- Trigger performed by Microsoft Defender XDR
- Activity Status: Completed

This provides an audit trail showing how the incident was created.


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

> 📸 **Screenshot:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 201607" src="https://github.com/user-attachments/assets/534bc69e-a3e1-481a-8fda-8f9e3ffbcabc" />


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

> 📸 **Screenshot:** 
<img width="1920" height="1020" alt="Screenshot 2026-08-04 201656" src="https://github.com/user-attachments/assets/879af468-2b0d-4ad5-9e19-943707f16fd0" />

---

## 🕵️ Attack Story

The **Attack Story** provides a visual representation of the incident by mapping the relationships between the generated alert and the impacted asset. It enables analysts to quickly understand how the suspicious Kerberos authentication activity relates to the affected device.

### 👀 Observed Entity

| Entity Type | Value |
|-------------|-------|
| Device | DC.root.project |


---

## 🕸️ Investigation Graph

The **Investigation Graph** visually connects the alert with associated entities, allowing analysts to pivot between the affected device and related security events. This graphical representation accelerates incident triage and helps identify additional indicators of compromise.

### 🔗 Associated Entity

| Entity | Value |
|--------|-------|
| Device | DC.root.project |



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

> 📸 **Screenshot:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 201722" src="https://github.com/user-attachments/assets/fd293514-486d-41db-b705-f0f3724a341c" />



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

> 📸 **Screenshot:** <img width="1920" height="1020" alt="Screenshot 2026-08-04 201621" src="https://github.com/user-attachments/assets/d359ac37-ace9-430b-8c35-b87bb2514059" />


---

## 📅 Activities

The **Activities** tab records actions automatically performed during incident creation and alert correlation.

| Time | Activity | Performed By | Status |
|------|----------|--------------|--------|
| Jul 30, 2026 6:31 PM | Alert automatically correlated to Incident 89 | Microsoft Defender XDR | Completed |

The activity timeline confirms that Microsoft Defender XDR successfully correlated the alert into a single incident without requiring manual analyst intervention.

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 201952" src="https://github.com/user-attachments/assets/34523f03-654d-49c2-9fd3-e12f26d36a77" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 202038" src="https://github.com/user-attachments/assets/5423cd81-e1ad-450c-84aa-90b5407921c5" />


---

# 🕸️ Attack Story

The Attack Story provides a visual representation of the entities involved in the brute force attack.

Microsoft Defender XDR automatically associated:

- User Account
- Suspicious IP Address
- Brute Force Alert

This relationship enables analysts to quickly understand the attack flow and identify the source responsible for the authentication attempts.



---

# 🔍 Investigation Graph

The Investigation Graph displays the relationships between the affected entities identified during the investigation.

Observed entities include:

- User Account (**dc.root.project\administrator**)
- Suspicious IP Address (**45.142.193.145**)

The graphical representation helps analysts pivot between related entities and investigate additional suspicious activity.


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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 202115" src="https://github.com/user-attachments/assets/1ac844a0-24ed-484a-b83c-a33667af8aab" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 202120" src="https://github.com/user-attachments/assets/f7895588-2d1b-461b-9024-fba038b38d4e" />

---

# 📋 Activities

The **Activities** tab records automated actions performed during incident creation and enrichment.

For this incident:

- Alert automatically correlated into Incident **76**
- Trigger performed by Microsoft Defender XDR
- Activity Status: **Completed**

The activity log provides an audit trail showing how the incident was automatically generated and enriched.

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

# 🚨 Mimikatz → PsExec Correlation Detection

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


<img width="1920" height="1020" alt="Screenshot 2026-08-04 202649" src="https://github.com/user-attachments/assets/71ca3d4d-c597-4afe-baa5-8788f7f58d18" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 202715" src="https://github.com/user-attachments/assets/b59faa0e-0936-4d9d-877c-4a3fb1c2a297" />

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 Device: `Vm1.root.project`
- 👤 User: `ROOT\SecManager`
- 🚨 Correlated Alerts

This allows analysts to quickly understand the relationship between the affected account and endpoint.

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 202734" src="https://github.com/user-attachments/assets/e8871f86-e019-4338-a03b-b4f7501ce1ba" />


---

## 📸 Impacted User

<img width="1920" height="1020" alt="Screenshot 2026-08-04 202739" src="https://github.com/user-attachments/assets/9460b260-0dc9-44cd-97bb-3cfb290a32b5" />

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

<img width="1146" height="346" alt="Screenshot 2026-08-04 202649" src="https://github.com/user-attachments/assets/1fb379a0-e9da-454a-9709-989d200c1a6d" />

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


<img width="1920" height="1020" alt="Screenshot 2026-08-04 203113" src="https://github.com/user-attachments/assets/cd542cf0-11eb-4452-b4f1-63098c6bca40" />

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203155" src="https://github.com/user-attachments/assets/76a1eccd-a0f2-4948-b743-cbb413b57dcd" />


---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Comman...`

This allows analysts to quickly understand the execution chain on the affected endpoint.

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


# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `Vm1` |
| **Risk Level** | None |

---


## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203215" src="https://github.com/user-attachments/assets/21043737-2dea-4412-a297-eef14b35872a" />

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203224" src="https://github.com/user-attachments/assets/38c105b0-acdb-4b31-af08-10eb42ba03ff" />


---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Download Cradle Detection' was added to the incident.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

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
<img width="1920" height="1020" alt="Screenshot 2026-08-04 203351" src="https://github.com/user-attachments/assets/74f77141-0a8b-49f3-9bd9-a0d371674b02" />

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203433" src="https://github.com/user-attachments/assets/521563c4-4c5f-4d43-b315-af356b45a665" />


---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Encod...`

This allows analysts to quickly understand the execution chain on the affected endpoint and identify the suspicious process.

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


# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `Vm1` |
| **Risk Level** | None |

---



## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203455" src="https://github.com/user-attachments/assets/0f4d51dd-e5cf-485d-9106-af4ccc425bca" />

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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203506" src="https://github.com/user-attachments/assets/334b1c7c-ab43-41d7-9ad6-88260b5ced7d" />

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Encoded PowerShell' was automatically correlated to incident 35.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

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

<img width="1920" height="1020" alt="Screenshot 2026-08-06 204946" src="https://github.com/user-attachments/assets/a30dd958-e58f-47aa-94c8-b75cb27959bb" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-06 204851" src="https://github.com/user-attachments/assets/177088f4-0109-4440-8bed-9e5dd17cf0e1" />

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\SecManager`
- 💻 **Device:** `Vm1.root.project`
- ⚙️ **Process:** `"C:\Windows\system32\netsh.exe" advfirewall set allprofiles state ...`

This allows analysts to quickly understand the relationship between the compromised account, the affected endpoint, and the execution chain.

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

<img width="1920" height="1020" alt="Screenshot 2026-08-06 204910" src="https://github.com/user-attachments/assets/2a38990a-20ea-435b-88b1-62d6dc80f20c" />


---

## 📸 Impacted User

<img width="1920" height="1020" alt="Screenshot 2026-08-06 204916" src="https://github.com/user-attachments/assets/122a6f4b-643a-4254-bac5-d00525a84ac5" />


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

<img width="1920" height="1020" alt="Screenshot 2026-08-06 204921" src="https://github.com/user-attachments/assets/acf0139d-8191-422d-95a3-9f1cfe80f621" />


---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 8 Alerts for 'firewall disabled' were automatically correlated to incident 220 over a short time span.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

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

# 🚨 Kerberoasting Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a potential **Kerberoasting** attack. Kerberoasting is a post-exploitation technique where an attacker requests Kerberos Service Tickets (TGS) for service accounts with Service Principal Names (SPNs) and then attempts to crack the passwords offline.

The analytics rule automatically identified the suspicious Kerberos ticket request (often indicated by specific encryption types like RC4 being requested for service accounts) and generated a **High severity alert**, allowing SOC analysts to investigate the compromised account and targeted service.

---

## 📖 Attack Scenario

Once an attacker compromises any valid domain user account, they can query Active Directory for accounts with associated SPNs (typically service accounts, which often have weak, non-expiring passwords). The attacker then requests a Kerberos TGS for that service. 

Active Directory encrypts the ticket using the service account's password hash and sends it back to the attacker. The attacker extracts this ticket from memory and uses offline brute-force tools (like Hashcat or John the Ripper) to crack the hash and retrieve the plain-text password, often leading to privilege escalation.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Kerberoasting Detection |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Credential Access |
| **Analytics Rule** | Kerberoasting Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected attempts to request Kerberos service tickets for offline password cracking.

The specific event data revealed an unusual ticket request for a service principal.

The activity involved:

- 👤 **Target User:** `L1Soc@ROOT.PROJECT`
- ⚙️ **Service Name:** `sqlsvc`
- 💻 **Computer:** `DC.root.project`
- 🌐 **Source IP:** `::ffff:10.0.0.4`

---

## Alert Workflow

```text
Attacker gains standard user access
          │
          ▼
Queries AD for SPNs (Service Accounts)
          │
          ▼
Requests TGS ticket for targeted SPN
(Credential Access)
          │
          ▼
AD returns ticket encrypted with service hash
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
          │
          ▼
High Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203647" src="https://github.com/user-attachments/assets/0bbefeb8-904e-4f5c-a46e-b2cbc14e8013" />

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 92 |
| **Incident Name** | Kerberoasting Detection |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 92 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with the necessary workspace to investigate the compromised account used to request the ticket, the targeted domain controller, and the specific service account at risk.

---

## 📸 Incident Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203716" src="https://github.com/user-attachments/assets/845247e4-962b-4d86-a8f3-1e0d540d37f3" />


---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `DC.root.project`
- 🚨 **Correlated Alerts**

This allows analysts to quickly understand the endpoint involved in handling the Kerberos ticket requests.

---



# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **Device** | `DC.root.project` |

The graph allows the SOC analyst to visually pivot around the affected Domain Controller during the investigation.

---



# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203752" src="https://github.com/user-attachments/assets/88676226-ce95-4408-b94a-34a299984458" />

---

# 🧪 Evidence & Response

Microsoft Defender's query results provided important forensic information embedded in the raw EventData XML.

| Property | Value |
|----------|-------|
| **Time Generated** | Jul 30, 2026 6:32:46 PM |
| **Computer** | `DC.root.project` |
| **Target User Name** | `L1Soc@ROOT.PROJECT` |
| **Service Name** | `sqlsvc` |
| **Ticket Encryption Type**| `0x12` |
| **IP Address** | `::ffff:10.0.0.4` |

*Note: The Ticket Encryption Type `0x12` often correlates with RC4 encryption (AES is generally preferred), which is commonly targeted by attackers for easier offline cracking.*

---



# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Kerberoasting Detection' was automatically correlated to incident 92.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---


# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the source IP (`::ffff:10.0.0.4`) and the user account (`L1Soc@ROOT.PROJECT`) that initiated the ticket request to determine if the activity is legitimate.
- ⚙️ Identify the targeted service account (`sqlsvc`) and assess its privilege level within the domain (e.g., Domain Admin, Local Admin on specific servers).
- 🔐 Check if the targeted service account uses a weak, easily crackable password or if it is enforcing AES encryption for Kerberos.
- 👤 Look for subsequent suspicious logins or activities originating from the targeted service account (`sqlsvc`), which would indicate the password was successfully cracked and used.
- 🚨 Reset the password of the targeted service account (`sqlsvc`) immediately using a complex, randomly generated password greater than 25 characters.
- 🛡️ Consider configuring the service account to support AES encryption and disable RC4 to make offline cracking significantly harder.

---

# 🎯 Security Impact

Kerberoasting is a critical credential access technique because it does not require administrative privileges to execute—any valid domain user can request service tickets.

Detecting this behavior allows SOC analysts to intercept an attacker before they can escalate privileges.

If successful and left undetected, this execution could lead to:

- 🔑 Credential Compromise of highly privileged service accounts
- ⬆️ Rapid Privilege Escalation
- 🔄 Lateral Movement using the compromised service account
- 🏢 Full Domain Compromise
- 📤 Data Exfiltration

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---

# 🚨 Log Cleared Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the clearing of Windows event logs on an endpoint. Clearing event logs is a primary defense evasion technique used by attackers to wipe forensic evidence of their activities, such as lateral movement, credential dumping, or malware execution.

The analytics rule detected an Event ID 1102 ("The audit log was cleared") and automatically generated a **High severity alert**, allowing SOC analysts to investigate the endpoint for preceding malicious behavior.

---

## 📖 Attack Scenario

Attackers frequently use built-in system tools (like `wevtutil.exe` or PowerShell's `Clear-EventLog`) to clear the Security, System, or Application event logs immediately after completing their objectives on a compromised host. By doing so, they eliminate traces of compromised accounts, executed commands, and accessed services.

Microsoft Sentinel detected this activity by monitoring Windows Event Logs for specific Event IDs—most notably Event ID 1102 (audit log cleared) or Event ID 104 (log file cleared)—indicating an intentional disruption of endpoint logging.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Log Cleared |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Defense evasion |
| **Analytics Rule** | Log Cleared |

---

## Alert Description

The alert was triggered because "whenever logs are cleared it generates an alert". 

The specific event generated was Event ID `1102 - The audit log was cleared`.

The activity involved:

- 💻 **Computer:** `Vm1`
- ⚙️ **Event ID:** `1102`

---

## Alert Workflow

```text
Attacker compromises host / executes malicious actions
          │
          ▼
Executes log clearing commands
(Defense Evasion - T1070.001)
          │
          ▼
Windows generates Event ID 1102
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
          │
          ▼
High Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 203936" src="https://github.com/user-attachments/assets/074bdcf9-0f05-44ce-9bd3-c306e1787a69" />


---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 25 |
| **Incident Name** | Log Cleared |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 25 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with the necessary workspace to investigate why the logs were cleared on the impacted endpoint.

---

## 📸 Incident Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204005" src="https://github.com/user-attachments/assets/c6b1916c-68e8-4620-bbb0-02e75e72e676" />


---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `Vm1`
- ⚙️ **Event/Process Entity:** `1102`

This allows analysts to quickly understand the execution chain on the affected endpoint.

---



# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **Device** | `Vm1` |
| **Event** | `1102` |

The graph allows the SOC analyst to visually pivot between the host and the log-clearing event during the investigation.


---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `Vm1` |
| **Risk Level** | None |

---

## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204025" src="https://github.com/user-attachments/assets/a3ddd550-b3be-4919-a584-c4cd464a80ad" />


---

# 🧪 Evidence & Response

Microsoft Defender identified suspicious activity as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process (identified via Event ID 1102) |
| **Verdict** | Suspicious |
| **Computer** | `Vm1` |
| **Time Generated** | Jul 24, 2026 5:55:30 PM |
| **Activity** | `1102 - The audit log was cleared.` |

---

## 📸 Evidence & Response

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204032" src="https://github.com/user-attachments/assets/d642005a-66e0-489a-a5dd-9fa0585d373b" />


---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Log Cleared' was automatically correlated to incident 25 at Jul 24, 2026 5:58 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---



# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Determine which user account was active on `Vm1` at the time the logs were cleared.
- ⚙️ Check if the log clearing was part of a scheduled administrative task or script (though this is rare for security logs).
- 🔍 Hunt for any surviving forensic artifacts or alerts on `Vm1` immediately prior to the log clearing event (e.g., failed logins, suspicious PowerShell execution, or lateral movement attempts).
- 🌐 Correlate network traffic logs (firewall, proxy) from `Vm1` to see if there was Command and Control (C2) communication or data exfiltration just before the wipe.
- 🚨 Isolate the affected endpoint (`Vm1`) immediately, as log clearing is highly indicative of an active, human-driven intrusion.
- 🛡️ Review central log repositories (like Sentinel workspaces) to reconstruct the attacker's actions prior to the local log destruction.

---

# 🎯 Security Impact

Clearing event logs is a critical defense evasion tactic that blinds local forensic tools and removes evidence of an attacker's foothold.

Detecting this behavior allows SOC analysts to identify that an endpoint is likely heavily compromised, even if the primary malicious actions were hidden.

If successful and left uninvestigated, this execution could indicate:

- 🥷 Successful Defense Evasion
- 🔑 Hidden Credential Compromise
- 🔄 Unseen Lateral Movement
- 💣 Preparation for a destructive payload (e.g., Ransomware)

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---

# 🚨 Mimikatz Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying **Mimikatz** execution on an endpoint. Mimikatz is a well-known credential dumper capable of extracting plaintext passwords, hashes, PIN codes, and Kerberos tickets from memory.

The analytics rule automatically identified the execution of a suspicious, Base64-encoded PowerShell command commonly associated with script-based Mimikatz deployment (such as `Invoke-Mimikatz`) and generated a **High severity alert**. This allows SOC analysts to immediately investigate critical credential access attempts.

---

## 📖 Attack Scenario

After gaining initial access to a system, attackers frequently attempt to harvest credentials to elevate their privileges and move laterally across the network. To avoid leaving artifacts on the disk that antivirus solutions might detect, adversaries often load Mimikatz directly into memory using PowerShell.

Microsoft Sentinel detected this activity by monitoring endpoint process execution logs for PowerShell instances launched with the `-EncodedCommand` (or `-E`) parameter containing payload signatures recognized as Mimikatz activity.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Mimikatz Detection |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Credential Access |
| **Analytics Rule** | Mimikatz Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected a PowerShell command line execution indicative of Mimikatz.

The specific command line observed was an encoded PowerShell command:
`powershell.exe -NoProfile -E VwByAGkAdABlAC0ASABvAHMAdAAgADUANQA3ADEAMAA4ADEANgAtAGUANwAwAdCALQA0ADUANABjAC0AYgAyAGEAMQAtADcANQBlADkANABhAGYAMgA1ADIAMQBjAA==`

The activity involved:

- 👤 **Account:** `WORKGROUP\Vm1$`
- 💻 **Computer:** `Vm1`

---

## Alert Workflow

```text
Attacker gains access to host
          │
          ▼
Executes Encoded PowerShell Command
(Credential Access - In-Memory)
          │
          ▼
Mimikatz loaded into memory
          │
          ▼
Process execution logged by OS
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

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204242" src="https://github.com/user-attachments/assets/d72889a0-df79-4fca-aeee-3be0f1f5606d" />

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 16 |
| **Incident Name** | Mimikatz Detection |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 16 based on the scheduled detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the credential dumping attempt, the compromised device, and the executing account context.

---

## 📸 Incident Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204314" src="https://github.com/user-attachments/assets/7f7a4060-b9fd-4f2d-8d09-f0881fa0926c" />

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `WORKGROUP\Vm1$`
- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `powershell.exe -NoProfile -E VwByAGkAdABlAC0ASABvAHMAdAA...`

This allows analysts to quickly understand the execution chain on the affected endpoint and the account used to run the process.

---



# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `WORKGROUP\Vm1$` |
| **Device** | `Vm1` |
| **Process** | `powershell.exe` |

The graph allows the SOC analyst to visually pivot between the host, the system account, and the executed encoded process during the investigation.

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
| **User** | `WORKGROUP\Vm1$` |

---

## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204339" src="https://github.com/user-attachments/assets/2fc3d6e8-1be9-4143-9599-29293429b530" />


---

## 📸 Impacted User

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204348" src="https://github.com/user-attachments/assets/6d9d1604-4695-4cc9-9a0d-ac4f0b9eed16" />


---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious process execution as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `WORKGROUP\Vm1$` |
| **Computer** | `Vm1` |
| **Time Generated** | Jul 24, 2026 5:24:55 PM |
| **Command Line** | `powershell.exe -NoProfile -E <Base64_String>` |

---

## 📸 Evidence & Response

<img width="1920" height="1020" alt="Screenshot 2026-08-04 204356" src="https://github.com/user-attachments/assets/65798b0b-4eeb-4cc4-8eb2-b8588c46d83d" />


---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Mimikatz Detection' was automatically correlated to incident 16 at Jul 24, 2026 5:30 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.



---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Decode the Base64 string from the command line (`VwByAGkAdABlAC0ASABvAHMAdAAgADUANQA3ADE...`) to verify the exact PowerShell commands being executed (e.g., verifying if it is `Invoke-Mimikatz`).
- 👤 Identify how the `WORKGROUP\Vm1$` system account was leveraged to run the command, which indicates the attacker already possesses elevated/SYSTEM privileges on the host.
- ⚙️ Identify the parent process of `powershell.exe` to trace the attacker's initial access vector or persistence mechanism.
- 🔐 Assume all credentials that were active in memory on `Vm1` at the time of execution are compromised. Identify which users were logged into `Vm1` recently.
- 🚨 Isolate the affected endpoint (`Vm1`) immediately to prevent the attacker from using the stolen credentials to move laterally.
- 🔑 Force a password reset for any user accounts that had active sessions on `Vm1`.

---

# 🎯 Security Impact

Mimikatz execution is a critical security event that directly leads to credential compromise. 

Detecting this behavior allows SOC analysts to respond to a high-privilege intrusion before the attacker can expand their access across the network.

If successful and left undetected, this execution could lead to:

- 🔑 Plaintext Password and NTLM Hash Theft
- 🎫 Kerberos Ticket Exfiltration (Pass-the-Ticket)
- 🔄 Rapid Lateral Movement
- ⬆️ Privilege Escalation (e.g., Domain Admin compromise)
- 🏢 Full Network / Active Directory Compromise

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Mshta Execution Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the execution of **Mshta.exe**. Mshta is a legitimate Windows utility designed to execute Microsoft HTML Applications (.hta files). However, attackers frequently abuse it as a "Living off the Land" binary (LOLBin) to proxy the execution of malicious scripts (like VBScript or JScript) while evading application whitelisting and traditional antivirus solutions.

The analytics rule automatically identified the suspicious execution of `mshta.exe` and generated a **High severity alert**, allowing SOC analysts to investigate the potentially malicious payload.

---

## 📖 Attack Scenario

Attackers commonly use `mshta.exe` for Defense Evasion. Because it is a signed, native Windows execution tool, running scripts through it can bypass security controls that block unauthorized executables. In this scenario, `mshta.exe` was used to execute a local `.hta` file, which typically contains embedded scripts designed to establish a foothold, download additional payloads, or execute discovery commands.

Microsoft Sentinel detected this activity by monitoring process execution logs for the invocation of `mshta.exe` with command-line arguments pointing to script files.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Mshta Execution |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Defense Evasion |
| **Analytics Rule** | Mshta Execution |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected a suspicious `mshta.exe` process execution.

The specific command line observed was:
`"C:\Windows\system32\mshta.exe" "\\Vm1\C$\Users\Sia123\AppData\Local\Temp\Test.hta"`

The activity involved:

- 👤 **Account:** `WORKGROUP\Vm1$`
- 💻 **Computer:** `Vm1`

---

## Alert Workflow

```text
Attacker drops or points to an .hta payload
          │
          ▼
Executes mshta.exe with payload path
(Defense Evasion)
          │
          ▼
Malicious script runs within mshta process
          │
          ▼
Process execution logged by OS
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
          │
          ▼
High Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 215920" src="https://github.com/user-attachments/assets/85da239d-0a7c-413e-9b81-d8f4a67c91f5" />


---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 28 |
| **Incident Name** | Mshta Execution |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 4 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 28 based on the Near Real-Time (NRT) detection alerts from Microsoft Sentinel. 

The incident grouped 4 active alerts related to Mshta Execution into a single workspace, indicating multiple triggers or repeated attempts to execute the payload.

---

## 📸 Incident Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 220000" src="https://github.com/user-attachments/assets/514aacbb-64e9-4162-8f4a-fa9edf6ea5ef" />


---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `WORKGROUP\Vm1$`
- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `"C:\Windows\system32\mshta.exe" "\\Vm1\C$\Users\Sia123\AppData\Loc...`

This allows analysts to quickly understand the execution chain on the affected endpoint and the context of the system account used.

---



# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `WORKGROUP\Vm1$` |
| **Device** | `Vm1` |
| **Process** | `mshta.exe` |

The graph allows the SOC analyst to visually pivot between the user, the host, and the executed process during the investigation.

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
| **User** | `WORKGROUP\Vm1$` |

---

## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 220021" src="https://github.com/user-attachments/assets/8cd1f784-ca3d-4efc-a3db-442d409218e9" />


---

## 📸 Impacted User

<img width="1920" height="1020" alt="Screenshot 2026-08-04 220028" src="https://github.com/user-attachments/assets/46361a7e-a7ff-463d-8c06-5f415b370957" />


---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious process execution as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `WORKGROUP\Vm1$` |
| **Computer** | `Vm1` |
| **Time Generated** | Jul 24, 2026 5:57:42 PM |
| **Command Line** | `"C:\Windows\system32\mshta.exe" "\\Vm1\C$\Users\Sia123\AppData\Local\Temp\Test.hta"` |

---

## 📸 Evidence & Response

<img width="1920" height="1020" alt="Screenshot 2026-08-04 220035" src="https://github.com/user-attachments/assets/1f5ed5e6-16ba-424d-bed9-a6a5f7fc109e" />


---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 4 Alerts for 'Mshta Execution' were automatically correlated to incident 28.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---



# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Isolate and retrieve the `Test.hta` file from `\\Vm1\C$\Users\Sia123\AppData\Local\Temp\` to analyze its embedded scripts (e.g., VBScript or JavaScript) and determine its true intent.
- ⚙️ Identify the parent process that invoked `mshta.exe` to uncover the initial access or delivery vector (e.g., a phishing document, a scheduled task, or another malicious script).
- 👤 Investigate the context of the `WORKGROUP\Vm1$` account being used, which may indicate systemic or elevated execution on the host.
- 🌐 Monitor `Vm1` for subsequent suspicious network connections (C2 traffic) or child processes spawned by `mshta.exe` (like `cmd.exe` or `powershell.exe`).
- 🚨 Isolate the affected endpoint (`Vm1`) if the `.hta` payload is confirmed malicious to prevent lateral movement or further malware staging.

---

# 🎯 Security Impact

Using `mshta.exe` is a prominent defense evasion tactic designed to hide malicious activity within a trusted Microsoft process.

Detecting this behavior allows SOC analysts to intercept an attack that might otherwise bypass file-based antivirus signatures or AppLocker restrictions.

If successful and left undetected, this execution could lead to:

- 🥷 Defense Evasion and successful payload execution
- 📥 Download and execution of secondary malware (e.g., Ransomware, RATs)
- 📡 Establishing Command and Control (C2) Communication
- 🛡️ Establishing Persistence via startup folders or registry keys

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Pass-the-Hash Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a potential **Pass-the-Hash (PtH)** attack. Pass-the-Hash is a lateral movement technique where an attacker uses a captured NTLM hash to authenticate to a remote server or service without needing the user's plaintext password.

The analytics rule automatically identified anomalous NTLM authentication activity (specifically a Network Logon - Type 3) originating from a potentially compromised endpoint and generated a **High severity alert**. This allows SOC analysts to investigate unauthorized lateral movement, particularly toward critical infrastructure like Domain Controllers.

---

## 📖 Attack Scenario

After successfully dumping credentials on a compromised machine (e.g., using Mimikatz to extract NTLM hashes from memory), the attacker bypasses standard authentication. They inject the stolen hash of a highly privileged account into their current session and attempt to access a remote system.

In this scenario, Microsoft Sentinel detected the attacker using the stolen hash of a privileged account (`ROOT\SecManager`) to perform a network logon (Logon Type 3) using the NTLM authentication package against the Domain Controller (`DC.root.project`) from the source IP `10.0.0.4`.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Pass-the-Hash Detection |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Lateral Movement |
| **Analytics Rule** | Pass-the-Hash Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected authentication patterns indicative of a Pass-the-Hash lateral movement attempt.

The query results confirmed a Network Logon via NTLM. The activity involved:

- 👤 **Account:** `ROOT\SecManager`
- 💻 **Computer:** `DC.root.project`
- 🌐 **IP Address:** `10.0.0.4`
- 🔑 **Authentication Package:** `NTLM`
- ⚙️ **Logon Type:** `3`

---

## Alert Workflow

```text
Attacker dumps NTLM hash from initial host
          │
          ▼
Injects hash into session (Pass-the-Hash)
(Lateral Movement)
          │
          ▼
Initiates Network Logon (Type 3) via NTLM
          │
          ▼
Authentication request hits Domain Controller
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
          │
          ▼
High Severity Alert Generated
          │
          ▼
Microsoft Defender Incident Created
```

---

## 📸 Alert Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 184040" src="https://github.com/user-attachments/assets/dcaae91c-2a10-45ee-a554-c2ed05626434" />

---

# 🚔 Incident Created

## Incident Summary

| Property | Value |
|----------|-------|
| **Incident ID** | 159 |
| **Incident Name** | Pass-the-Hash Detection |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 159 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the compromised source IP, the targeted Domain Controller, and the exploited administrative account.

---

## 📸 Incident Overview

<img width="1920" height="1020" alt="Screenshot 2026-08-04 183816" src="https://github.com/user-attachments/assets/b906209c-f563-4a04-9e8a-c1332d6268af" />


---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\SecManager`
- 💻 **Device:** `DC.root.project`
- 🌐 **IP Address:** `10.0.0.4`

This allows analysts to quickly map the trajectory of the lateral movement from the source IP to the targeted asset.

---


# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\SecManager` |
| **Device** | `DC.root.project` |
| **IP Address** | `10.0.0.4` |

The graph allows the SOC analyst to visually pivot between the compromised identity, the source of the attack, and the targeted Domain Controller.

---



# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` (Displayed as `DC`) |
| **Risk Level** | None |
| **Exposure Level** | Low |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\SecManager` |

---

## 📸 Impacted Device

<img width="1920" height="1020" alt="Screenshot 2026-08-04 183902" src="https://github.com/user-attachments/assets/191154e0-98db-4ec9-a42c-3524918e814e" />


---

## 📸 Impacted User

<img width="1920" height="1020" alt="Screenshot 2026-08-04 183910" src="https://github.com/user-attachments/assets/5005ed15-0060-408e-9cfb-c66c6a0df491" />


---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious IP address and logon event as part of the evidence.

The query results provided important forensic information regarding the authentication context:

| Property | Value |
|----------|-------|
| **Entity Type** | IP Address |
| **Verdict** | Suspicious |
| **Time Generated** | Aug 1, 2026 6:57:38 PM |
| **Account** | `ROOT\SecManager` |
| **Computer** | `DC.root.project` |
| **IP Address** | `10.0.0.4` |
| **Logon Type** | `3` (Network) |
| **Auth Package** | `NTLM` |

---

## 📸 Evidence & Response

<img width="1920" height="1020" alt="Screenshot 2026-08-04 183921" src="https://github.com/user-attachments/assets/50df12d5-2a5f-422a-b572-8e8e34235733" />


---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Pass-the-Hash Detection' was automatically correlated to incident 159 at Aug 1, 2026 7:00 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---



# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the source IP address (`10.0.0.4`). Determine what endpoint this belongs to (e.g., `Vm1`) and if it is an authorized administrative jump box.
- ⚙️ Review preceding alerts on the source endpoint (`10.0.0.4`) for signs of credential dumping (e.g., Mimikatz, LSASS memory access, Log Cleared).
- 👤 Confirm if the `ROOT\SecManager` user actively initiated a legitimate network session using NTLM at that exact time. 
- 🌐 Monitor `DC.root.project` for post-exploitation actions taken by `ROOT\SecManager` immediately following the successful logon (e.g., DCSync, adding new users, modifying group policies).
- 🚨 Isolate the source endpoint (`10.0.0.4`) to cut off the attacker's foothold.
- 🔑 Immediately rotate the password for the `ROOT\SecManager` account (and any other privileged accounts active on the compromised endpoint), as changing the password invalidates the stolen NTLM hash.

---

# 🎯 Security Impact

Pass-the-Hash is a critical lateral movement technique that allows attackers to traverse a network and access resources exactly as the compromised user would, without ever needing to crack the password.

Detecting this behavior allows SOC analysts to identify and stop lateral movement toward Tier 0 assets (like Domain Controllers).

If successful and left undetected, this execution could lead to:

- 🔄 Lateral Movement to Domain Controllers and high-value servers
- ⬆️ Complete Privilege Escalation (if a Domain Admin hash is passed)
- 🎫 Enabling further attacks like DCSync to extract all Active Directory hashes
- 🏢 Complete network and domain compromise

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Network Discovery Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the execution of commands aimed at mapping internal network topologies and connections. Network discovery is a reconnaissance technique used by attackers to understand the environment they have compromised.

The analytics rule automatically identified the execution of native Windows network utilities and generated a **Medium severity alert**. This allows SOC analysts to investigate potential lateral movement preparation.

---

## 📖 Attack Scenario

After gaining initial access to a host, attackers lack knowledge of the surrounding network. To find valuable targets (like Domain Controllers, file shares, or database servers), they frequently use built-in, "Living off the Land" binaries (LOLBins) such as `ipconfig.exe` or `ping.exe`. Because these are standard administrative tools, their execution often blends in with normal system activity.

Microsoft Sentinel detected this reconnaissance phase by monitoring process execution logs for specific commands and arguments that are highly indicative of network mapping behavior.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | network discovery |
| **Severity** | Medium |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Discovery |
| **Analytics Rule** | network discovery |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected the execution of commands aimed at mapping internal network topologies and connections.

The specific command line observed in the query results was:
`"C:\Windows\system32\PING.EXE" 10.0.0.4`

The activity involved:

- 👤 **Account:** `ROOT\SecManager`
- 💻 **Computer:** `Vm1.root.project`

---

## Alert Workflow

```text
Attacker gains access to endpoint
          │
          ▼
Executes ipconfig / ping commands
(Discovery / Network Reconnaissance)
          │
          ▼
Process execution logged by OS
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
| **Incident ID** | 96 |
| **Incident Name** | network discovery |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 2 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 96 based on the Near Real-Time (NRT) detection alerts from Microsoft Sentinel. 

The incident successfully grouped 2 active alerts related to network discovery into a single investigation workspace.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\SecManager`
- 💻 **Device:** `Vm1.root.project`
- ⚙️ **Process:** 2 Processes identified

This allows analysts to quickly understand the execution chain on the affected endpoint and the context of the user account.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the detailed entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\SecManager` |
| **Device** | `Vm1.root.project` |
| **Process 1** | `"C:\Windows\system32\ipconfig.exe"` |
| **Process 2** | `"C:\Windows\system32\PING.EXE" 10.0.0.4` |

The graph highlights that the user sequentially executed IP configuration checks followed by a targeted ping to `10.0.0.4`.

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

Microsoft Defender identified two suspicious process executions as part of the evidence.

The query results provided important forensic information regarding the event timeline:

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `ROOT\SecManager` |
| **Computer** | `Vm1.root.project` |
| **Time Generated** | Jul 31, 2026 6:25:24 PM |
| **Command Line** | `"C:\Windows\system32\PING.EXE" 10.0.0.4` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 2 Alerts for 'network discovery' were automatically correlated to the incident.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify with the user (`ROOT\SecManager`) if they were actively troubleshooting network connectivity to `10.0.0.4` during the timeframe.
- ⚙️ Check the parent processes of `ipconfig.exe` and `ping.exe`. If they were spawned by an interactive command prompt (`cmd.exe`), it might be administrative action; if spawned by a script (`powershell.exe`, `wscript.exe`) or an unusual binary, it is highly suspicious.
- 🌐 Monitor `Vm1.root.project` for subsequent connections to `10.0.0.4` over protocols like SMB (445), RDP (3389), or SSH (22), which would indicate an attempt to move laterally.
- 🔍 Look for other reconnaissance commands executed by `ROOT\SecManager` around the same time, such as `netstat`, `arp -a`, `net use`, or `nltest`.

---

# 🎯 Security Impact

While network discovery commands are not inherently destructive, they are a critical precursor to lateral movement and privilege escalation. 

Detecting this behavior allows SOC analysts to identify unauthorized access early in the attack lifecycle.

If this reconnaissance was malicious and left uninvestigated, it could lead to:

- 🎯 Identification of high-value targets (e.g., Domain Controllers, databases)
- 🔄 Subsequent Lateral Movement to internal subnets
- 🔑 Focused credential dumping against discovered critical assets

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Password Spray Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a potential **Password Spray** attack. A password spray is a type of brute-force attack where an attacker attempts to access a large number of accounts (usernames) with a few commonly used passwords, avoiding standard account lockout policies that trigger after multiple failed attempts on a single account.

The analytics rule automatically identified multiple failed authentication attempts targeting different accounts originating from a single IP address. It generated a **High severity alert**, allowing SOC analysts to investigate the source of the authentication attempts and determine if any accounts were successfully compromised.

---

## 📖 Attack Scenario

To bypass traditional brute-force protections (which lock an account after 3-5 bad attempts), attackers "spray" one or two common passwords (e.g., "Welcome123!", "Summer2026") across hundreds of known usernames. 

Microsoft Sentinel detected this activity by monitoring authentication logs and correlating multiple failed login events (`FailedUsers: 3`, `FailedAttempts: 4`) against multiple target accounts (`\TEST`, `\ADMINISTRATOR`, `\ADMIN`) coming from the exact same external source IP (`103.176.46.208`) within a short timeframe (approximately 3 minutes).

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Password Spray Detection |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Credential Access |
| **Analytics Rule** | Password Spray Detection |

---

## Alert Description

The alert was triggered based on the rule definition: "generate alert if passowrd spary is detected for multiple accounts from single ip address".

The query results confirmed multiple failed attempts. The activity involved:

- 🌐 **Source IP Address:** `103.176.46.208`
- 👤 **Targeted Accounts:** `["\\TEST", "\\ADMINISTRATOR", "\\ADMIN"]`
- 💻 **Computer:** `Vm1.root.project`

---

## Alert Workflow

```text
Attacker acquires a list of valid usernames
          │
          ▼
Attempts login across many accounts with one password
(Credential Access - Password Spraying)
          │
          ▼
Authentication logs record multiple failed logins
from a single IP address
          │
          ▼
Microsoft Sentinel Scheduled Analytics Rule
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
| **Incident ID** | 88 |
| **Incident Name** | Password Spray Detection |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 88 based on the scheduled detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the malicious IP address and ensure that none of the targeted administrative or test accounts were successfully breached.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 🌐 **IP Address:** `103.176.46.208`
- 👤 **Targeted Users:** `["\\TEST", "\\ADMINISTRATOR", "\\ADMIN"]`

This allows analysts to clearly see that a single external entity is fanning out attacks against a specific group of user accounts.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **IP Address** | `103.176.46.208` |
| **User Group** | `["\\TEST", "\\ADMINISTRATOR", "\\ADMIN"]` |

The graph allows the SOC analyst to visually pivot between the source of the attack and the identities being actively targeted.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## User

| Property | Value |
|----------|-------|
| **User** | `["\\TEST", "\\ADMINISTRATOR", "\\ADMIN"]` |

*(Note: Device impact was not explicitly mapped as an asset in the incident interface, though `Vm1.root.project` was identified in the raw logs as the targeted computer).*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious IP address acting as the source of the attacks as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context:

| Property | Value |
|----------|-------|
| **Entity Type** | IP Address |
| **Verdict** | Suspicious |
| **IP Address** | `103.176.46.208` |
| **First Attempt** | Jul 30, 2026 4:52:07 PM |
| **Last Attempt** | Jul 30, 2026 4:55:55 PM |
| **Failed Users** | 3 |
| **Failed Attempts** | 4 |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Password Spray Detection' was automatically correlated to incident 88 at Jul 30, 2026 5:02 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Analyze the source IP address (`103.176.46.208`) using Threat Intelligence sources (e.g., VirusTotal, AbuseIPDB) to determine if it is a known malicious node, VPN, or Tor exit node.
- 🌐 Block the malicious IP address (`103.176.46.208`) at the perimeter firewall or via Conditional Access policies.
- 🔐 **CRITICAL:** Query authentication logs (Event ID 4624) to determine if there were any *successful* logins from `103.176.46.208` for the targeted accounts (`\TEST`, `\ADMINISTRATOR`, `\ADMIN`) or any other accounts in the environment.
- 👤 Verify if the targeted accounts are protected by Multi-Factor Authentication (MFA). If an attacker successfully guessed a password, MFA would act as the next line of defense.
- ⚙️ Force a password reset for any account that shows suspicious successful authentication following the spray.
- 🔍 Look for impossible travel alerts associated with the targeted users, which might corroborate compromised credentials.

---

# 🎯 Security Impact

Password spraying is a highly effective credential access technique used by attackers to gain an initial foothold or escalate privileges without triggering noisy account lockouts.

Detecting this behavior allows SOC analysts to block the attacking infrastructure and verify the integrity of user credentials.

If successful and left undetected, this attack could lead to:

- 🔑 Initial Access via compromised credentials
- ⬆️ Immediate Privilege Escalation (e.g., if the `\ADMINISTRATOR` account was successfully breached)
- 🏢 Unrestricted access to sensitive data and systems
- 📤 Data Exfiltration and Ransomware deployment

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)


---

# 🚨 PowerShell Download Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a **PowerShell Download** execution. Attackers frequently use built-in Windows tools like PowerShell to fetch malicious payloads from external command and control (C2) servers.

The analytics rule automatically identified the suspicious PowerShell command parameters used to initiate a web request and generated a **High severity alert**, allowing SOC analysts to investigate the potential command and control (C2) activity and payload delivery.

---

## 📖 Attack Scenario

"Living off the land" (LOTL) techniques often leverage PowerShell's `Invoke-WebRequest` cmdlet (or aliases like `iwr`, `wget`) to download second-stage malware directly to the file system. Instead of dropping a bulky executable, the attacker executes a lightweight command that reaches out to an external server to fetch the payload.

Microsoft Sentinel detected this activity by monitoring process execution logs for specific PowerShell cmdlets and arguments designed to pull a remote file (`https://example.com`) and save it locally (`C:\Temp\test.html`).

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | PowerShell Download |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Command and Control |
| **Analytics Rule** | PowerShell Download |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected PowerShell execution used specifically to download files from remote locations.

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
Executes PowerShell to download file
(Command and Control / Ingress Tool Transfer)
          │
          ▼
Network request to external URL
          │
          ▼
Payload downloaded to local disk
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
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
| **Incident ID** | 58 |
| **Incident Name** | PowerShell Download |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 58 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with the necessary workspace to investigate the command execution, the target URL, and the impacted endpoint.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `Vm1\Sia123`
- 💻 **Device:** `Vm1`
- ⚙️ **Process:** `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Comman...`

This allows analysts to quickly understand the execution chain on the affected endpoint and the account that ran the command.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `Vm1\Sia123` |
| **Device** | `Vm1` |
| **Process** | `powershell.exe` |

The graph allows the SOC analyst to visually pivot between the host, the executing user, and the process during the investigation.

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
| **Command Line** | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "Invoke-WebRequest https://example.com -OutFile C:\Temp\test.html"` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'PowerShell Download' was automatically correlated to incident 58.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the legitimacy of the target URL (`https://example.com`).
- 🌐 Review network and proxy logs to determine if the connection to the URL was successful and if data was actually downloaded.
- 📁 Inspect the file system for the presence of the downloaded file (`C:\Temp\test.html`) and analyze it for malicious content or secondary scripts.
- 👤 Confirm if the user `Vm1\Sia123` authorized this activity.
- ⚙️ Identify the parent process that spawned the PowerShell instance to uncover the initial access vector (e.g., cmd.exe, a malicious document, or an RDP session).
- 🔍 Search for subsequent execution of the downloaded file.
- 🚨 Isolate the affected endpoint (`Vm1`) if malicious payload execution is confirmed.

---

# 🎯 Security Impact

A PowerShell download command indicates that an attacker (or unauthorized software) is attempting to pull additional tools or payloads into the environment. 

Detecting this behavior allows SOC analysts to intercept an attack in its early stages before the primary payload is executed.

If successful, this attack chain could lead to:

- 📥 Execution of Malware (Ransomware, RATs, Info Stealers)
- 📡 Establishing Command and Control (C2) Communication
- 🔄 Lateral Movement preparation
- 🛡️ Establishing Persistence within the environment

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 PsExec Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the execution of **PsExec**. PsExec is a legitimate Microsoft Sysinternals utility designed for remote system administration. However, it is frequently abused by attackers to execute commands, spawn interactive command prompts, or deploy malware (such as ransomware) on remote systems across a compromised network.

The analytics rule automatically identified the creation of the PsExec service and its associated process execution, generating a **High severity alert**. This allows SOC analysts to investigate potential lateral movement or remote code execution.

---

## 📖 Attack Scenario

After compromising an account with sufficient privileges (like a local or domain administrator), attackers need a way to execute commands on other machines in the network to spread their access. PsExec allows them to do this by connecting to the hidden `ADMIN$` share of a target machine, uploading a service executable (`PSEXESVC.exe`), and interacting with it over named pipes.

Microsoft Sentinel detected this activity by monitoring endpoint process creation logs (Event ID 4688) for the explicit execution of `psexec.exe`, indicating an attempt to initiate a remote session.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | PsExec Detection |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Lateral Movement |
| **Analytics Rule** | PsExec Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected PsExec service creation and process execution.

The query results confirmed the execution via Windows Event Logs. The activity involved:

- 👤 **Account:** `ROOT\SecManager`
- 💻 **Computer:** `Vm1.root.project`
- ⚙️ **Process:** `PsExec.exe`
- 📋 **Event ID:** `4688` (Process Creation)

---

## Alert Workflow

```text
Attacker acquires privileged credentials
          │
          ▼
Executes PsExec targeting a remote host
(Lateral Movement / Remote Execution)
          │
          ▼
PsExec connects to ADMIN$ share & creates service
          │
          ▼
Windows generates Event ID 4688 (Process Creation)
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
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
| **Incident ID** | 85 |
| **Incident Name** | PsExec Detection |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 85 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the remote execution attempt, the executing user, and the targeted endpoint.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\SecManager`
- 💻 **Device:** `Vm1.root.project`
- ⚙️ **Process:** `psexec`

This allows analysts to quickly understand the execution context and the administrative account utilized to run the remote tool.

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
| **Process** | `psexec` |

The graph allows the SOC analyst to visually pivot between the user identity, the host where the process was spawned, and the PsExec process itself.

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

The query results provided important forensic information regarding the event timeline:

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Account** | `ROOT\SecManager` |
| **Computer** | `Vm1.root.project` |
| **Time Generated** | Jul 29, 2026 10:51:29 PM |
| **Process** | `PsExec.exe` |
| **Event ID** | `4688` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'PsExec Detection' was automatically correlated to incident 85 at Jul 29, 2026 10:54 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify with the user `ROOT\SecManager` (or the IT operations team) if PsExec is an approved administrative tool and if they were actively using it on `Vm1.root.project` at the time of the alert.
- ⚙️ Identify the specific commands passed to PsExec via the command line logs. Attackers often use flags like `-s` (run as SYSTEM) and `-accepteula` to suppress GUI prompts.
- 🌐 Identify the *target* machine. Look for Event ID 7045 (Service Creation) for `PSEXESVC` on other hosts in the network originating from `Vm1.root.project`.
- 🔍 Look for suspicious child processes spawned by PsExec on the target machine (e.g., `cmd.exe`, `powershell.exe`, or unknown binaries).
- 🚨 Isolate the source endpoint (`Vm1.root.project`) if the PsExec activity is deemed malicious, as it is acting as a jump point.
- 🔑 Assume the `ROOT\SecManager` credentials have been compromised and initiate a password rotation.

---

# 🎯 Security Impact

Because it requires administrative privileges to function, the successful execution of PsExec is a strong indicator that an attacker has already bypassed initial defenses and escalated their privileges.

Detecting this behavior allows SOC analysts to interrupt lateral movement before an attacker can deploy widespread destructive payloads.

If successful and left undetected, this execution could lead to:

- 🔄 Widespread Lateral Movement across the domain
- ⬆️ Remote execution of commands as NT AUTHORITY\SYSTEM
- 💣 Mass deployment of Ransomware to multiple endpoints simultaneously
- 📤 Coordinated Data Exfiltration

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Scheduled Task Created Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the creation of a new Windows Scheduled Task on an endpoint.

The analytics rule automatically identified Event ID 4698 ("A scheduled task was created") and generated a **Medium severity alert**. This allows SOC analysts to investigate potential persistence mechanisms or privilege escalation attempts established by an attacker.

---

## 📖 Attack Scenario

Attackers frequently abuse the Windows Task Scheduler to maintain access to a compromised system across reboots (Persistence) or to execute malicious payloads under a higher-privileged context, such as `NT AUTHORITY\SYSTEM` (Privilege Escalation).

By scheduling a task to run a downloaded binary or an encoded PowerShell script at specific times, upon user logon, or on system startup, the attacker ensures their code continues to run without requiring active interaction.

Microsoft Sentinel detected this activity by monitoring the Windows Security Event Log specifically for Event ID 4698, which is logged whenever a new task is registered with the Task Scheduler service.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | scheduled task created |
| **Severity** | Medium |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Privilege Escalation, Persistence |
| **Analytics Rule** | scheduled task created |

---

## Alert Description

The alert was triggered because it "triggers an alert whenever a scheduled task was created".

The specific event generated was Event ID `4698 - A scheduled task was created`.

The activity involved:

- 💻 **Computer:** `Vm1.root.project`
- ⚙️ **Event ID:** `4698`

---

## Alert Workflow

```text
Attacker gains access to host
          │
          ▼
Uses schtasks.exe or PowerShell to create a task
(Persistence / Privilege Escalation)
          │
          ▼
Task Scheduler registers the new task
          │
          ▼
Windows generates Event ID 4698
          │
          ▼
Microsoft Sentinel Scheduled Analytics Rule
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
| **Incident ID** | 65 |
| **Incident Name** | scheduled task created |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 65 based on the scheduled detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the creation of the task and determine its intended execution path on the impacted endpoint.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 💻 **Device:** `Vm1.root.project`
- ⚙️ **Event/Process Entity:** `4698`

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
| **Device** | `Vm1.root.project` |
| **Event** | `4698` |

The graph allows the SOC analyst to visually pivot between the host and the scheduled task creation event during the investigation.

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

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious process execution (represented by the PID associated with the event) as part of the evidence.

The query results provided important forensic information regarding the event timeline and execution context.

| Property | Value |
|----------|-------|
| **Entity Type** | Process (identified via Event ID 4698) |
| **Verdict** | Suspicious |
| **Computer** | `Vm1.root.project` |
| **Time Generated** | Jul 28, 2026 9:57:18 PM |
| **Activity** | `4698 - A scheduled task was created.` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'scheduled task created' was automatically correlated to incident 65 at Jul 28, 2026 10:05 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Extract the raw XML data from Event ID 4698 in Sentinel or the local Event Viewer. This will reveal the critical details: the `TaskName`, the executable or script it is configured to run (`Command`), the arguments (`Arguments`), and the account it runs under (`UserId`).
- 👤 Identify the user account that *created* the task to determine if it was a legitimate administrator or a compromised account.
- ⚙️ Analyze the configured `Command` path. If it points to `cmd.exe`, `powershell.exe`, `mshta.exe`, or a binary in a temporary directory (e.g., `C:\Temp\`, `AppData\Local\Temp`), it is highly suspicious.
- 🌐 Check network logs for any unusual outbound connections originating from the execution of the scheduled task.
- 🚨 Isolate the affected endpoint (`Vm1.root.project`) if the scheduled task is confirmed malicious.
- 🛡️ Delete the malicious scheduled task and locate/remove the underlying payload it was configured to execute.

---

# 🎯 Security Impact

Scheduled tasks are one of the most common and reliable methods for attackers to establish a permanent foothold on a system.

Detecting this behavior allows SOC analysts to identify and remove attacker persistence before they can re-establish access after a reboot or connection loss.

If successful and left undetected, this execution could lead to:

- 🛡️ Long-term Persistence (Surviving reboots and logoffs)
- ⬆️ Privilege Escalation (if the task is set to run as SYSTEM)
- 📡 Continuous Command and Control (C2) beaconing
- 📥 Execution of secondary malware payloads on a schedule

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)


---
# 🚨 SMB Admin Share Access Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying access to administrative SMB shares (such as `ADMIN$`, `C$`, `IPC$`). 

The analytics rule automatically identified a suspicious connection from an endpoint to the `IPC$` share on a Domain Controller and generated a **High severity alert**. This allows SOC analysts to investigate potential lateral movement, remote execution, or reconnaissance activities.

---

## 📖 Attack Scenario

Administrative shares are hidden network shares created by Windows by default. They are intended for remote administration, but attackers frequently abuse them after compromising a privileged account. 

Accessing the `IPC$` (Inter-Process Communication) share specifically is often a precursor to lateral movement tools like PsExec or WMI, as it is used to establish a named pipe connection before transferring payloads or issuing commands to other administrative shares (like `ADMIN$`). 

Microsoft Sentinel detected this activity by monitoring network share access logs (Event ID 5140) directed at critical infrastructure (the Domain Controller).

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | SMB Admin Share Access |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Lateral Movement |
| **Analytics Rule** | SMB Admin Share Access |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected access to administrative SMB shares for lateral movement.

The query results confirmed a connection to the `IPC$` share. The activity involved:

- 👤 **Account:** `ROOT\VM1$`
- 💻 **Target Computer:** `DC.root.project`
- 🌐 **Source IP Address:** `10.0.0.4`
- 📁 **Share Name:** `\\*\IPC$`

---

## Alert Workflow

```text
Attacker compromises host and acquires credentials
          │
          ▼
Initiates SMB connection to target host
(Lateral Movement / Remote Admin Tools)
          │
          ▼
Connects to hidden administrative share (IPC$)
          │
          ▼
Target host logs network share access (Event ID 5140)
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
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
| **Incident ID** | 191 |
| **Incident Name** | SMB Admin Share Access |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 191 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the compromised source IP, the targeted Domain Controller, and the identity used to facilitate the SMB connection.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\VM1$`
- 💻 **Device:** `DC.root.project`
- 🌐 **IP Address:** `10.0.0.4`

This allows analysts to quickly map the trajectory of the lateral movement from the source endpoint to the Domain Controller.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\VM1$` |
| **Device** | `DC.root.project` |
| **IP Address** | `10.0.0.4` |

The graph allows the SOC analyst to visually pivot between the source of the attack, the identity utilized, and the targeted asset.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\VM1$` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified a suspicious IP address and associated share access as part of the evidence.

The query results provided important forensic information regarding the event context:

| Property | Value |
|----------|-------|
| **Entity Type** | IP Address |
| **Verdict** | Suspicious |
| **Time Generated** | Aug 1, 2026 7:03:48 PM |
| **Account** | `ROOT\VM1$` |
| **Computer** | `DC.root.project` |
| **IP Address** | `10.0.0.4` |
| **Share Name** | `\\*\IPC$` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'SMB Admin Share Access' was automatically correlated to incident 191 at Aug 1, 2026 7:07 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the source IP address (`10.0.0.4`). Determine if this endpoint (likely `Vm1`) is supposed to be initiating administrative connections to the Domain Controller.
- 👤 Analyze the use of the machine account `ROOT\VM1$`. While machine accounts do legitimately communicate with DCs, accessing the `IPC$` share followed by other administrative actions (like Service Creation or scheduled tasks) is highly suspicious and indicates the host `Vm1` is compromised and the attacker has SYSTEM level privileges.
- 🌐 Monitor `DC.root.project` for subsequent connections from `10.0.0.4` targeting other administrative shares like `ADMIN$` or `C$`.
- ⚙️ Review Event ID 7045 (Service Creation) or Event ID 4698 (Scheduled Task Creation) on the Domain Controller originating from the `VM1$` account immediately following this SMB access.
- 🚨 Isolate the source endpoint (`10.0.0.4` / `Vm1`) to halt the lateral movement attempt.

---

# 🎯 Security Impact

Accessing administrative SMB shares is a critical step in most lateral movement playbooks. It is the necessary bridge to execute remote commands or transfer payloads across the network.

Detecting this behavior allows SOC analysts to intercept an attacker traversing the network before they can fully compromise a new, high-value asset.

If successful and left undetected, this access could lead to:

- 🔄 Remote Code Execution (via PsExec, WMI, or Services)
- 📥 Malicious Payload Deployment (e.g., dropping Ransomware binaries)
- 🏢 Compromise of the Domain Controller and Active Directory
- 📤 Data staging and exfiltration

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 User Added to Domain Admins Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a critical Active Directory modification: **a user account being added to the Domain Admins security group**. 

The analytics rule automatically identified Event ID 4728 and generated a **High severity alert**. This allows SOC analysts to immediately investigate potential unauthorized privilege escalation or the creation of a persistent backdoor by an attacker.

---

## 📖 Attack Scenario

After successfully compromising a domain environment, attackers often seek to ensure long-term access (Persistence) and maximum control (Privilege Escalation). One of the most direct ways to achieve this is by adding a standard user account—either an existing compromised account or a newly created "rogue" account—to a highly privileged group like "Domain Admins" or "Enterprise Admins".

Microsoft Sentinel detected this activity by monitoring the Domain Controller's Security Event logs for Event ID 4728, which triggers specifically when a member is added to a security-enabled global group.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | User Added to Domain Admins |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Persistence |
| **Analytics Rule** | User Added to Domain Admins |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected when a user account is added to the Domain Admins security group. This may indicate privilege escalation or unauthorized administrative access.

The specific event generated was Event ID `4728 - A member was added to a security-enabled global group`.

The activity involved:

- 👤 **Subject Account (The Actor):** `IA123`
- 👤 **Added User (The Target):** `CN=Soc Analyst L3,CN=Users,DC=root,DC=project`
- 🛡️ **Group Name:** `Domain Admins`
- 💻 **Computer:** `DC.root.project`

---

## Alert Workflow

```text
Attacker gains administrative access to AD
          │
          ▼
Executes command to modify group membership
(Persistence / Privilege Escalation)
          │
          ▼
"Soc Analyst L3" added to "Domain Admins"
          │
          ▼
Domain Controller logs Event ID 4728
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
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
| **Incident ID** | 73 |
| **Incident Name** | User Added to Domain Admins |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 73 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the actor (`IA123`) making the change, the Domain Controller where the change occurred, and the implications for the `Soc Analyst L3` account.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User (Actor):** `IA123`
- 💻 **Device:** `DC.root.project`

This allows analysts to clearly see which account executed the unauthorized change on the Domain Controller.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `IA123` |
| **Device** | `DC.root.project` |

The graph allows the SOC analyst to visually pivot between the identity that performed the action and the domain infrastructure.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `IA123` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender did not extract separate discrete evidence items (like IP addresses or file hashes) because the event is a native Active Directory configuration change.

However, the query results provided the critical forensic information:

| Property | Value |
|----------|-------|
| **Time Generated** | Jul 29, 2026 3:01:43 PM |
| **Activity** | `4728 - A member was added to a security-enabled global group.` |
| **Added User** | `CN=Soc Analyst L3,CN=Users,DC=root,DC=project` |
| **Computer** | `DC.root.project` |
| **Group Name** | `Domain Admins` |
| **Subject Account** | `IA123` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'User Added to Domain Admins' was automatically correlated to incident 73 at Jul 29, 2026 3:05 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify with identity management teams if there was an approved change request to grant Domain Admin rights to the `Soc Analyst L3` account.
- 👤 Investigate the `IA123` account (the actor). Was this account recently compromised? Did it suddenly elevate its own privileges to make this change?
- ⚙️ Review surrounding logs on `DC.root.project` for Event ID 4720 (User Created) to see if `Soc Analyst L3` was created just moments before being added to the group.
- 🌐 Monitor the network for immediate lateral movement or data access utilizing the newly empowered `Soc Analyst L3` account.
- 🚨 If the activity is unauthorized, immediately remove `Soc Analyst L3` from the Domain Admins group.
- 🔑 Force a password reset and revoke active sessions for both the actor (`IA123`) and the target account (`Soc Analyst L3`).

---

# 🎯 Security Impact

Unmonitored changes to the Domain Admins group represent one of the highest severity risks in a Windows domain environment. 

Detecting this behavior allows SOC analysts to sever an attacker's persistent, highest-level access before they can deploy widespread destructive actions.

If successful and left undetected, this execution could lead to:

- ⬆️ Complete Privilege Escalation (System-wide administrative rights)
- 🛡️ Indestructible Persistence (Attacker owns the identity infrastructure)
- 💣 Domain-wide Ransomware deployment capabilities
- 🎫 Disabling of security tools and creation of golden tickets

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 User Added to Local Administrators Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying a user being added to an administrative group. The analytics rule generated a **High severity alert**.

---

## 📖 Attack Scenario

Attackers may add users to admin groups to maintain persistence or escalate privileges within the environment. The rule explicitly "creates an alert whenever a user is added to admin grp or whenever a user is a made admin".

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | User Added to Local Administrators |
| **Severity** | High |
| **Status** | In progress |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Privilege Escalation, Persistence |

---

## Alert Description

The alert description states it "creates an alert whenever a user is added to admin grp or whenever a user is a made admin".

The query results confirmed an Activity ID of `4728 - A member was added to a security-enabled global group.`.

The activity involved:

- 👤 **Subject Account:** `ROOT\IA123`
- 👤 **Target Account:** `ROOT\Domain Admins`
- 💻 **Computer:** `DC.root.project`

---

## Alert Workflow

```text
Attacker executes command to modify group membership
          │
          ▼
User is added to an administrative group
          │
          ▼
Event ID 4728 is logged
          │
          ▼
Microsoft Sentinel Scheduled Analytics Rule
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
| **Incident ID** | 75 |
| **Incident Name** | User Added to Local Administrators |
| **Severity** | High |
| **Status** | Active |
| **Assigned To** | akashakash91744@gmail.com |
| **Active Alerts** | 1 |

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\Domain Admins`
- 💻 **Device:** `DC.root.project`

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\Domain Admins` |
| **Device** | `DC.root.project` |

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\Domain Admins` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

The query results provided the critical forensic information:

| Property | Value |
|----------|-------|
| **Time Generated** | Jul 29, 2026 3:01:43 PM |
| **Activity** | `4728 - A member was added to a security-enabled global group.` |
| **Target Account** | `ROOT\Domain Admins` |
| **Computer** | `DC.root.project` |
| **Subject Account** | `ROOT\IA123` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'User Added to Local Administrators' was automatically correlated to incident 75 at Jul 29, 2026 3:47 PM.
- 🤖 An 'Update Alert' activity was recorded at Jul 29, 2026 3:47 PM.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the legitimacy of the administrative action performed by the subject account.
- ⚙️ Review surrounding logs on the Domain Controller to see if the user addition aligns with approved change management.
- 🚨 Isolate accounts involved if the activity is deemed unauthorized.

---

# 🎯 Security Impact

Unauthorized additions to administrative groups present a severe risk of privilege escalation and persistence.

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 User Created Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the creation of a new user account. The analytics rule generated a **Medium severity alert**.

---

## 📖 Attack Scenario

Attackers often create new local or domain user accounts to establish persistence within a compromised environment. The rule explicitly "creates an alert whenever a new local user is created".

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | user created |
| **Severity** | Medium |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | Scheduled detection |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Persistence |

---

## Alert Description

The alert description states it "creates an alert whenever a new local user is created".

The query results confirmed an Activity ID of `4720 - A user account was created.`.

The activity involved:

- 👤 **Subject Account:** `ROOT\IA123`
- 👤 **Target Account:** `ROOT\sqlsvc`
- 💻 **Computer:** `DC.root.project`

---

## Alert Workflow

```text
Attacker executes command to create a new user account
          │
          ▼
New user account is created on the system
          │
          ▼
Event ID 4720 is logged
          │
          ▼
Microsoft Sentinel Scheduled Analytics Rule
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
| **Incident ID** | 74 |
| **Incident Name** | user created |
| **Severity** | Medium |
| **Status** | Active |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\sqlsvc`
- 💻 **Device:** `DC.root.project`

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\sqlsvc` |
| **Device** | `DC.root.project` |

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\sqlsvc` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

The query results provided the critical forensic information:

| Property | Value |
|----------|-------|
| **Time Generated** | Jul 29, 2026 3:17:05 PM |
| **Activity** | `4720 - A user account was created.` |
| **Target Account** | `ROOT\sqlsvc` |
| **Computer** | `DC.root.project` |
| **Subject Account** | `ROOT\IA123` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'user created' was automatically correlated to incident 74 at Jul 29, 2026 3:25 PM.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the legitimacy of the user creation action performed by the subject account.
- ⚙️ Review surrounding logs on the Domain Controller to see if the user addition aligns with approved change management.
- 🚨 Disable the new account and isolate related accounts if the activity is deemed unauthorized.

---

# 🎯 Security Impact

Unauthorized user creation presents a risk of persistence, allowing attackers to maintain access even if their initial entry point is remediated.

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 WMI Lateral Movement Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying potential **WMI (Windows Management Instrumentation) Lateral Movement**. Attackers frequently abuse WMI to execute commands and run processes remotely across systems in a network without needing to drop interactive shells.

The analytics rule automatically identified suspicious WMI process execution patterns and generated a **High severity alert**, allowing SOC analysts to investigate remote administrative execution and lateral movement.

---

## 📖 Attack Scenario

WMI is a powerful native Windows administration feature that allows scripts and management tools to interact with the operating system. Adversaries abuse this functionality by utilizing WMI command-line utilities (`wmic.exe`) or programmatic APIs to spawn processes on remote hosts (often spawning `WmiPrvSE.exe` with an `-Embedding` argument via `svchost.exe`). This allows them to execute payloads or perform reconnaissance stealthily.

Microsoft Sentinel detected this activity by monitoring process creation logs for WMI-related provider execution chains indicative of remote interaction.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | WMI Lateral Movement Detection |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Execution |
| **Analytics Rule** | WMI Lateral Movement Detection |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected WMI process execution patterns associated with lateral movement.

The specific query results observed were:
- **Time Generated:** `Aug 1, 2026 6:43:16 PM`
- **Account:** `ROOT\DC$`
- **Command Line:** `C:\Windows\system32\wbem\wmiprvse.exe -Embedding`
- **Computer:** `DC.root.project`
- **New Process Name:** `C:\Windows\system32\wbem\WmiPrvSE.exe`
- **Parent Process Name:** `C:\Windows\system32\svchost.exe`

---

## Alert Workflow

```text
Attacker initiates remote WMI connection
          │
          ▼
WMI Provider Host (WmiPrvSE.exe) spawned via svchost.exe
(Execution / Lateral Movement)
          │
          ▼
Remote command or process executed
          │
          ▼
Process creation logged by OS
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
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
| **Incident ID** | 126 |
| **Incident Name** | WMI Lateral Movement Detection |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 126 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the WMI activity on the Domain Controller.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\DC$`
- 💻 **Device:** `DC.root.project`

This allows analysts to quickly understand the connection between the system account and the Domain Controller.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `ROOT\DC$` |
| **Device** | `DC.root.project` |

The graph allows the SOC analyst to visually pivot between the device and account entities during the investigation.

---

## 📸 Investigation Graph

> *(Insert Investigation Graph Screenshot)*

---

# 💻 Impacted Assets

The incident identified the following impacted assets.

## Device

| Property | Value |
|----------|-------|
| **Device name** | `DC.root.project` |
| **Domain** | `root.project` |
| **Risk Level** | None |

---

## User

| Property | Value |
|----------|-------|
| **User** | `ROOT\DC$` |

---

## 📸 Impacted Device

> *(Insert Device Screenshot)*

---

## 📸 Impacted User

> *(Insert User Screenshot)*

---

# 🧪 Evidence & Response

Microsoft Defender identified process activity as part of the evidence.

The query results provided important forensic information regarding the execution context:

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **Computer** | `DC.root.project` |
| **Account** | `ROOT\DC$` |
| **Command Line** | `C:\Windows\system32\wbem\wmiprvse.exe -Embedding` |
| **Parent Process** | `C:\Windows\system32\svchost.exe` |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'WMI Lateral Movement Detection' was automatically correlated to incident 126 at Aug 1, 2026 6:46 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Determine the originating source machine that triggered the WMI call on `DC.root.project`. Review network connection logs (SMB, RPC, WinRM) hitting the DC at `Aug 1, 2026 6:43:16 PM`.
- ⚙️ Inspect WMI repository modifications or permanent event subscriptions, as attackers frequently use WMI for fileless persistence.
- 👤 Check if the account `ROOT\DC$` or any associated user account was leveraged from an external or lower-privileged host.
- 🔍 Look for secondary child processes spawned by `WmiPrvSE.exe` (such as `cmd.exe`, `powershell.exe`, or suspicious scripts) which indicate what command was executed remotely.
- 🚨 Isolate the source workstation if malicious remote execution is confirmed.

---

# 🎯 Security Impact

WMI lateral movement allows attackers to execute code across network boundaries using built-in administrative protocols, making it difficult to detect without specialized monitoring.

Detecting this behavior allows SOC analysts to intercept remote execution before payloads can execute fully in memory.

If successful and left undetected, this attack could lead to:

- 🔄 Unauthorized Remote Code Execution
- 🛡️ Fileless Persistence via WMI Event Consumers
- ⬆️ Further Privilege Escalation
- 🏢 Domain Compromise

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Active Directory Computer Enumeration Detected

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying active enumeration of computer objects within Active Directory. 

The analytics rule automatically identified suspicious PowerShell reconnaissance commands and generated a **Medium severity alert**, allowing SOC analysts to investigate potential domain discovery and reconnaissance activities.

---

## 📖 Attack Scenario

After gaining access to a domain environment, attackers frequently perform reconnaissance to map out the network structure, find active domain controllers, workstations, and servers. This is often done using built-in PowerShell Active Directory module cmdlets (such as `Get-AdComputer`) or tools like BloodHound/SharpHound to identify targets for lateral movement.

Microsoft Sentinel detected this activity by monitoring PowerShell execution logs for command-line arguments querying Active Directory computer objects using filters like `-Filter *`.

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | Active Directory Computer Enumeration Detected |
| **Severity** | Medium |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Discovery |
| **Analytics Rule** | Active Directory Computer Enumeration Detected |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected execution of PowerShell commands commonly used for Active Directory reconnaissance.

The specific command line observed was:
`"powershell.exe" & {Get-AdComputer -Filter *}`

The activity involved:

- 👤 **Account:** `ROOT\SecManager`
- 💻 **Computer:** `Vm1.root.project`

---

## Alert Workflow

```text
Attacker gains access to domain-joined host
          │
          ▼
Executes PowerShell AD enumeration command
(Discovery / Active Directory Reconnaissance)
          │
          ▼
PowerShell queries Active Directory for computer objects
          │
          ▼
Process execution logged by OS
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
| **Incident ID** | 219 |
| **Incident Name** | Active Directory Computer Enumeration Detected |
| **Severity** | Medium |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 1 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 219 based on the Near Real-Time (NRT) detection alert from Microsoft Sentinel. 

This incident provides the analyst with a centralized workspace to investigate the reconnaissance script execution, the user account involved, and the impacted endpoint.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `ROOT\SecManager`
- 💻 **Device:** `Vm1.root.project`
- ⚙️ **Process:** `"powershell.exe" & {Get-AdComputer -Filter *}`

This allows analysts to quickly understand the execution chain on the affected endpoint and the context of the user account.

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
| **Process** | `powershell.exe` |

The graph allows the SOC analyst to visually pivot between the user account, host, and the executed reconnaissance process during the investigation.

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
| **Exposure Level** | Low |

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

The evidence and response tab recorded the following details:

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **First Seen** | Aug 1, 2026 7:24 PM |
| **Impacted Assets** | `Vm1.root.project` |
| **Detection Origin** | Active Directory Computer Enumeration Detected |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 Alert 'Active Directory Computer Enumeration Detected' was automatically correlated to incident 219 at Aug 1, 2026 7:28 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify if the user `ROOT\SecManager` was performing authorized administrative domain auditing or asset discovery.
- ⚙️ Inspect the parent process of `powershell.exe` to see how the enumeration command was triggered (e.g., interactive prompt, scheduled task, or script execution).
- 🌐 Monitor `Vm1.root.project` for subsequent enumeration commands targeting user accounts (`Get-AdUser`), groups (`Get-AdGroup`), or organizational units.
- 🔍 Look for further lateral movement attempts originating from `Vm1.root.project` following the reconnaissance phase.
- 🚨 Isolate the endpoint if the activity is deemed unauthorized or part of a broader compromise.

---

# 🎯 Security Impact

Active Directory enumeration provides attackers with a roadmap of the enterprise network, helping them target valuable servers and administrative accounts.

Detecting this behavior allows SOC analysts to intercept attackers during the early discovery phase before they can execute targeted lateral movement.

If successful and left uninvestigated, this reconnaissance could lead to:

- 🎯 Identification of high-value internal targets (e.g., Domain Controllers, database servers)
- 🔄 Coordinated Lateral Movement across the internal network
- 🔑 Focused credential harvesting against discovered systems

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
# 🚨 Certutil Download Detection

## 🎯 Detection Overview

This detection demonstrates Microsoft Sentinel identifying the abuse of the native Windows administrative utility **Certutil.exe** to download malicious external files. 

The analytics rule automatically identified suspicious certutil command-line switches used for downloading payloads and generated a **High severity alert**, allowing SOC analysts to investigate command and control (C2) activity and unauthorized file staging.

---

## 📖 Attack Scenario

`Certutil.exe` is a built-in legitimate binary designed for managing Certificate Services. However, because it is trusted and signed by Microsoft, attackers frequently abuse its built-in URL caching and decoding capabilities (such as `-urlcache`, `-split`, or `-f`) to fetch malicious payloads from external web servers while evading application whitelisting and traditional endpoint defenses.

Microsoft Sentinel detected this activity by monitoring process execution logs for instances where `certutil.exe` was invoked with arguments pointing to external URLs (`https://example.com/test.txt`).

---

# 🚨 Alert Generated

## Alert Summary

| Property | Value |
|----------|-------|
| **Alert Name** | certutil download |
| **Severity** | High |
| **Status** | New |
| **Classification** | Not Set |
| **Detection Source** | NRT rules |
| **Service Source** | Microsoft Sentinel |
| **Categories** | Command and Control |
| **Analytics Rule** | certutil download |

---

## Alert Description

The alert was triggered after Microsoft Sentinel detected the abuse of the certutil.exe administrative tool to download malicious external files.

The specific command line observed in the query results was:
`"C:\Windows\system32\certutil.exe" -urlcache -split -f https://example.com test.txt`

The activity involved:

- 👤 **Account:** `Vm1\Sia123`
- 💻 **Computer:** `Vm1`

---

## Alert Workflow

```text
Attacker gains access to host
          │
          ▼
Executes certutil with URL cache parameters
(Command and Control / Ingress Tool Transfer)
          │
          ▼
Certutil reaches out to external URL and downloads file
          │
          ▼
Process execution logged by OS
          │
          ▼
Microsoft Sentinel NRT Analytics Rule
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
| **Incident ID** | 49 |
| **Incident Name** | certutil download |
| **Severity** | High |
| **Status** | Active |
| **Classification** | Unclassified |
| **Assigned To** | Unassigned |
| **Active Alerts** | 3 |
| **Created Automatically** | Yes |

---

## Incident Correlation

Microsoft Defender automatically created Incident 49 based on the Near Real-Time (NRT) detection alerts from Microsoft Sentinel. 

The incident successfully grouped 3 active alerts related to certutil download activity into a single investigation workspace.

---

## 📸 Incident Overview

> *(Insert Incident Overview Screenshot)*

---

# 🕸️ Attack Story

The Attack Story provides a visual relationship between the entities involved in the incident.

Microsoft Defender associated:

- 👤 **User:** `Vm1\Sia123`
- 💻 **Device:** `Vm1`
- ⚙️ **Process Group:** 3 Processes identified (`certutil.exe` execution variations)

This allows analysts to quickly understand the execution chain on the affected endpoint and the context of the user account.

---

## 📸 Attack Story

> *(Insert Attack Story Screenshot)*

---

# 🔍 Investigation Graph

The Investigation Graph automatically maps the detailed entities associated with the incident.

### Observed Entities

| Entity Type | Entity |
|-------------|--------|
| **User** | `Vm1\Sia123` |
| **Device** | `Vm1` |
| **Process Group** | 3 instances of `certutil.exe` download commands |

The graph highlights the repeated execution of `certutil.exe` commands originating from the user session on `Vm1`.

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

Microsoft Defender identified three suspicious process execution events as part of the evidence.

The evidence and response tab recorded the following details:

| Property | Value |
|----------|-------|
| **Entity Type** | Process |
| **Verdict** | Suspicious |
| **First Seen** | Jul 25, 2026 6:14 PM |
| **Impacted Assets** | `Vm1` |
| **Detection Origin** | certutil download |

---

## 📸 Evidence & Response

> *(Insert Evidence Screenshot)*

---

# 📋 Activities

The Activities tab records automated actions performed during the incident lifecycle.

For this incident:

- 🚨 3 Alerts for 'certutil download' were automatically correlated to incident 49 at Jul 25, 2026 6:26 PM.
- 🤖 Activities were performed by Microsoft Defender XDR via automated triggers.

The activity history provides an audit trail of the automated incident workflow.

---

## 📸 Activities

> *(Insert Activities Screenshot)*

---

# 🛡️ SOC Analyst Investigation

During investigation the analyst should:

- 🔎 Verify the legitimacy of the destination URL (`https://example.com/test.txt`).
- 📁 Inspect the file system on `Vm1` to locate and remove any files dropped or cached by `certutil.exe`.
- 👤 Confirm with the user `Vm1\Sia123` if they intentionally executed certutil for certificate management or troubleshooting.
- ⚙️ Check the parent process of `certutil.exe` to see if it was spawned interactively via `cmd.exe`/`powershell.exe` or by a malicious parent script.
- 🌐 Review proxy or firewall logs to see if outbound traffic connected to the external IP/domain associated with the download request.
- 🚨 Isolate the affected endpoint (`Vm1`) if the downloaded payload is confirmed to be malicious.

---

# 🎯 Security Impact

Using built-in administrative binaries like `certutil.exe` for file downloads is a classic Living off the Land (LotL) technique designed to bypass signature-based detections.

Detecting this behavior allows SOC analysts to intercept payload delivery before second-stage malware can be executed.

If successful and left uninvestigated, this download could lead to:

- 📥 Execution of secondary malware payloads (e.g., RATs, ransomware, backdoors)
- 📡 Establishing Command and Control (C2) communication
- 🔄 Further lateral movement within the network

---

⬆️ [**Back to Detection Validation Summary**](https://github.com/SAI1813q/Microsoft-Sentinel-SOC-Lab/blob/main/Detection/README.md#-detection-validation-summary)

---
