# 🚨 Detection Validation

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
