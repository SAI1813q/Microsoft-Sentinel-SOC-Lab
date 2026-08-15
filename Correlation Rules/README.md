
# 🔗 Correlation Rules

## 📖 Overview

This section documents the multi-stage correlation rules implemented in Microsoft Sentinel to identify related security events that, when observed together, provide stronger evidence of an attack than individual detections alone.

The correlation rules combine multiple analytics detections using KQL-based logic and temporal relationships to identify higher-confidence attack chains.

---

## 📊 Correlation Rules

| # | Correlation Rule | Attack Chain | Rule |
|---|---|---|---|
| 1 | Brute Force → Successful Login → New Local User | Credential Attack → Account Creation | [View Rule](#-correlation-1--brute-force--successful-login--new-local-user) |
| 2 | Encoded PowerShell → Registry Run Key | Execution → Persistence | [View Rule](#-correlation-2--encoded-powershell--registry-run-key) |
| 3 | Mimikatz → PsExec | Credential Dumping → Service Execution | [View Rule](#-correlation-3--mimikatz--psexec) |
| 4 | New Service → Event Log Cleared | Service Creation → Evidence Removal | [View Rule](#-correlation-4--new-service--event-log-cleared) |
| 5 | Certutil Download → Mshta Execution | Payload Transfer → Proxy Execution | [View Rule](#-correlation-5--certutil-download--mshta-execution) |
| 6 | Defender Disabled → Firewall Disabled → Mimikatz | Defense Impairment → Credential Dumping | [View Rule](#-correlation-6--defender-disabled--firewall-disabled--mimikatz) |
