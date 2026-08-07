# 📚 Lessons Learned

Building this Microsoft Sentinel SOC Lab involved much more than deploying Azure resources and writing detection rules. Throughout the project, numerous configuration issues, failed detections, telemetry gaps, and automation challenges had to be identified, investigated, and resolved. These troubleshooting experiences significantly improved my understanding of Microsoft Sentinel, Microsoft Defender XDR, Azure security services, and real-world SOC operations.

## 🎯 Key Takeaways

- 🛠️ **Troubleshooting is a Core SOC Skill**
  - Many detections initially failed due to incorrect audit policies, missing event logs, disabled process creation auditing, incomplete telemetry, or misconfigured entity mappings. Identifying and resolving these issues reinforced the importance of systematic troubleshooting.

- 📥 **Data Collection is the Foundation of Detection**
  - Learned how Azure Monitor Agent (AMA), Data Collection Rules (DCRs), Sysmon, and Windows Security Logs work together to provide the telemetry required for effective detection engineering.

- 🔍 **Detection Validation is Essential**
  - Every analytic rule was tested using attack simulations to verify alerts, incidents, entity mappings, alert grouping, automation, and workbook visualizations. Rules were refined whenever expected detections failed or generated inaccurate results.

- ⚙️ **Automation Requires Careful Planning**
  - Implementing Automation Rules and Logic Apps highlighted the importance of correctly configuring triggers, conditions, permissions, execution order, and incident workflows to ensure reliable automated responses.

- 📊 **Accurate Dashboards Depend on Accurate Queries**
  - Building Microsoft Sentinel Workbooks required multiple iterations to ensure visualizations represented actual security events instead of misleading or incomplete data.

- 🎯 **MITRE ATT&CK Improves Detection Coverage**
  - Mapping every detection to MITRE ATT&CK techniques provided a structured approach for organizing detections and measuring coverage across different stages of the attack lifecycle.

- 🖥️ **Practical Windows Security Monitoring**
  - Working extensively with Windows Security Events, Sysmon telemetry, Active Directory, and endpoint activity improved my understanding of attacker behavior and Windows internals.

- ☁️ **Cloud-Native SOC Deployment**
  - Gained practical experience deploying and integrating Microsoft Sentinel, Microsoft Defender XDR, Log Analytics Workspace, Azure Monitor Agent, Data Collection Rules, Logic Apps, and Azure networking components.

- 🚀 **Iterative Development Produces Better Security Solutions**
  - The project continuously evolved through testing, troubleshooting, and refinement. Each iteration resulted in more reliable detections, improved automation, and more meaningful security dashboards.

---
