
# 🏗️ Architecture Overview

Welcome to the technical architecture documentation for this cloud-native Security Operations Center (SOC) project. This document outlines the end-to-end design, components, and data flow implemented to monitor, ingest, and analyze threat telemetry within Microsoft Azure and Microsoft Sentinel.

---

## 📖 Project Overview
This project simulates an enterprise security operations environment. It deploys vulnerable honeypot virtual machines with exposed administrative endpoints to capture live brute-force traffic, streams logs using the Azure Monitor Agent (AMA), consolidates data into a central Log Analytics Workspace, and handles threat analytics and response automation via Microsoft Sentinel and Microsoft Defender XDR.

---

## ☁️ Azure Infrastructure
* **Resource Group:** Centralized management via a dedicated resource group (`ResourceGrp`) hosted in **Central India**.

<img width="1920" height="1020" alt="Screenshot 2026-08-05 192253" src="https://github.com/user-attachments/assets/5ac1d8ac-bf0d-4c85-afb9-1e67fe0d6988" />

* **Subscription Management:** Deployed using an active Azure subscription with unified identity and resource tracking.

<img width="1920" height="1020" alt="Screenshot 2026-07-22 180005" src="https://github.com/user-attachments/assets/5fcfcecc-fa4a-4ee0-afd8-eee33f7815ab" />

---

## 🌐 Network Architecture
* **Virtual Network (VNet):** Configured with a dedicated address space (`10.0.0.0/16`) named `VNet1`.
<img width="1920" height="1020" alt="Screenshot 2026-08-05 193823" src="https://github.com/user-attachments/assets/d4317b98-13ca-4d8a-aab7-26da3cc93ca3" />

* **Network Security Groups (NSGs):** Configured with granular security rules across `DC-nsg`, `Vm1-nsg`, and `vm2-nsg` to control traffic flows.
* **Public IP Endpoints:** Dedicated public IPs (`DC-ip`, `Vm1-ip`) attached to virtual machines to purposely simulate exposure and draw external attack traffic.
<img width="1920" height="1020" alt="Screenshot 2026-08-05 193853" src="https://github.com/user-attachments/assets/233890b0-f778-422d-ba1e-f5d615a50271" />

---

## 🖥️ Virtual Machines
* **Domain Controller (`DC`):** 
  * **OS:** Windows Server 2022 Datacenter.
  * **Extensions:** Configured with the **AzureMonitorWindowsAgent**.
  <img width="1920" height="1020" alt="Screenshot 2026-08-05 192429" src="https://github.com/user-attachments/assets/b9d659dc-7560-4933-a2a1-73040a7d76e1" />

* **Workstation (`Vm1`):** 
  * **OS:** Windows 10 Pro (Standard B2als v2 size, 2 vCPUs, 4 GiB RAM).
  * **Extensions:** Integrated with the **AzureMonitorWindowsAgent** to stream operating system telemetry.
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192342" src="https://github.com/user-attachments/assets/467cae40-70cc-4e9f-84e1-b83793cfc654" />

---

## 🏢 Active Directory
* **Domain Structure:** Managed under the `root.project` forest using Active Directory Users and Computers (ADUC).
* **Simulated Users & Security Roles:** Configured with dedicated organizational accounts including custom security tiers (`SOC analyst L1 User`, `SOC analyst L3 User`, `Security Manager`), standard users, and service accounts to generate realistic authentication logs and internal event histories.

<img width="1599" height="720" alt="WhatsApp Image 2026-08-05 at 7 57 56 PM" src="https://github.com/user-attachments/assets/c2117ae0-e333-4819-8f2d-34ad710d4c26" />

---

## 📡 Log Collection Architecture
* **Azure Monitor Agent (AMA):** Modern log forwarding agents deployed across Windows virtual machines.
* **Data Collection Rules (DCR):** Configured via `dcr-windows` to stream granular Windows Security Events directly into the cloud workspace.

<img width="1920" height="1020" alt="Screenshot 2026-08-05 193550" src="https://github.com/user-attachments/assets/d5896da0-0219-4426-979f-e36c17c78e0d" />



## 🛡️ Microsoft Sentinel & Unified SecOps (Defender XDR)
* **Workspace Integration:** Connected through `LAW-Project1` in Central India, bridging Azure Sentinel analytics into the unified Microsoft Defender portal interface.
* **Content Hub Solutions:** Deployed out-of-the-box and customized analytics including *Windows Security Events via AMA*, threat detection rules, and advanced hunting packages.<img width="1920" height="1020" alt="Screenshot 2026-08-05 192743" src="https://github.com/user-attachments/assets/fd58fd3f-c214-45c3-b21f-2671701c8b7c" />


---

## 📊 Log Analytics Workspace (LAW)
* **Central Repository (`LAW-Project1`):** Serves as the core hub for security event storage, analytical query processing, and 30-day retention management.


<img width="1920" height="1020" alt="Screenshot 2026-08-08 234655" src="https://github.com/user-attachments/assets/ed952c04-4341-45b3-a499-0729a41bfbc3" />

---

## 📥 Data Collection Rules (DCR)
* **Targeted Ingestion Rules:** Configured via `dcr-windows` targeting scope subscriptions and specific resource groups (`ResourceGrp`) for `DC` and `Vm1`.

<img width="1920" height="1020" alt="Screenshot 2026-08-05 193622" src="https://github.com/user-attachments/assets/cdbb8ea8-bbab-441e-8104-33e5c37e2ef4" />
<img width="1920" height="1020" alt="Screenshot 2026-07-29 120525" src="https://github.com/user-attachments/assets/d6a68e91-1777-4707-a155-f50d2610fc93" />

---

## 🤖 Automation Components
* **Logic Apps Automation:** Includes workflows such as `Notification`, `PB-alert-enrichment`, and `Team_msg` configured to handle automated incident notification and playbook execution with verified successful run histories.

<img width="1920" height="1020" alt="Screenshot 2026-07-27 111106" src="https://github.com/user-attachments/assets/b402c022-8ea0-4696-92cb-9ea03a23cb0e" />

---

## 🔄 End-to-End Data Flow
1. **Threat Surface Exposure:** Public IP addresses on `Vm1` and `DC` draw incoming connection and brute-force attempts from external sources.
2. **Telemetry Generation:** Operating systems and Active Directory record local security events and authentication attempts.
3. **Ingestion Pipeline:** The **Azure Monitor Agent** governed by `dcr-windows` collects logs and streams them to the **Log Analytics Workspace** (`LAW-Project1`).
4. **Detection & SIEM:** **Microsoft Sentinel** evaluates incoming telemetry against deployed KQL analytics and threat rules.
5. **Automation & Response:** Triggered alerts activate Azure Logic Apps (`Notification`) to distribute automated event responses.

---


[⬆️ Back to Project Overview](#-project-overview)
