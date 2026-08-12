
# 🏗️ Architecture Overview

Welcome to the technical architecture documentation for this cloud-native Security Operations Center (SOC) project. This document outlines the end-to-end design, components, and data flow implemented to monitor, ingest, and analyze threat telemetry within Microsoft Azure and Microsoft Sentinel.

---

## 📖 Project Overview
This project replicates a production enterprise security operations setup. It deploys vulnerable honeypot virtual machines with exposed administrative endpoints to capture live brute-force traffic, streams logs using the Azure Monitor Agent (AMA), consolidates data into a central Log Analytics Workspace, and handles threat analytics and response automation via Microsoft Sentinel and Microsoft Defender XDR.

---

## ☁️ Azure Infrastructure
* **Resource Group:** Centralized management via a dedicated resource group (`ResourceGrp`) hosted in **Central India**.
* **Subscription Management:** Deployed using an active Azure subscription with unified identity and resource tracking.
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192253" src="https://github.com/user-attachments/assets/5ac1d8ac-bf0d-4c85-afb9-1e67fe0d6988" />
---

## 🌐 Network Architecture
* **Virtual Network (VNet):** Configured with a dedicated address space (`10.0.0.0/16`) named `VNet1`.
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

---

## 📡 Log Collection Architecture
* **Azure Monitor Agent (AMA):** Modern log forwarding agents deployed across Windows virtual machines.
* **Data Collection Rules (DCR):** Configured via `dcr-windows` to stream granular Windows Security Events directly into the cloud workspace.

---

## 🛡️ Microsoft Sentinel & Unified SecOps (Defender XDR)
* **Workspace Integration:** Connected through `LAW-Project1` in Central India, bridging Azure Sentinel analytics into the unified Microsoft Defender portal interface.
* **Content Hub Solutions:** Deployed out-of-the-box and customized analytics including *Windows Security Events via AMA*, threat detection rules, and advanced hunting packages.

---

## 📊 Log Analytics Workspace (LAW)
* **Central Repository (`LAW-Project1`):** Serves as the core hub for security event storage, analytical query processing, and 30-day retention management.
<img width="1920" height="1020" alt="Screenshot 2026-08-05 193204" src="https://github.com/user-attachments/assets/2c0ba554-8b6b-4d34-845c-b936652ae2e7" />
---

## 📥 Data Collection Rules (DCR)
* **Targeted Ingestion Rules:** Configured via `dcr-windows` targeting scope subscriptions and specific resource groups (`ResourceGrp`) for `DC` and `Vm1`.
<img width="1920" height="1020" alt="Screenshot 2026-08-05 193622" src="https://github.com/user-attachments/assets/4572dc20-211e-4092-aeb2-4d1f23e83244" />
---

## 🤖 Automation Components
* **Logic Apps Automation:** Includes workflows such as `Notification`, `PB-alert-enrichment`, and `Team_msg` configured to handle automated incident notification and playbook execution with verified successful run histories.

---

## 🔄 End-to-End Data Flow
1. **Threat Surface Exposure:** Public IP addresses on `Vm1` and `DC` draw incoming connection and brute-force attempts from external sources.
2. **Telemetry Generation:** Operating systems and Active Directory record local security events and authentication attempts.
3. **Ingestion Pipeline:** The **Azure Monitor Agent** governed by `dcr-windows` collects logs and streams them to the **Log Analytics Workspace** (`LAW-Project1`).
4. **Detection & SIEM:** **Microsoft Sentinel** evaluates incoming telemetry against deployed KQL analytics and threat rules.
5. **Automation & Response:** Triggered alerts activate Azure Logic Apps (`Notification`) to distribute automated event responses.

---

## 📸 Architecture Screenshots

* **Azure Resource Group Overview:**
  ![Resource Group Inventory]
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192245" src="https://github.com/user-attachments/assets/eb076887-4130-4b02-997b-0d487e2e3c20" />
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192302" src="https://github.com/user-attachments/assets/a3c62f43-02ad-4d20-a34c-a36fe701f0ad" />


* **Virtual Machine Specifications (`Vm1`):**
  ![VM1 Properties]<img width="1920" height="1020" alt="Screenshot 2026-08-05 192455" src="https://github.com/user-attachments/assets/4369aca4-f895-4fbb-92ac-51475b088b34" />
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192451" src="https://github.com/user-attachments/assets/1fd683ac-022b-4032-a095-bafbea0430d7" />
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192435" src="https://github.com/user-attachments/assets/1386db52-4d26-4b9c-be54-6966d44bb0eb" />


* **VM1 Agent Extensions:**
  ![VM1 Extensions](./images/Screenshot%202026-08-05%20192455.png)

* **Domain Controller Setup (`DC`):**
  ![DC Properties]<img width="1920" height="1020" alt="Screenshot 2026-08-05 192408" src="https://github.com/user-attachments/assets/7a398bd2-53db-455f-9fcf-c6d4b71e6e08" />
<img width="1920" height="1020" alt="Screenshot 2026-08-05 192402" src="https://github.com/user-attachments/assets/46b543db-a796-4687-ba0c-04c28a387602" />

<img width="1920" height="1020" alt="Screenshot 2026-08-05 192413" src="https://github.com/user-attachments/assets/0a82020d-194b-450d-9479-f023d08aeaba" />


* **Active Directory Users and Computers (ADUC):**
  ![Active Directory Users and Groups](./images/WhatsApp%20Image%202026-08-05%20at%207.57.56%20PM.jpeg)

* **Virtual Network Topology (`VNet1`):**
  ![VNet Configuration]<img width="1920" height="1020" alt="Screenshot 2026-08-05 193823" src="https://github.com/user-attachments/assets/a4e01e9b-9a26-4fd5-b189-24215a0e5b64" />


* **Network Security Groups:**
  ![NSGs]


* **Microsoft Sentinel Workspace & Defender XDR Integration:**
  ![Sentinel Defender Hub]<img width="1920" height="1020" alt="Screenshot 2026-08-05 192743" src="https://github.com/user-attachments/assets/fd58fd3f-c214-45c3-b21f-2671701c8b7c" />



* **Content Hub & Windows Security Events Solution:**
  ![Content Hub]<img width="1920" height="1020" alt="Screenshot 2026-08-05 193455" src="https://github.com/user-attachments/assets/32225039-7bf4-4b2e-b18d-a81f8a633e79" />
<img width="1920" height="1020" alt="Screenshot 2026-08-05 193512" src="https://github.com/user-attachments/assets/0556a5c4-5567-4d83-a48a-d72de6931046" />


* **Data Collection Rules (DCR) Scope Configuration:**
  ![DCR Wizard Scope]<img width="1920" height="1020" alt="Screenshot 2026-08-05 193550" src="https://github.com/user-attachments/assets/d2a40419-5688-47ce-8d0b-56d644db0449" />



* **Logic Apps Automation Playbooks (`Notification`):**
  ![Logic Apps Run History]

---

[⬆️ Back to Project Overview](#-project-overview)
