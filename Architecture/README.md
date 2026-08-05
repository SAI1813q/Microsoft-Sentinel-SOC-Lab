
# 🏗️ Architecture Overview

Welcome to the technical architecture documentation for this cloud-native Security Operations Center (SOC) project. This document outlines the end-to-end design, components, and data flow implemented to monitor, ingest, and analyze threat telemetry within Microsoft Azure and Microsoft Sentinel.

---

## 📖 Project Overview
This project replicates a production enterprise security operations setup. It deploys vulnerable honeypot virtual machines with exposed administrative endpoints to capture live brute-force traffic, streams logs using the Azure Monitor Agent (AMA), consolidates data into a central Log Analytics Workspace, and handles threat analytics and response automation via Microsoft Sentinel and Microsoft Defender XDR.

---

## ☁️ Azure Infrastructure
* **Resource Group:** Centralized management via a dedicated resource group (`ResourceGrp`) hosted in **Central India**.
* **Subscription Management:** Deployed using an active Azure subscription with unified identity and resource tracking.

---

## 🌐 Network Architecture
* **Virtual Network (VNet):** Configured with a dedicated address space (`10.0.0.0/16`) named `VNet1`.
* **Network Security Groups (NSGs):** Configured with granular security rules across `DC-nsg`, `Vm1-nsg`, and `vm2-nsg` to control traffic flows.
* **Public IP Endpoints:** Dedicated public IPs (`DC-ip`, `Vm1-ip`) attached to virtual machines to purposely simulate exposure and draw external attack traffic.

---

## 🖥️ Virtual Machines
* **Domain Controller (`DC`):** 
  * **OS:** Windows Server 2022 Datacenter.
  * **Extensions:** Configured with the **AzureMonitorWindowsAgent**.
* **Honeypot Workstation (`Vm1`):** 
  * **OS:** Windows 10 Pro (Standard B2als v2 size, 2 vCPUs, 4 GiB RAM).
  * **Extensions:** Integrated with the **AzureMonitorWindowsAgent** to stream operating system telemetry.

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

---

## 📥 Data Collection Rules (DCR)
* **Targeted Ingestion Rules:** Configured via `dcr-windows` targeting scope subscriptions and specific resource groups (`ResourceGrp`) for `DC` and `Vm1`.

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
  ![Resource Group Inventory](./images/Screenshot%202026-08-05%20192245.png)

* **Virtual Machine Specifications (`Vm1`):**
  ![VM1 Properties](./images/Screenshot%202026-08-05%20192429.png)

* **VM1 Agent Extensions:**
  ![VM1 Extensions](./images/Screenshot%202026-08-05%20192455.png)

* **Domain Controller Setup (`DC`):**
  ![DC Properties](./images/Screenshot%202026-08-05%20192402.png)

* **Active Directory Users and Computers (ADUC):**
  ![Active Directory Users and Groups](./images/WhatsApp%20Image%202026-08-05%20at%207.57.56%20PM.jpeg)

* **Virtual Network Topology (`VNet1`):**
  ![VNet Configuration](./images/Screenshot%202026-08-05%20193823.png)

* **Network Security Groups:**
  ![NSGs](./images/Screenshot%202026-08-05%20193853.png)

* **Microsoft Sentinel Workspace & Defender XDR Integration:**
  ![Sentinel Defender Hub](./images/Screenshot%202026-08-05%20192743.jpg)

* **Content Hub & Windows Security Events Solution:**
  ![Content Hub](./images/Screenshot%202026-08-05%20193455.png)

* **Data Collection Rules (DCR) Scope Configuration:**
  ![DCR Wizard Scope](./images/Screenshot%202026-08-05%20193622.png)

* **Logic Apps Automation Playbooks (`Notification`):**
  ![Logic Apps Run History](./images/Screenshot%202026-08-05%20193713.png)

---

[⬆️ Back to Project Overview](#-project-overview)
