

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jorgegsosa11/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## 📘 Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls. Recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours.

**🎯 Goal**: Detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## 🔍 High-Level TOR IoC Discovery Plan

- ✅ Check `DeviceFileEvents` for any `tor.exe` or `firefox.exe` file events  
- ✅ Check `DeviceProcessEvents` for signs of TOR browser installation or usage  
- ✅ Check `DeviceNetworkEvents` for outgoing connections over known TOR ports (`443`, `9001`, `9030`, `9050`)

---

## 🛠️ Steps Taken

### 🔹 Step 1: File Event Detection

Searched `DeviceFileEvents` for any file with the string `"tor"` in it. Discovered that user `jorge_lab` downloaded a TOR installer and extracted many TOR-related files to the Desktop, along with creating a file named `something.txt`.

**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName startswith "jorge"
| where FileName contains "tor-browser-windows-x86_64-portable-14."
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FolderPath, SHA256, account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/9f297351-b108-4149-9868-9912b686c2bd)


---

## 🔹 Step 2: TOR Browser Execution Detection

Searched `DeviceProcessEvents` for `ProcessCommandLine` containing the TOR browser executable.

- **📅 Date**: June 5, 2025  
- **⏰ Time**: 04:30 AM UTC  
- **👤 User**: `jorge_lab`  
- **💻 Device**: `jorge-test-mach`  
- **📌 Action**: TOR Browser installer (`tor-browser-windows-x86_64-portable-14.5.3.exe`) was manually executed from the Downloads folder.

**🔍 KQL Query:**

```kql
DeviceProcessEvents
| where DeviceName == "jorge-test-mach"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project TimeGenerated, AccountName, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/879b50c4-a616-4aa0-856e-18ebe57e71d5)


---

## 🔹 Step 3: Confirmed TOR Browser Launch

Searched `DeviceProcessEvents` again for any indication that `tor.exe`, `firefox.exe`, or other TOR executables were run.

- **Date:** June 5, 2025  
- **Time:** 04:31 AM UTC  
- **Observation:** TOR's `firefox.exe` was launched from the Tor Browser folder. The initiating process was the installer identified earlier.

### 🔍 KQL Query:

```kql
DeviceProcessEvents
| where DeviceName == "jorge-test-mach"
| where FileName in~ ("tor.exe", "firefox.exe", "start-tor-browser.exe", "torbrowser.exe")
  or FileName has_any ("tor-browser", "torbrowser", "torbrowser-install", "torbrowser-launcher")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```
![image](https://github.com/user-attachments/assets/57649bb8-485c-4d9b-acd5-f50b2e43084d)


---

## 🔹 Step 4: TOR Network Communication Detected

Checked `DeviceNetworkEvents` for outgoing TOR-related connections over known ports: 443, 9001, 9030, 9050.

- **Date:** June 5, 2025  
- **Time:** ~04:32 AM UTC  

### Observation:
- Connection to `65.109.67.160` on port `443`  
- Connection to `37.120.184.36` on port `9001`  

These indicate successful TOR communications.

### 🔍 KQL Query:

```kql
DeviceNetworkEvents
| where DeviceName == "jorge-test-mach"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (80, 443, 9001, 9030, 9050)
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe", "start-tor-browser.exe", "torbrowser.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp desc

```
![image](https://github.com/user-attachments/assets/2bf8466d-b5b2-430a-b364-848d89f973f1)


---

# Chronological Event Log: Tor Activity Threat Hunt - jorge_lab

This document outlines the chronological sequence of events related to the detection and investigation of Tor Browser activity on the **jorge-test-mach** device, associated with the user **jorge_lab**. The timeline is constructed from various security logs and observations during the threat hunt.

---

## Event Timeline

### June 5, 2025, 04:28 AM UTC - Tor Browser Download and Execution
- **Action:** A file named `tor-browser-windows-x86_64-portable-14.5.3.exe` was identified as having been downloaded and subsequently executed.  
- **User:** jorge_lab  
- **Device:** jorge-test-mach  
- **Location:** The executable was run from the Downloads folder.  
- **Details:** This event indicates the manual download and initial execution of the Tor Browser installer by the user. The process was recorded as being created.

---

### June 5, 2025, 04:28 AM UTC (Approx.) - Tor Files Copied to Desktop
- **Action:** Numerous Tor-related files were copied to the desktop, and a file named `something.txt` was created on the desktop.  
- **User:** jorge_lab  
- **Device:** jorge-test-mach  
- **Location:** Desktop  
- **Details:** This activity is indicative of the Tor Browser's portable installation or extraction process, often leading to files being placed in user-accessible directories like the desktop. The creation of `something.txt` alongside these events suggests potential post-installation actions or notes.

---

### June 5, 2025, 04:29 AM UTC - Tor Browser Application Opened
- **Action:** The Tor Browser application, specifically `firefox.exe` (the main executable for Tor Browser), was launched.  
- **User:** jorge_lab  
- **Device:** jorge-test-mach  
- **Location:** The `firefox.exe` was started from within the Tor Browser folder.  
- **Details:** This event confirms that the Tor Browser was not only downloaded and extracted but was actively opened and used by the user. The initiating process was identified as the Tor Browser installer.

---

### June 5, 2025, 04:32 AM UTC (Approx.) - Tor Network Connections Established
- **Action:** The Tor client initiated outbound network connections to the Tor network.  
- **User:** jorge_lab  
- **Device:** jorge-test-mach  
- **Location:** The Tor program was running from the Tor Browser folder on the desktop.  
- **Details:** Active communication with the Tor network was observed through multiple connections:  
  - Connection to IP `65.109.67.160` on port `443` (standard HTTPS port), with a RemoteUrl resembling a random or hidden service domain.  
  - Connection to IP `37.120.184.36` on port `9001`, a commonly used port for Tor nodes.  

  These connections clearly indicate active Tor network usage, signifying that the Tor Browser was successfully communicating with the Tor anonymity network.

---

## Summary of Findings

The chronological analysis reveals a clear sequence of events:  
The user **jorge_lab** downloaded and executed the Tor Browser installer, which resulted in the copying of Tor-related files to the desktop. Immediately following, the Tor Browser application was launched, and within minutes, it established active connections to the Tor network, indicating successful and intentional use of the anonymity tool on the **jorge-test-mach** device.

---

## Response Taken

- TOR usage was confirmed on endpoint **jorge-test-mach**.  
- The device was isolated from the network.  
- The user’s direct manager was notified.  
