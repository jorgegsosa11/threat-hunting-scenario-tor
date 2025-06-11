# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

---

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Downloaded the TOR browser installer: https://www.torproject.org/download/
2. Installed it manually by executing the installer:  
   `tor-browser-windows-x86_64-portable-14.5.3.exe`
3. Extracted the browser and support files to the Desktop.
4. Opened the TOR browser from the `Tor Browser` folder on the Desktop.
5. Connected to TOR and browsed websites. Though specific `.onion` sites may rotate, the activity generated network connections and logs indicating TOR usage:
   - Example:  
     - TOR Exit Node: `65.109.67.160`
     - TOR Directory Server: `37.120.184.36`
6. Created a file on the desktop named `something.txt` — potentially used to simulate post-activity logs.
7. File and folder artifacts related to TOR remained on the desktop.

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description** |
|---------------|------------------|
| **Name** | DeviceFileEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Used for detecting TOR browser download, file extractions to the Desktop, and creation/deletion of a suspicious file (`something.txt`). |

| **Parameter** | **Description** |
|---------------|------------------|
| **Name** | DeviceProcessEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect the manual launch of the TOR installer and execution of `firefox.exe` (TOR browser). |

| **Parameter** | **Description** |
|---------------|------------------|
| **Name** | DeviceNetworkEvents |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Used to detect TOR network activity, including connections made by `tor.exe` and `firefox.exe` over common TOR ports (443, 9001). |

---

## Related Queries:

```kql
// 1. Detect TOR browser installer download
DeviceFileEvents
| where DeviceName startswith "jorge"
| where FileName contains "tor-browser-windows-x86_64-portable-14."
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FolderPath, SHA256, account = InitiatingProcessAccountName
// 2. Detect execution of the TOR installer
DeviceProcessEvents
| where DeviceName == "jorge-test-mach"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"
| project TimeGenerated, AccountName, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
// 3. Detect TOR browser launch (firefox.exe or tor.exe)
DeviceProcessEvents
| where DeviceName == "jorge-test-mach"
| where FileName in~ ("tor.exe", "firefox.exe", "start-tor-browser.exe", "torbrowser.exe")
  or FileName has_any ("tor-browser", "torbrowser", "torbrowser-install", "torbrowser-launcher")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
// 4. Detect network connections made by TOR processes
DeviceNetworkEvents
| where DeviceName == "jorge-test-mach"
| where InitiatingProcessAccountName != "system"
| where RemotePort in (80, 443, 9001, 9030, 9050)
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe", "start-tor-browser.exe", "torbrowser.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| sort by Timestamp desc
// 5. Detect presence of a “shopping list” or similar text file
DeviceFileEvents
| where FileName contains "something.txt"
| project Timestamp, DeviceName, RequestAccountName, ActionType, FolderPath
