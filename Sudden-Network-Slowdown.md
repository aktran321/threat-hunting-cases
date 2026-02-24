# Scenario
The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. 
After ruling out external DDoS attacks, the security team suspects something might be going on internally.

## Activity
Develop an initial hypothesis.
- All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

## Data Collection
- I consider inspecting the logs for excessive successful/failed connections from any devices.  If discovered, pivot and inspect those devices for any suspicious file or process events.
```
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| where DeviceName == "ktran-vm"
```
The device `ktran-vm` has many failed connections to two different IP addresses.
![Failed Connections](/images-sc2/failed-connections.png)
We can investigate these failed connections with the two queries below.
```
let IPInQuestion1 = "10.0.0.161";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where RemoteIP == IPInQuestion1
| order by Timestamp desc
| where DeviceName == "ktran-vm"
```
![Port Scan 1](/images-sc2/port-scan-1.png)
```
let IPInQuestion2 = "10.0.0.171";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where RemoteIP == IPInQuestion2
| order by Timestamp desc
| where DeviceName == "ktran-vm"
```
![Port Scan 2](/images-sc2/port-scan-2.png)

Let's observe all logs from the device through the `DeviceProcessEvents` table 10 minutes prior to when the scan took place.
```
let VMName = "ktran-vm";
let specificTime = datetime(2026-02-24T14:21:57.6791001Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
We find an interesting log.
![Port scan command](/images-sc2/ps-command.png)

At `2026-02-24T14:19:33.4564258Z`, a powershell script called `portscan.ps1` was executed.

After logging into the machine in question, we can see observe the script that was launched.

![code](/images-sc2/code.png)

We can see which account executed the command with the query here.
```
let VMName = "ktran-vm";
DeviceProcessEvents
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
| where InitiatingProcessCommandLine contains "portscan"
```
We discover that the script was launched by the `SYSTEM` account. Since this is unexpected beahvior and not set up by the admins, I isolated the device and ran a malware scan with Microsoft Defender for Endpoint.

The malware scan produced no results, so out of caution, we kept the device isolated and put in a ticket to have the machine re-imaged and re-built.

## MITRE ATT&CK Related TTPs

T1046 – Network Service Discovery
Internal port scanning against 10.0.0.161 and 10.0.0.171.

T1059.001 – Command and Scripting Interpreter: PowerShell
Execution of portscan.ps1.

T1082 – System Information Discovery (Potential)
Likely host/service enumeration tied to scanning activity.

T1078 – Valid Accounts (Potential)
Execution under the SYSTEM account.

T1562 – Impair Defenses (Contextual Risk)
Unrestricted PowerShell usage and lack of internal restrictions increase exposure.


