# Scenario
- During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) 
that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

# Activity: 
Develop a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).

- During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

# Data Collection
Gather relevant data from logs, network traffic and endpoints

Navigate to Microsoft Defender for Endpoint and query for all unique devices onboarded to the service.
```
DeviceInfo
| distinct DeviceName
```
For this scenario we will just be focusing on the windows-target-1 machine.
The following KQL command will show the latest logs from the machine where it was internet facing. The DeviceName is purposefully cut off in the command as "windows-target-" because Microsoft Defender for Endpoint does not show the full name in the logs.
```
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == 1
| order by Timestamp desc
```
Last Internet Facing Time
- 2026-02-24T03:48:19.6247242Z

Brute force attempts are very common. We can check for such events through the `DeviceLogonEvents` table.
```
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
As seen below, the machine has been targeted by various IPs.
![Brute-Force-Attempts](/images-th/brute-force-attempts.png)

Check for successful logons from some of the top IPs with the most brute force attempts
```
let RemoteIPsInQuestion = dynamic(["119.42.115.235","183.81.169.238", "74.39.190.50", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)

```

![no results](/images-th/no-results.png)

Lets check for any successful logons for `windows-target-1`
```
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| distinct AccountName
```
The only successful logons for this machine is for the account `labuser0`
We can now look for the number of successful vs unsuccessful logons for this user
```
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser0"
| summarize count()
```
There were `27` successful logons in the past 30 days
```
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser0"
| summarize count()
```
The above query returned `0` failed logons in the past 30 days.
This indicates to us that a brute force attempt for the `labuser0` account so far has not taken place as a one-time password guess is unlikely.

To investigate further, we can check all of the IP addresses that have had successful logons for the `labuser0` account.
```
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser0"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
![labuser-logon-success](/images-th/labuser-logon-success.png)

By clicking on the IP addresses in the logs, we can check the geographical location of where the successful logons took place. All of the evidence looks normal. 

See if any attackers have successful and unsuccessful logon attempts
```
// Investigate for potential brute force successes
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName
| order by FailedLogonAttempts;
let SuccessfulLogons =  DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName
| order by SuccessfulLogons;
FailedLogons
| where DeviceName == "windows-target-"
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```
![no results](/images-th/no-results.png)


# MITRE ATT&CK Mapping
Observed
- **T1133 – External Remote Services** (VM exposed to internet)
- **T1110.001 – Password Guessing** (Brute-force attempts)
- **T1078 – Valid Accounts** (Successful network logons)

Potential / Hypothesized
- **T1046 – Network Service Scanning**
- **T1087 – Account Discovery**
- **T1021 – Remote Services (RDP/SMB/WinRM)** (Lateral Movement)
- **T1098 – Account Manipulation** (Persistence)

# Response
- Configure Network Security Group (NSG) for `windows-target-1` and only allow in-bound traffic from specific endpoints
- Implement account lockout after a certain number of failed logon attempts
- Implement Multi-Factor Authentication (MFA)
