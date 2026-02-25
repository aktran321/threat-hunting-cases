# Scenario
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP).
After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then 
quit the company. Your task is to investigate John's activities on his corporate device (windows-target-1) using Microsoft 
Defender for Endpoint (MDE) and ensure nothing suspicious is taking place.

# Hypothesis
John is an administrator on his device and is not limited on which applications he uses. He may try to archive/compress 
sensitive information and send it to a private drive or something.

# Data Collection
I used the query below in MDE DeviceFileEvents to look for files created on John Doe's device. There is regular activity of archiving files to a "backup" folder.
```
let VMName = "windows-target-";
DeviceFileEvents
| where DeviceName == VMName
| where FileName endswith ".zip"
| order by Timestamp desc
```
![initial logs](/images-exf/initial-logs.png)

We can take the Timestamp from the creation of one of the files in question and see what processes were started around that time.
```
let VMName = "windows-target-";
let specificTime = datetime(2026-02-23T20:49:11.6726289Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
```
![exfiltration script](/images-exf/exfiltrate-script.png)

From the logs, we notice an `exfiltratedata.ps1` powershell script has been run and is using the 7-Zip program to stealthily compress files employee data into an archive.

I increased the time window to see if the data was successfully exfiltrated off the machine, but did not see any evidence of this happening.
```
let VMName = "windows-target-";
let specificTime = datetime(2026-02-23T20:49:11.6726289Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where DeviceName == VMName
| order by Timestamp desc
```

# Response
Upon discovering the archiving of employee data, I immediately isolated the machine and notified the employee's manager, including everything with the archives being created at regular intervals via a powershell script. There didn't appear to be any evidence of data exfiltration. Standing by for further instructions from management.

# MITRE ATT&CK TTPs Aligned to Scenario

TA0001 – Initial Access
• (Potential future risk if insider attempts external staging/exfil)

TA0002 – Execution
• T1059.001 – Command and Scripting Interpreter: PowerShell  
  (Execution of exfiltratedata.ps1)
• T1059 – Command and Scripting Interpreter

TA0007 – Discovery
• T1083 – File and Directory Discovery  
  (Identifying sensitive files before compression)

TA0009 – Collection
• T1560 – Archive Collected Data  
• T1560.001 – Archive via Utility (7-Zip used to compress data)

TA0010 – Exfiltration
• T1041 – Exfiltration Over C2 Channel (Potential)
• T1567 – Exfiltration Over Web Service (Potential private drive upload)
• T1020 – Automated Exfiltration (If scripted/scheduled)

TA0005 – Defense Evasion
• T1140 – Deobfuscate/Decode Files or Information (if script obfuscation used)
• T1036 – Masquerading (Using “backup” folder naming to appear legitimate)

TA0003 – Persistence (If recurring)
• T1053 – Scheduled Task/Job (If script runs at intervals)

# Learning
Moving forward, we could create alerts to notify management and automatically isolate a machine if there are a large number of zip files being created at once. We could even implement application whitelisting so only certain individuals are allowed to compress files.
