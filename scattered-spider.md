## Overview

A confirmed Business Email Compromise (BEC) incident involving a £24,500 wire transfer prompted investigation within Microsoft Sentinel.

The objective of this hunt was to:
- Confirm account compromise
- Identify attacker infrastructure
- Trace attacker activity post-authentication
- Determine persistence mechanisms
- Scope impact and affected users

25 February 2026, 21:00 to 23:00 UTC

```
SigninLogs
| where TimeGenerated between (
    datetime(2026-02-25 21:00:00) .. datetime(2026-02-25 23:00:00)
)
| where UserDisplayName == "Mark Smith"
```
![display-name](/images-scsp/display-name.png)

Mark authenticated from his usual location during the day. But someone else authenticated as Mark from somewhere else during the evening.

![ip-location](/images-scsp/ip-location.png)

The attacker signed in from Noord-Holland Amsterdam with the IP address `205.147.16.190`

ResultType 50074 shows that previous sign-in attempts from the attacker failed due to MFA.

![result-type](/images-scsp/result-type.png)

However, after just three attempts, Mark Smith eventually approved the MFA

```
SigninLogs
| where TimeGenerated between (
    datetime(2026-02-25 21:00:00) .. datetime(2026-02-25 23:00:00)
)
| where UserDisplayName == "Mark Smith"
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ResultType, ResultSignature
```

![[mfa-brute-force](/images-scsp/[mfa-brute-force.png)

After the successful sign-in the attacker accessed the app `One Outlook Web`
![app-name](/images-scsp/app-name.png)

We also see that the attacker is using a Linux OS and Firefox 147.0 Browser.

---
IR Lead: "MFA is confirmed beaten. Now I need to know what the attacker did once inside. What did they touch first? The sequence tells us the objective."

The first action after authentication reveals intent. Did they exfiltrate immediately? Set up persistence? Or read the inbox to understand the target?

Query CloudAppEvents for the attacker's IP during the attack window. Sort by time ascending. What was the very first ActionType?

```
CloudAppEvents
| where TimeGenerated >= todatetime('2026-02-25T21:54:24.731913Z')
| where IPAddress == "205.147.16.190"
| project TimeGenerated, AccountId, RawEventData, ObjectName, ObjectType, AccountDisplayName, Application, ActionType
```

Given the ActionType `MailItemsAccessed`, the attacker immediately accessed Mark Smith's email inbox once they acquired access to his account.

![access-mail](/images-scsp/access-mail.png)

At `2026-02-25T22:03:59Z` the attacker created a `New-InboxRule`. Sophisticated attackers establish persistence to maintain access. Inbox rules are a favorite. They are silent, persistent, and often overlooked.

![new-inbox-rule](/images-scsp/new-inbox-rule.png)

Digging into `Raw Data` > `Parameters`

![parameters1](/images-scsp/parameters1.png)

The attacker has created the above rule for defense evasion. The rule activates whenever an email contains any of these words: phishing, compromised, verify, security.

The rule is given then name `..` so that it might be overlooked. The rule then immediately deletes emails with the above keywords to hide artifacts from the actual owner.

This can be mapped to MITRE ATT&CK T1564.008 - Hide Artifacts: Email Rules.

Another inbox rule called `.` was created to forward emails to `insights@duck.com` whenever an email contained the keywords `invoice, payment, wire, transfer`.

![parameters2](/images-scsp/parameters2.png)

The attacker is exfiltrating data, utilizing MITRE ATT&CK T114.003 Email Forwarding.

We now pivot into `EmailEvents` to see who the attacker successfully phished.

```
EmailEvents
| where TimeGenerated >= todatetime('2026-02-25T21:54:24.731913Z')
| where SenderIPv4 == "205.147.16.190" 
```

The recipient is `j.reynolds@lognpacific.com`

![phish](/images-scsp/phish.png)

The subject line being `RE: Invoice #INV-2026-0892 - Updated Banking Details`

And EmailDirection `Intra-org` showing that the email was sent from within the organization.

Checking `SignInLogs`, we can find other apps the attacker gained access to

```
SigninLogs
| where TimeGenerated >= todatetime('2026-02-25T21:54:24.731913Z')
| where IPAddress == "205.147.16.190"
| distinct AppDisplayName
```
![other-apps](/images-scsp/other-apps.png)

Since the attacker still has a valid session and inbox rules are still active, our first containment action is to `revoke sessions`

The scenario utilized MFA fatigue, inbox rule persistence, BEC targeting finance, and anonymization infrastructure which has affected companies such as MGM Resorts and Caesars Entertainment. Methods used by the Threat Group Scatter Spider.
