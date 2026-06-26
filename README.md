# soc-triage-cheat-sheet
# 3 AM SOC Triage Cheat Sheet  This repository contains a high-density, printable A4 cheat sheet designed for junior SOC analysts during their first shifts. It focuses on immediate triage for Linux auth.log, Windows Security event logs, and HTTP access logs.

**Write-up**

This cheat sheet is built specifically for a 6-month-junior SOC analyst walking into their first night shift at a small Kenyan SaaS company. At this stage, a junior doesn't need a text dump of RFC specifications; they need immediate, cognitive scaffolding to distinguish benign business operations from an active compromise when an alert fires at 3:00 AM.

The core trade-off made for extreme A4 compactness was omitting exhaustive field permutations and advanced multi-log correlation rules. Instead, the focus is strictly on single-source, high-signal fields that can be verified immediately using basic command-line utilities (grep, awk) or quick SIEM filters. Advanced behaviors like distributed password spraying or multi-stage lateral movement were dropped in favor of standalone, log-isolated indicators that give a junior the confidence to make an accurate initial triage decision within 60 seconds.

**3 AM SOC Triage Cheat Sheet (A4 Printable Layout)**
1. Linux auth.log (SSH & Privilege Escalation)

   The 5 Essential Fields:
   1)Timestamp / Hostname: When and where. Essential for tracking lateral movement timelines.
   
   2)Process[PID]: Usually sshd or sudo. Identifies the entry mechanism.
   
   3)Event Status: Look for Accepted vs. Failed or password vs. publickey.
   
   4)User Account: The target identity (e.g., ubuntu, root, or individual dev names)
   
   5)Source IP & Port: Where the connection originated.
   
   What "Normal" Looks Like:

   Successful publickey logins for standard users (ubuntu, deploy) during deployment windows or regular working hours,**

**Top 3 Misuse Signatures**

1)Inbound Brute Force: Thousands of continuous Failed password for invalid user entries from a non-Kenyan IP address.

  a)1-Line Detection: grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c
  
2)Unusual Sudo Abuse: A non-admin service account suddenly executing interactive shells or high-privilege binary commands.

  a)1-Line Detection: grep "COMMAND=" /var/log/auth.log | grep -vE "(expected_deploy_user|monitoring)"
  
3)Compromised Key / Off-Hours Access: A successful publickey authentication targeting an executive or infrastructure engineer account at an impossible hour (e.g., 03:15 AM) from an unfamiliar international hosting provider network.

  a)1-Line Detection: grep "Accepted publickey" /var/log/auth.log
  
**Real Sample Line**

Jun 26 03:14:22 prod-api-01 sshd[28411]: Accepted publickey for ubuntu from 197.248.31.42 port 49221 ssh2: RSA SHA256:abc123XYZ...

a)Jun 26 03:14:22 $\rightarrow$ Timestamp: Check if 3:14 AM aligns with an authorized maintenance window.

b)prod-api-01 > Hostname: The target system; our production backend API gateway.

c)Accepted publickey > Status/Mechanism: Login succeeded using an SSH key, bypassing password requirements.

d)ubuntu > User: The default administrative account; high-value target.

e)197.248.31.42 > Source IP: Resolves to Safaricom (Nairobi, Kenya). Expected, but verify ownership if off-hours.

3. **Windows Security Event Log (Active Directory & Servers)**
   
The 5 Essential Fields

EventID: The numeric identifier of the activity type (e.g., 4624, 4625).

TargetUserName: The account being accessed or manipulated.

LogonType: Crucial. Tells you how they connected (e.g., Type 2 = Interactive, Type 3 = Network, Type 10 = RDP).

IpAddress: The network origin of the request.

AuthenticationPackage: Identifies the protocol used (e.g., NTLM vs. Kerberos).

What "Normal" Looks Like:

EventID 4624 (Successful Logon) with Logon Type 3 (Network shares/API communication) inside the local network, or Logon Type 2/10 during daytime business hours originating from internal office subnets.

Top 3 Misuse Signatures

1)Log Clearance (Anti-Forensics): EventID 1102 generated when an administrative user clears the Security audit log.

a)1-Line Detection: EventID == 1102 (Set to immediate P1 critical alert).

1)Pass-the-Hash / Lateral Movement: EventID 4624 with Logon Type 3 using NTLM authentication instead of Kerberos, where the source address is an internal workstation.

a)1-Line Detection: EventID == 4624 AND LogonType == 3 AND AuthenticationPackage == "NTLM"

1)RDP Brute Force / Spraying: High frequency of EventID 4625 (Failed Logon) with Logon Type 10 followed by a single successful 4624 entry.

a)1-Line Detection: Count EventID == 4625 by TargetUserName and IpAddress where LogonType == 10.

**Real Sample Line**

EventID: 4624, Time: 2026-06-26T11:45:10, Account: Administrator, Logon Type: 10, Source IP: 41.89.22.10, Auth: Negotiate

a)EventID: 4624 > Action: Successful account authentication.

b)Account: Administrator > Target: Built-in local domain administrator account.

c)Logon Type: 10 > Logon Type: Remote Interactive (Someone is actively controlling an RDP desktop session).

d)41.89.22.10 > Source IP: Resolves to a public Kenyan university network range. High anomaly if corporate staff are not on-site there.

3. **HTTP Access Log (Nginx / Web Applications)**

The 6 Essential Fields

a)Remote IP: The client's internet address.

b)Timestamp: Exact time of the HTTP request.

c)Method & Path: The HTTP action (GET, POST) and URL destination.

d)Status Code: The server's response code (e.g., 200, 401, 404, 500).

e)Body Bytes Sent: Size of the payload returned to the client.

f)User-Agent: The browser string or automated tool signature.

What "Normal" Looks Like:

Standard GET and POST traffic targeting active application routes (/api/v1/dashboard), returning 200 OK or 302 Redirect statuses, utilizing standard modern browser User-Agents (Chrome, Safari, Firefox), with consistent response payload sizes.

Top 3 Misuse Signatures

1)Web Shell Execution: A POST request directed at a static file or asset directory (e.g., /static/uploads/) returning a 200 OK.

a)1-Line Detection: awk '$7 ~ /\.(php|py|sh|pl)$/ && $6 ~ /POST/' access.log

2)SQL Injection / Path Traversal Scanning: Inbound URL paths containing database commands or directory path symbols (../, UNION SELECT, etc/passwd).

a)1-Line Detection: egrep -i "(\.\.\/|select|union|concat)" access.log

3)Credential Stuffing / Enumeration: A sudden spike of thousands of POST requests targeting the login endpoint(/api/v1/auth/login) from a single IP returning 401 Unauthorized.

a)1-Line Detection: grep "/login" access.log | awk '{print $1, $9}' | sort | uniq -

**Real Sample Line**

102.219.208.5 - - [26/Jun/2026:12:01:45 +0300] "POST /api/v1/auth/login HTTP/1.1" 401 54 "-" "sqlmap/1.8.2"

a)102.219.208.5 > Remote IP: Public IP originating from an African cloud provider/hosting space.

b)POST /api/v1/auth/login > Request: Sending data directly to the application's authentication endpoint.

c)401 > Status Code: Unauthorized. The login attempt failed.
d)54 > Bytes Sent: Small response body, standard for an error message payload.
e)sqlmap/1.8.2 > User-Agent: Direct indicator of automated SQL injection exploitation tools. Instant true positive alert.
