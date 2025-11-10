# Windows-Security-Event-Log-Analysis-using-Splunk
Perform detailed analysis of Windows Security Event Logs using Splunk to monitor user logon behavior, detect suspicious activities, and , privilege escalation, or log tampering.  This project demonstrates core SOC Analyst capabilities — log ingestion, event correlation, alert creation, and dashboard visualization.


Project Title:
Windows Security Event Log Analysis using Splunk
🎯 Objective

Perform detailed analysis of Windows Security Event Logs using Splunk to monitor user logon behavior, detect suspicious activities, and identify potential security incidents such as brute-force attempts, privilege escalation, or log tampering.

This project demonstrates core SOC Analyst capabilities — log ingestion, event correlation, alert creation, and dashboard visualization.

⚙️ Environment Setup
-Component	Description
-Operating System	Windows 10 / 11
-SIEM Tool	Splunk Free Edition
-Log Source	Windows Event Viewer → Security Logs
=Index Name	moniter
=Source Type	WinEventLog:Security
-Host	DESKTOP-R8E33U0
-Event IDs Used	4624, 4625, 4634, 4672, 4648, 1102

🧠 Event Codes and Purpose
Event ID	Meaning	Detection Use
-4624	Successful Logon	Track normal user and system logins
-4625	Failed Logon	Detect brute-force or password spraying
-4634	Logoff	Monitor session activity
-4672	Special Privileges Assigned	Identify privilege escalation
-4648	Logon Using Explicit Credentials	Detect lateral movement
-1102	Audit Log Cleared	Detect log tampering or cover-up attempts

🔍 Splunk Searches Used
-Which accounts log in most
-What Logon_Type they use
-How often accounts log in or out
-Whether logins happen at unusual hours
-Which hosts are active

✅ Step 1: Analyze Login Frequency by User

index=moniter source="WinEventLog:Security" EventCode=4624
| stats count by Account_Name
| sort - count


Goal: Identify most active users or system accounts.
SOC insight: A normal user shouldn’t have hundreds of daily logons — if so, it might be malware or a looping service.

✅ Step 2: Analyze Logon Types

index=moniter source="WinEventLog:Security" EventCode=4624
| stats count by Logon_Type

Logon Type	Meaning	Example:
2	Interactive	Local console login
3	Network	File share
5	Service	Windows services
7	Unlock	Screen unlock
10	Remote Interactive	RDP

SOC insight: If you mainly see Type 2 or 7 → normal local use.
If Type 10 suddenly appears → someone used RDP (remote access).

✅ Step 3: Detect Logins at Unusual Hours

index=moniter source="WinEventLog:Security" EventCode=4624
| eval hour=strftime(_time,"%H")
| stats count by Account_Name, hour
| sort hour


SOC insight: Normal work hours are 08–18.
If logins occur at 02:00 AM, that’s suspicious — insider activity or persistence.

✅ Step 4: Correlate Logon (4624) with Logoff (4634)

index=moniter source="WinEventLog:Security" (EventCode=4624 OR EventCode=4634)
| eval action=if(EventCode=4624,"Logon","Logoff")
| stats earliest(_time) as first latest(_time) as last by Account_Name, action


SOC insight: Accounts that log on but never log off might be running as hidden background sessions.

✅ Step 5: Detect Privilege Escalation (Event 4672)

index=moniter source="WinEventLog:Security" EventCode=4672
| table _time, Account_Name, Privileges


SOC insight: 4672 appears when a user gets special privileges (Admin, SYSTEM).
If it happens soon after a 4624 logon → possible privilege escalation.

✅ Step 6: Find New or Rarely Used Accounts

index=moniter source="WinEventLog:Security" EventCode=4624
| stats earliest(_time) as first_login latest(_time) as last_login by Account_Name
| eval days_active = round((last_login - first_login)/86400,1)
| where days_active < 1

✅Logon/Logoff Tracking (Timeline Analysis)

Tracking logon and logoff patterns helps identify users who remain logged in for long periods or sessions active during off-hours — a common sign of persistence or insider misuse.

🔹 Query: Logon vs Logoff Timeline

index=moniter source="WinEventLog:Security" (EventCode=4624 OR EventCode=4634)
| eval action=if(EventCode=4624,"Logon","Logoff")
| timechart count by action span=1h




-Consistent interactive logons (Type 2) — normal user behavior.
-Few failed login attempts (Event 4625) — minimal brute-force risk.
-No remote (Type 10) logons detected — system not accessed via RDP.
-Privilege escalation (Event 4672) observed only by Administrator — legitimate.
-No log clearing (Event 1102) — logs intact, indicating secure environment
