# 01 – Host and Network Indicators of Compromise (IOCs)

## Executive Summary

Following the reconstruction of the execution chain, a variety of host-based and network-based Indicators of Compromise (IOCs) were identified. These artifacts provide valuable forensic evidence that can be leveraged to detect similar attacks across enterprise environments.

The attacker utilized a combination of phishing, PowerShell execution, remote payload retrieval, command-and-control communications, and Active Directory reconnaissance. Each stage generated observable artifacts within Windows Sysmon logs, Zeek network telemetry, and DNS activity.

This section consolidates those indicators into a structured reference for incident responders and threat hunters.

---

# Investigation Objectives

The objectives of this phase were to:

- Identify malicious files written to disk.
- Document malicious processes.
- Identify suspicious domains and IP addresses.
- Correlate host artifacts with network activity.
- Produce reusable Indicators of Compromise for future investigations.

---

# Host-Based Indicators

## Malicious Files

The following files were identified during the investigation as malicious or directly associated with attacker activity.

| File | Description |
|-------|-------------|
| invoice.one | Initial phishing document delivered to the victim. |
| invoice.bat | Batch file exported and executed by Microsoft OneNote. |
| default.exe | Primary payload downloaded during the attack. |
| svchost.exe (Temp) | Renamed payload executed from the user's temporary directory. |
| SharpHound.exe | Active Directory enumeration tool. |
| mimikatz.exe | Credential dumping utility used for DCSync operations. |
| DomainPasswordSpray.ps1 | PowerShell script associated with password spraying activity. |
| XceGuhkzarrQv.vbs | Malicious VBScript associated with persistence. |

---

## Suspicious Processes

The investigation identified multiple malicious process executions.

| Process | Purpose |
|----------|----------|
| ONENOTE.EXE | Opened the phishing document. |
| OneNoteM.exe | Helper process spawned by Microsoft OneNote. |
| cmd.exe | Executed exported batch file. |
| powershell.exe | Retrieved and executed remote payloads. |
| default.exe | Primary attacker payload. |
| SharpHound.exe | Active Directory reconnaissance. |
| mimikatz.exe | Credential theft and DCSync. |

---

## File System Artifacts

Several suspicious execution paths were identified.

```text
C:\Users\bob\Downloads\invoice.one
C:\Users\bob\AppData\Local\Temp\OneNote\16.0\Exported\...\invoice.bat
C:\Users\bob\AppData\Local\Temp\default.exe
C:\Users\bob\AppData\Local\Temp\svchost.exe
C:\Users\Public\DomainPasswordSpray.ps1
C:\Users\svc-sql\AppData\Local\Temp\XceGuhkzarrQv.vbs
```

These execution locations are commonly abused because they allow malware to operate from user-writable directories while avoiding administrative privileges.

---

# Network-Based Indicators

## Malicious Domains

The investigation identified several external services used by the attacker.

| Domain | Purpose |
|----------|---------|
| file.io | Initial payload delivery. |
| pastebin.com | Remote PowerShell payload hosting. |
| ngrok.io | Command-and-Control infrastructure. |

---

## IP Addresses

The following IP addresses were observed during the investigation.

| IP Address | Description |
|------------|-------------|
| 192.168.28.130 | Victim workstation (WS001). |
| 18.158.249.75 | file.io infrastructure. |
| 104.20.67.143 | pastebin.com infrastructure. |
| 3.125.102.39 | ngrok infrastructure. |

---

## DNS Indicators

DNS telemetry revealed repeated lookups associated with attacker-controlled infrastructure.

Observed domains included:

- file.io
- pastebin.com
- ngrok.io

Repeated DNS resolution requests were consistent with payload retrieval and persistent command-and-control communications.

---

## Network Behaviour

Observed network activity included:

- DNS lookups
- HTTPS connections
- Payload downloads
- Remote PowerShell retrieval
- Encrypted C2 communications

These behaviours collectively indicate an active malware infection rather than isolated malicious events.

---

# Indicators of Compromise Summary

## Files

- invoice.one
- invoice.bat
- default.exe
- svchost.exe
- SharpHound.exe
- mimikatz.exe
- DomainPasswordSpray.ps1
- XceGuhkzarrQv.vbs

---

## Processes

- ONENOTE.EXE
- OneNoteM.exe
- cmd.exe
- powershell.exe
- default.exe
- SharpHound.exe
- mimikatz.exe

---

## Domains

- file.io
- pastebin.com
- ngrok.io

---

## IP Addresses

- 18.158.249.75
- 104.20.67.143
- 3.125.102.39

---

# Defensive Value

The indicators documented in this phase can be integrated into:

- SIEM detection rules
- Endpoint Detection and Response (EDR) platforms
- Threat Hunting playbooks
- Network intrusion detection systems
- Incident response procedures

Collectively, these host and network artifacts provide defenders with reliable detection opportunities across multiple stages of the intrusion lifecycle.