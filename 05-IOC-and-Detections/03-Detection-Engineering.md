# 03 – Detection Engineering

## Executive Summary

The Stuxbot investigation identified multiple opportunities where attacker activity could have been detected before the intrusion progressed to later stages of the attack lifecycle.

This section transforms the forensic findings collected throughout the investigation into actionable detection logic that can be implemented within Security Information and Event Management (SIEM) platforms, Endpoint Detection and Response (EDR) solutions, and Threat Hunting playbooks.

Rather than relying on static Indicators of Compromise (IOCs), these detections focus on attacker behavior and abnormal process relationships.

---

# Detection Strategy

The recommended detections are organized according to the attack lifecycle.

The highest-priority detections focus on:

- Suspicious process creation
- PowerShell execution
- Malicious command-line arguments
- DNS requests
- Active Directory reconnaissance
- Credential theft
- Persistence mechanisms

---

# Process Creation Detection

## OneNote spawning child processes

### Investigation Query

```text
event.code:1 AND process.parent.name:"ONENOTE.EXE"
```

### Why This Matters

Microsoft OneNote normally opens notebook content.

It should rarely create child processes such as:

- cmd.exe
- powershell.exe
- wscript.exe
- cscript.exe

Observed process chain:

```text
ONENOTE.EXE
        ↓
cmd.exe
        ↓
invoice.bat
        ↓
powershell.exe
```

This process relationship represents one of the strongest early indicators of compromise identified during the investigation.

---

# PowerShell Detection

## Investigation Query

```text
process.name:"powershell.exe"
```

PowerShell should be monitored for:

- Invoke-WebRequest
- DownloadString
- Invoke-Expression
- Encoded commands
- Remote script execution

Useful hunting queries:

```text
process.command_line:*Invoke-WebRequest*
```

```text
process.command_line:*DownloadString*
```

```text
process.command_line:*iex*
```

```text
process.command_line:*-enc*
```

---

# DNS Detection

Observed malicious domains:

- file.io
- pastebin.com
- ngrok.io

Investigation query:

```text
event.code:22
```

Recommended columns:

- dns.question.name
- process.name
- host.hostname
- user.name

Behavioral detections should prioritize repeated DNS requests associated with attacker-controlled infrastructure.

---

# Active Directory Enumeration Detection

## SharpHound

Detection query:

```text
process.name:"SharpHound.exe"
```

SharpHound execution should generally be considered highly suspicious within enterprise environments.

Recommended investigation:

- Identify the parent process.
- Determine the execution path.
- Correlate with PowerShell activity.
- Review network communications.

---

# PowerView Detection

PowerShell Script Block Logging query:

```text
powershell.file.script_block_text:*Invoke-ShareFinder*
```

Alternative:

```text
powershell.file.script_block_text:*Get-NetShare*
```

These commands frequently indicate internal Active Directory reconnaissance.

---

# Credential Access Detection

## Mimikatz

Investigation query:

```text
process.name:"mimikatz.exe"
```

Additional hunting queries:

```text
process.command_line:*sekurlsa*
```

```text
process.command_line:*lsadump*
```

```text
process.command_line:*dcsync*
```

The presence of Mimikatz should always be treated as a high-confidence indicator of malicious activity.

---

# Persistence Detection

Observed persistence artifact:

```text
XceGuhkzaTr0y.vbs
```

Detection queries:

```text
file.name:*.vbs
```

Alternative:

```text
process.command_line:*.vbs
```

Randomized VBScript files executing from user directories should be investigated immediately.

---

# Detection Priorities

## High Severity

- Mimikatz execution
- SharpHound execution
- PowerView execution
- DCSync activity
- PowerShell Invoke-WebRequest
- PowerShell DownloadString
- PowerShell Invoke-Expression

---

## Medium Severity

- OneNote spawning cmd.exe
- OneNote spawning PowerShell
- Pastebin access
- Ngrok communications
- Randomized VBScript execution

---

## Low Severity

- file.io DNS requests
- Unusual outbound DNS activity
- Temporary directory executable creation

---

# Behavioral Detection Recommendations

Detection rules should prioritize:

- Parent-child process relationships
- PowerShell command-line arguments
- Script Block Logging
- DNS behavior
- Active Directory enumeration
- Credential access tooling
- Persistence mechanisms

Behavior-based detections provide significantly greater resilience than static IOCs, as attacker infrastructure such as IP addresses and domains may change over time.

---

# SOC Analyst Recommendations

Recommended response actions include:

- Isolate affected hosts.
- Acquire volatile memory when possible.
- Block attacker-controlled domains.
- Reset privileged credentials.
- Review Active Directory replication permissions.
- Hunt for similar process chains across the environment.
- Correlate endpoint and network telemetry.

---

# Phase Summary

The investigation identified multiple opportunities where attacker activity could have been detected before domain-level compromise occurred.

The recommended detection logic emphasizes attacker behavior rather than static indicators, enabling defenders to identify similar intrusions even when adversaries modify their infrastructure or malware payloads.

These recommendations can be directly incorporated into enterprise SIEM alerting, threat hunting playbooks, and detection engineering workflows.