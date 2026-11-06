# 03 – Detection Engineering

## Executive Summary

The Stuxbot investigation identified multiple opportunities where attacker activity could have been detected at different stages of the intrusion lifecycle.

This section transforms the forensic findings collected throughout the investigation into actionable detection logic that can be implemented within Security Information and Event Management (SIEM) platforms, Endpoint Detection and Response (EDR) solutions, and Threat Hunting playbooks.

Rather than relying on static Indicators of Compromise (IOCs), these detections focus on attacker behavior and abnormal process relationships.

The proposed detection logic is based on observed attack artifacts, including suspicious process execution, PowerShell activity, DNS communications, Active Directory reconnaissance, credential access attempts, and persistence mechanisms. The queries represent candidate hunting and detection logic rather than fully tested production detection rules.

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

Detection opportunities were derived by correlating endpoint telemetry, process command lines, PowerShell Script Block Logging, and network-related events collected during the investigation.

---

# Process Creation Detection

## OneNote spawning child processes

### Investigation Query

```text
event.code:1 AND process.parent.name:"ONENOTE.EXE"
```

### Detection Rationale and Findings

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
The investigation identified a suspicious execution sequence originating from Microsoft OneNote, followed by batch-file and PowerShell activity. The process relationship provides an opportunity for early-stage detection of malicious document execution.

This process relationship represents one of the strongest early indicators of compromise identified during the investigation.

Detection logic should prioritize unusual OneNote child processes, particularly command interpreters and scripting engines, while correlating process creation events with command-line arguments and subsequent network activity.

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
The investigation identified PowerShell execution involving the retrieval and execution of remote script content. The observed use of iex and iwr provided evidence of a download-and-execute technique.

The additional queries extend detection coverage to related PowerShell execution techniques; they do not imply that every listed technique was observed during the intrusion.

PowerShell detections should correlate suspicious command-line arguments with parent processes, network destinations, and Script Block Logging to reduce false positives.


---

# DNS Detection

Observed malicious domains:

- file.io
- pastebin.com
- ngrok.io

These domains were identified in the investigation context. Because they can also support legitimate activity, their presence alone does not establish malicious intent.

Investigation query:

```text
event.code:22
```

Recommended columns:

- dns.question.name
- process.name
- host.hostname
- user.name

Detection logic should correlate DNS requests involving the identified services with suspicious process activity, unusual outbound connections, and the execution timeline. Repeated DNS requests alone are insufficient to confirm attacker-controlled communications.

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

SharpHound activity was identified during the post-exploitation investigation, providing evidence of Active Directory enumeration. Detection opportunities include identifying the executable, examining its execution context, and correlating its activity with other reconnaissance artifacts.

Because executable names can be changed, process-name matching should be supplemented with command-line, file, and behavioral telemetry.

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

PowerShell Script Block Logging exposed reconnaissance-related activity during the investigation. The queries above provide candidate detection logic for identifying PowerView network share enumeration functions.

Matches should be reviewed in context, as similar enumeration commands may also be used during legitimate administrative or security assessment activities.

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

The investigation identified Mimikatz execution with command-line arguments associated with an attempted DCSync operation. The lsadump and dcsync patterns provide relevant hunting opportunities, while sekurlsa represents an additional credential-access detection opportunity not confirmed by the observed command.

Mimikatz-related execution should be prioritized for investigation, particularly when associated with unauthorized credential access activity. However, process-name matching alone is insufficient to establish malicious intent or confirm successful credential extraction.

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

The investigation identified a suspicious VBScript artifact, **XceGuhkzaTr0y.vbs**, associated with the persistence phase of the intrusion. Its randomized filename provided an investigative lead for examining script-based activity.

The queries above can identify VBScript files and references to VBScript execution. However, they are broad hunting filters and do not independently confirm persistence.

To strengthen detection confidence, script activity should be correlated with persistence-related artifacts, including scheduled tasks, registry autorun entries, startup folders, and repeated execution following user logon or system restart.

---

# Detection Priorities

Detection priorities were proposed based on the observed attack behaviors and their potential security impact. These classifications are illustrative and would require validation and tuning before production deployment.

## High Severity

- Mimikatz execution
- SharpHound execution
- PowerView execution
- DCSync activity
- PowerShell Invoke-WebRequest
- PowerShell DownloadString
- PowerShell Invoke-Expression
- PowerShell downloading and immediately executing remote scripts in a suspicious process context
- Pastebin access associated with suspicious PowerShell execution at different stages of the observed intrusion

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

The resulting hunting queries and detection recommendations provide a foundation for developing SIEM alerts, EDR detection logic, and threat hunting playbooks. Before production deployment, these detections would require validation against representative telemetry, false-positive analysis, and environment-specific tuning.

This phase demonstrates how forensic findings from the Stuxbot investigation can be translated into practical detection opportunities across process execution, PowerShell activity, network communications, Active Directory reconnaissance, credential access, and persistence.
