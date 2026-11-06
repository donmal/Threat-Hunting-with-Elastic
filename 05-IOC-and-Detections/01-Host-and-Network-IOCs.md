# 01 – Host and Network Indicators of Compromise (IOCs)

## Executive Summary

Following the reconstruction of the observed execution sequence, a variety of host-based and network-based Indicators of Compromise (IOCs) were identified. These artifacts provide valuable forensic evidence that can be leveraged to investigate and detect similar suspicious activity across enterprise environments.

The attacker utilized a combination of phishing, PowerShell execution, remote payload retrieval, suspected command-and-control activity, and Active Directory reconnaissance tooling. Each stage generated observable artifacts within Windows Sysmon logs, Zeek network telemetry, and DNS activity.

This section consolidates those indicators into a structured reference for incident responders and threat hunters.

Indicators are assessed in the context of the investigation, distinguishing suspicious files and execution artifacts from legitimate system components and third-party infrastructure that may also have benign uses.

---

# Investigation Objectives

The objectives of this phase were to:

- Identify malicious files written to disk.
- Document suspicious processes and their associated execution context.
- Identify suspicious domains and IP addresses.
- Correlate host artifacts with network activity.
- Produce reusable Indicators of Compromise for future investigations.

---

# Host-Based Indicators

## Malicious Files

The following files were identified during the investigation as malicious, suspicious or associated with the investigated activity.

| File | Description |
|-------|-------------|
| invoice.one | Initial phishing document delivered to the victim. |
| invoice.bat | Batch file exported and executed by Microsoft OneNote. |
| default.exe | Primary payload downloaded during the attack. |
| svchost.exe (Temp) | Suspicious executable identified in a user-writable temporary directory: possible masquerading. |
| SharpHound.exe | Active Directory enumeration tool. |
| mimikatz.exe | Credential dumping utility executed with DCSync-related arguments. |
| DomainPasswordSpray.ps1 | PowerShell script associated with password spraying activity. |
| XceGuhkzarrQv.vbs | Suspicious VBScript artifact potentially associated with persistence: mechanism unconfirmed. |

The presence of a tool or script is not sufficient to establish that every supported capability was executed. File hashes, full paths and execution telemetry should be used to strengthen attribution of these artifacts to the investigated activity.

---

## Suspicious Processes

The investigation identified multiple processes associated with the suspicious execution sequence and subsequent post-exploitation activity.

| Process | Purpose |
|----------|----------|
| ONENOTE.EXE | Opened the phishing document. |
| OneNoteM.exe | Helper process spawned by Microsoft OneNote. |
| cmd.exe | Executed exported batch file. |
| powershell.exe | Executed commands associated with remote payload retrieval and execution. |
| default.exe | Primary attacker payload. |
| SharpHound.exe | Active Directory reconnaissance tooling. |
| mimikatz.exe | Attempted DCSync credential access. |

Legitimate Windows processes such as ONENOTE.EXE, cmd.exe and powershell.exe are not inherently malicious. Their investigative significance arises from the observed process relationships, command-line arguments and associated artifacts.

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

These execution locations are commonly abused because they allow malware to operate from user-writable directories while potentially executing without elevated privileges, depending on the permissions and actions involved.

The location of **svchost.exe** within a user's temporary directory is particularly noteworthy because legitimate Windows Service Host binaries normally reside in Windows system directories. However, the file's origin and behaviour must be examined before confirming masquerading.

---

# Network-Based Indicators

## Domains Associated with Suspicious Activity

The investigation identified several external services associated with the investigated execution and network activity.

| Domain | Purpose |
|----------|---------|
| file.io | Initial payload delivery. |
| pastebin.com | Remote PowerShell payload hosting. |
| ngrok.io | Ngrok tunneling infrastructure associated with suspected command-and-control activity. |

These are legitimate third-party services and should not be treated as universally malicious domains. Their significance depends on the observed URL paths, process associations, timestamps and surrounding network activity.

---

## IP Addresses

The following IP addresses were observed during the investigation.

| IP Address | Description |
|------------|-------------|
| 192.168.28.130 | Victim workstation (WS001). |
| 18.158.249.75 | file.io infrastructure. |
| 104.20.67.143 | pastebin.com infrastructure. |
| 3.125.102.39 | ngrok infrastructure. |

The victim's private IP address is an internal investigation reference rather than an external malicious indicator. The public IP addresses should be interpreted as infrastructure observed during the laboratory investigation, not as permanently malicious or exclusive to the attacker.

---

## DNS Indicators

DNS telemetry revealed repeated lookups associated with external services relevant to the investigated activity..

Observed domains included:

- file.io
- pastebin.com
- ngrok.io

The observed DNS requests provided evidence of domain resolution activity associated with payload delivery and suspected tunneling communications. DNS resolution alone did not confirm successful payload transfer, sustained command-and-control sessions or persistence.

---

## Network Behaviour

Observed network activity included:

- DNS lookups
- HTTPS connections
- Network activity associated with payload delivery
- PowerShell commands attempting remote content retrieval
- Ngrok-related encrypted communications potentially associated with C2

When correlated with the suspicious process execution sequence, these network indicators supported the assessment of a multi-stage intrusion. Individual network events were evaluated in context rather than treated as conclusive evidence of malicious activity on their own.

---

# Indicators of Compromise Summary

The following consolidated list provides a quick reference to the artifacts identified during the investigation. Entries include confirmed investigation artifacts as well as contextual indicators that require correlation before being used in operational detections.

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

Collectively, these host and network artifacts provide defenders with contextual indicators and potential detection opportunities across multiple stages of the intrusion lifecycle.

For operational use, detections should prioritize combinations of suspicious behaviour, process lineage, file paths and network activity rather than relying exclusively on filenames, shared service domains or public IP addresses.
