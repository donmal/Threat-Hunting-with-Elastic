# 06 – Lessons Learned & Defensive Recommendations

## Executive Summary

The Stuxbot investigation demonstrated how a seemingly harmless phishing document can rapidly evolve into multistage-stage intrusion involving endpoint execution, payload delivery, persistence, credential access, and Active Directory-related activity.
The investigation covered:

•	Initial Access

•	User Execution

•	PowerShell Abuse

•	Payload Delivery

•	Persistence

•	Credential Access

•	Active Directory Enumeration

•	Command & Control Communications

This document summarizes the key lessons learned during the investigation and provides practical recommendations for improving detection, response, and prevention capabilities.
The purpose of this section is not to identify new evidence but to answer the question:
"What should defenders learn from this incident so that the next attack is detected earlier or prevented entirely?"

The recommendations below are derived from artifacts and telemetry examined during the Hack The Box Academy investigation. They represent defensive improvements informed by the observed attack chain rather than controls independently validated in a production environment.

## Investigation Timeline Overview

The attack chain unfolded as follows:

invoice.one
        ↓
ONENOTE.EXE
        ↓
OneNoteM.exe
        ↓
cmd.exe
        ↓
invoice.bat
        ↓
powershell.exe
        ↓
Pastebin Payload
        ↓
default.exe
        ↓
Ngrok C2
        ↓
SharpHound
        ↓
Mimikatz
        ↓
DCSync

This sequence summarizes the principal execution and post-exploitation stages identified during the investigation. It should be interpreted as a high-level reconstruction rather than proof that every artifact formed a direct parent-child process relationship.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 1 – Complete Stuxbot attack chain reconstructed during the investigation.

## Lesson 1 – User Execution Remains One of the Biggest Risks

The entire compromise started because a user interacted with a malicious file.
Artifact:
invoice.one
Although modern security products provide protection against malicious attachments, attackers continue to abuse:
•	Microsoft Office files
•	OneNote files
•	PDF files
•	Archives
•	Cloud-hosted downloads

These formats can be used to deliver malicious content, socially engineer users, or evade insufficiently configured attachment inspection controls.

# Why This Matters
The attack required:

The initial execution sequence demonstrated that user interaction with an untrusted document could initiate a chain of suspicious processes without requiring evidence of software vulnerability exploitation.

# Security Recommendation

Implement:
User Awareness Training
Teach users to identify:
•	Unexpected invoices
•	Payment requests
•	OneNote attachments
•	Cloud-hosted downloads

# Email Security Controls

Deploy:
•	Attachment Sandboxing
•	URL Rewriting
•	Attachment Detonation
•	Threat Intelligence Enrichment

Prioritize attachment inspection and user-execution controls capable of detecting embedded scripts and suspicious child-process creation, rather than relying exclusively on file extensions or known malicious hashes.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 2 – Initial phishing document observed during the investigation.

## Lesson 2 – OneNote Can Be Abused for Malware Delivery

The attack leveraged:
invoice.one
as the delivery mechanism.
Historically, defenders focused heavily on:
DOCM

XLSM

PDF

The observed OneNote execution demonstrates why monitoring should extend beyond traditional Office macro-enabled documents to include unusual execution behavior associated with note-taking applications.

# Detection Opportunity

Monitor:
ONENOTE.EXE
launching:
cmd.exe

powershell.exe

wscript.exe

cscript.exe

# Recommended Detection

event.code:1 AND process.parent.name:"ONENOTE.EXE"

# Why This Is High Fidelity

OneNote spawning command interpreters or scripting engines is an unusual parent-child process relationship that warrants investigation, particularly when associated with recently downloaded documents or subsequent network activity. The query is a hunting starting point, not a standalone high-fidelity detection rule.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 3 – OneNote spawning suspicious child processes.

## Lesson 3 – Process Chains Reveal the Entire Story

A single event rarely explains an intrusion.
The attack became obvious only after correlating:
Process Creation

File Creation

DNS Queries

Network Connections

# Critical Process Chain

ONENOTE.EXE
        ↓
cmd.exe
        ↓
invoice.bat
        ↓
powershell.exe

The chain above is a simplified representation of the execution flow. The exact parent-child relationships and command-line arguments should be validated against Sysmon process creation events.

# SOC Analyst Takeaway

Always investigate:
Parent Process
Who started this?
Child Process
What did it start?

Correlate process identifiers, parent-process identifiers, timestamps, command-line arguments, file paths, and network activity to reconstruct execution sequences and distinguish legitimate administrative behavior from suspicious activity.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 4 – Parent-child process relationship analysis.

## Lesson 4 – PowerShell Remains a Primary Attack Vector

PowerShell played a central role in the compromise.
Observed behavior included:
Remote Downloads

Script Execution

Memory Execution

Network Communications

# Why Attackers Prefer PowerShell

PowerShell:
•	Exists on many Windows endpoints and servers.
•	Is trusted by administrators.
•	Can execute code directly in memory.
•	Can be abused to execute malicious commands while blending with legitimate administrative activity.

# Example Behavior Observed

Download → Execute
from:
pastebin.com

The investigation identified PowerShell-based retrieval and execution behavior associated with externally hosted content. Such activity becomes more suspicious when correlated with unusual parent processes, encoded commands, or unexpected outbound connections.

# Detection Recommendations

Monitor:
process.command_line:*DownloadString*
and
process.command_line:*Invoke-WebRequest*

These indicators should be combined with PowerShell Script Block Logging (Event ID 4104), process ancestry, user context, and network telemetry to reduce false positives and improve detection confidence.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 5 – Malicious PowerShell execution.

## Lesson 5 – Public Services Are Frequently Abused

The attackers leveraged legitimate platforms:
Pastebin
file.io
ngrok

# Why This Matters

Blocking known malware domains is relatively easy.
Blocking legitimate services is significantly harder.

These services may also support legitimate workflows, making behavioral context essential when determining whether their use represents malicious activity.

# Observed Usage

file.io
Used for:
Payload Delivery

# Pastebin

Used for:
Script Hosting

# Ngrok

Used for:
Command & Control

The investigation highlighted how publicly accessible services can support different stages of an intrusion without requiring attacker-owned infrastructure for every operation.

# Defensive Recommendation

Correlate access to file-sharing, paste-hosting, and tunneling services with endpoint execution telemetry, downloaded file artifacts, unusual process activity, and destination reputation. Apply service restrictions according to organizational requirements rather than indiscriminately blocking every public platform.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 6 – Legitimate services abused during the attack.

## Lesson 6 – DNS Is Extremely Valuable

DNS logs were instrumental throughout the investigation.
Without DNS telemetry:
file.io

pastebin.com

ngrok.io
might never have been identified.

# Why DNS Hunting Works

DNS telemetry can reveal domain resolution attempts associated with payload delivery, external script hosting, and command-and-control infrastructure. However, not every network connection generates an observable DNS query, particularly when cached results, direct IP connections, or encrypted DNS are involved.

# SOC Recommendation

Retain DNS telemetry according to organizational risk, investigative requirements, storage capacity, and applicable retention policies. A 90–180-day retention window may provide a useful starting point where operationally and legally appropriate.

# Detection Examples

dns.question.name:*ngrok.io*
dns.question.name:*file.io*
dns.question.name:*pastebin*

Validate field mappings and wildcard syntax against the deployed Elastic index configuration. Domain matches should be correlated with the initiating process and surrounding network activity before being classified as malicious.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 7 – DNS evidence supporting attacker infrastructure discovery.

## Lesson 7 – Command & Control Can Hide in Plain Sight

The attacker leveraged:
ngrok.io
for command-and-control operations.

# Why This Is Effective

Traffic appeared as:
HTTPS
Port 443
Encrypted
which resembles normal internet activity.

Encrypted tunneling services can make malicious communications harder to distinguish from legitimate HTTPS traffic when detection relies primarily on destination ports or protocol identification.

# Defensive Recommendation

Monitor:
•	Tunneling Services
•	Dynamic DNS Services
•	Rare Domains
•	Newly Registered Domains

# Examples

ngrok.io

trycloudflare.com

serveo.net

localtunnel.me

These domains are examples of tunneling services and should not automatically be classified as malicious. Detection should prioritize unauthorized tunnel creation, unusual outbound connections, unexpected process-to-network relationships, and connections inconsistent with established endpoint behavior.

# SOC Analyst Takeaway

Correlating Sysmon network connection events with DNS telemetry and process execution records can help identify suspicious tunneling activity even when the contents of the network traffic are encrypted.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 8 – Command-and-control communications identified through ngrok.

## Lesson 8 – Persistence Often Uses Simple Mechanisms

The investigation identified:
XceGuhkzaTr0y.vbs
as a persistence-related artifact.

The presence of this VBScript artifact warranted further investigation into its execution context, file location, and potential relationship with persistence mechanisms.

# Why Attackers Use Scripts

Scripts are:
•	Small
•	Flexible
•	Easy to modify

Capable of executing through legitimate Windows scripting engines, potentially allowing malicious behavior to blend with routine system activity.

# Defensive Recommendation

Monitor:
.vbs

.js

.hta

.ps1
files created within:
Temp

Public

Downloads

Startup
directories.

Extend monitoring to scheduled tasks, Run/RunOnce registry keys, Startup folder modifications, and suspicious execution through **wscript.exe** or **cscript.exe**.

File creation alone does not confirm persistence. Analysts should establish whether the artifact was configured to execute automatically through a persistence mechanism.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 9 – Persistence artifact identified during investigation.

## Lesson 9 – Active Directory Is the Ultimate Target

The attack progressed beyond initial compromise.

The adversary eventually deployed:

SharpHound.exe

mimikatz.exe

# What This Means

The attacker moved from:

Initial Access

Credential Access

Domain Reconnaissance

The presence of SharpHound and Mimikatz indicated a shift toward Active Directory reconnaissance and credential-focused post-exploitation activity. Their execution is consistent with attempts to identify privileged relationships, enumerate domain resources, and access sensitive authentication material.

# Why This Matters

The objective was no longer a single workstation.

The activity suggested that the attacker was attempting to extend access beyond the initially compromised endpoint and potentially target domain-level privileges.

# Defensive Recommendation

Monitor unexpected Active Directory enumeration, privileged account activity, suspicious access to LSASS, and execution of known credential-access or reconnaissance tooling. Correlate endpoint evidence with domain controller security events to determine the scope of attempted or successful compromise.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 10 – Active Directory reconnaissance using SharpHound.

## Lesson 10 – DCSync Is a Critical Alert

The investigation confirmed:
DCSync Activity
through Mimikatz.

The investigation identified evidence associated with Mimikatz and DCSync-related activity, highlighting the potential risk of Active Directory replication abuse. Confirmation of successful credential replication should be supported by the relevant command output or domain controller telemetry.

# Why DCSync Is Dangerous

DCSync allows attackers to retrieve:
Password Hashes

KRBTGT Hash

Domain Admin Credentials

An attacker with sufficient directory replication privileges can request password-related secrets from a domain controller remotely, without requiring an interactive logon to the domain controller itself.

# Security Recommendation

Immediately investigate:
Replication Requests

Mimikatz Usage

Directory Replication Permissions

Prioritize investigation of Windows Security Event ID 4662 where appropriate auditing is enabled, particularly replication-related access by unexpected accounts. Review the permissions **DS-Replication-Get-Changes** and **DS-Replication-Get-Changes-All**, and distinguish legitimate replication activity from unauthorized requests.

# Incident Response Considerations

Where unauthorized DCSync activity is confirmed, treat the incident as a potential domain-level credential compromise. Scope affected accounts, review replication privileges, contain attacker access, and follow an appropriate credential recovery process. KRBTGT password resets may be necessary in confirmed compromise scenarios and should follow a carefully coordinated recovery procedure.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 11 – Credential theft activity identified through Mimikatz.

## Lesson 11 – Multiple Log Sources Are Essential

This investigation required:
Sysmon

Windows Logs

PowerShell Logs

Zeek Logs
working together.

# What Each Source Contributed

Source	Contribution
Sysmon	Processes, Files, DNS, Network
Windows Logs	Host Activity
PowerShell Logs	Script Visibility
Zeek	Network Visibility

Each telemetry source provided a different investigative perspective. Sysmon supported endpoint process and file analysis, Windows Security logs provided relevant operating system and authentication activity, PowerShell logs exposed script execution details, and Zeek contributed network-level observations.

# Key Observation

No single log source contained the entire story.
Only correlation provided the complete picture.

Correlating endpoint and network telemetry made it possible to connect suspicious document execution with subsequent script activity, external communications, and post-exploitation behavior.

# SOC Analyst Takeaway

Effective threat hunting requires understanding the visibility and limitations of each log source. Analysts should use timestamps, host identifiers, process relationships, destination addresses, and user context to validate findings across multiple sources rather than relying on isolated events.

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 12 – Multi-source correlation throughout the investigation.

## Lesson 12 – Threat Hunting Beats Reactive Detection

Many stages of the attack:
PowerShell

Ngrok

SharpHound

Mimikatz
were discovered through hunting rather than alerts.

The investigation demonstrated the value of hypothesis-driven analysis when reconstructing suspicious activity from available telemetry, including behaviors that may not be covered by existing detection rules.

# Why Hunting Matters

Threat hunting identifies:
Unknown Threats

Missed Alerts

Stealthy Activity

Threat hunting can uncover previously undetected activity and improve detection coverage. However, its effectiveness depends on telemetry availability, investigative methodology, and the stage at which suspicious behavior is discovered.

# SOC Recommendation

Conduct recurring hunts focused on:
PowerShell Abuse
Credential Access
AD Enumeration
Tunneling Services
Rare Parent-Child Process Relationships

# Detection Engineering Opportunities

The investigation provides several opportunities to translate hunting findings into reusable detection logic:

- Identify OneNote spawning command interpreters or scripting engines.
- Detect suspicious PowerShell download-and-execute patterns.
- Correlate access to public tunneling services with unusual endpoint processes.
- Identify unexpected execution of Active Directory reconnaissance tools.
- Monitor suspicious credential access and directory replication behavior.


These detections should be tested against representative benign and malicious activity, tuned to reduce false positives, and documented with clear investigation and escalation procedures.

# Security Improvements Recommended

# Immediate Actions

- Reset Compromised Credentials
- Audit Domain Admin Accounts
- Investigate and contain endpoints associated with confirmed malicious activity.
- Review connections to ngrok, file.io, and Pastebin, applying targeted restrictions where justified.
- Revoke compromised sessions and reset affected credentials where compromise is confirmed.
- Review privileged accounts, Active Directory replication permissions, and suspicious authentication events.
- Preserve relevant endpoint and network evidence to support incident scoping and response.

Immediate containment actions should be based on confirmed findings and the assessed scope of compromise, rather than indiscriminately blocking services that may have legitimate organizational uses.

# Medium-Term Actions

Enable PowerShell Script Block Logging

Enable Sysmon DNS Logging

Improve Threat Intelligence Integration

Create Detection Rules

# Long-Term Actions

Deploy EDR

Implement Threat Hunting Program

Improve Security Awareness Training

Conduct Purple Team Exercises

## Key Takeaways

What Worked Well
✓ Sysmon logging
✓ DNS visibility
✓ Zeek telemetry
✓ Process correlation
✓ PowerShell logging

These telemetry sources supported the reconstruction of the attack sequence and demonstrated the investigative value of combining endpoint and network evidence.

## What Could Be Improved

✓ Earlier detection of OneNote abuse
✓ Earlier detection of PowerShell activity
✓ Earlier detection of Ngrok communications
✓ Better monitoring of credential theft activity

These improvements represent potential detection and monitoring opportunities identified during the investigation, rather than verified weaknesses in a production security environment.

# Additional Investigative Lessons

- **Evidence correlation**: Individual indicators become more meaningful when linked through process ancestry, timestamps, and network activity.
  
- **Detection context**: Legitimate administrative tools and public services require behavioral analysis before being classified as malicious
 
-**Visibility limitations**: The absence of a log event does not necessarily establish that an activity did not occur.

-**Evidence confidence**: Analysts should distinguish observed execution, suspected attacker objectives, and confirmed compromise outcomes.

-**Detection development**: Investigation findings can inform reusable detection rules and improve future SOC workflows.

## Final Conclusions

The Stuxbot investigation demonstrates how a modern intrusion can progress from a simple phishing attachment to advanced post-exploitation activity involving Active Directory reconnaissance and credential-access techniques.

The attack successfully leveraged:

•	User execution
•	PowerShell
•	Public cloud services
•	Tunneling infrastructure
•	Credential theft tooling

to establish persistence, maintain command-and-control access, and onduct activity consistent with attempts to obtain broader access within the Active Directory environment.

The most important lesson is that successful detection was achieved not through a single alert, but through the correlation of host telemetry, network visibility, PowerShell logs, DNS activity, and threat hunting methodology.

Organizations that combine these data sources and continuously hunt for anomalous behavior will be significantly more capable of detecting and stopping similar attacks in the future.

From a SOC analyst perspective, this investigation reinforced the importance of evidence-based analysis, understanding telemetry limitations, reconstructing attacker behavior across multiple data sources, and translating investigative findings into actionable detection and response recommendations.

The resulting lessons provide a practical foundation for improving threat hunting methodology, detection engineering, and incident response readiness against similar multi-stage intrusions.

