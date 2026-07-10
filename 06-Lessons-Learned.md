# 06 – Lessons Learned & Defensive Recommendations

## Executive Summary

The Stuxbot investigation demonstrated how a seemingly harmless phishing document can rapidly evolve into a full compromise involving:
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
to bypass traditional controls.

# Why This Matters
The attack required:
One user
One click
One file
to begin the compromise.
No exploit was necessary.

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
but attackers increasingly use:
OneNote
to evade controls.

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

OneNote rarely needs to launch command interpreters.
Such behavior should be treated as suspicious.

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

# SOC Analyst Takeaway

Always investigate:
Parent Process
Who started this?
Child Process
What did it start?

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
•	Exists on every Windows system.
•	Is trusted by administrators.
•	Can execute code directly in memory.
•	Frequently bypasses traditional AV solutions.

# Example Behavior Observed

Download → Execute
from:
pastebin.com

# Detection Recommendations

Monitor:
process.command_line:*DownloadString*
and
process.command_line:*Invoke-WebRequest*

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

Attackers must:
Resolve Domain
Before
Connecting To Domain
in most scenarios.

# SOC Recommendation

Retain DNS logs for:
90–180 Days
minimum.

# Detection Examples

dns.question.name:*ngrok.io*
dns.question.name:*file.io*
dns.question.name:*pastebin*

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

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 8 – Command-and-control communications identified through ngrok.

## Lesson 8 – Persistence Often Uses Simple Mechanisms

The investigation identified:
XceGuhkzaTr0y.vbs
as a persistence-related artifact.

# Why Attackers Use Scripts

Scripts are:
•	Small
•	Flexible
•	Easy to modify
•	Less likely to trigger signatures

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

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 9 – Persistence artifact identified during investigation.

## Lesson 9 – Active Directory Is the Ultimate Target

The attack progressed beyond initial compromise.
The adversary eventually deployed:
SharpHound.exe
and
mimikatz.exe

# What This Means

The attacker moved from:
Initial Access
to
Privilege Escalation

Credential Access

Domain Reconnaissance

# Why This Matters

The objective was no longer a single workstation.
The objective became:
The Entire Domain

# Screenshot Placeholder

Insert Screenshot Here
Caption:
Figure 10 – Active Directory reconnaissance using SharpHound.

## Lesson 10 – DCSync Is a Critical Alert

The investigation confirmed:
DCSync Activity
through Mimikatz.

# Why DCSync Is Dangerous

DCSync allows attackers to retrieve:
Password Hashes

KRBTGT Hash

Domain Admin Credentials
without directly accessing a Domain Controller.

# Security Recommendation

Immediately investigate:
Replication Requests

Mimikatz Usage

Directory Replication Permissions

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

# Key Observation

No single log source contained the entire story.
Only correlation provided the complete picture.

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

# Why Hunting Matters

Threat hunting identifies:
Unknown Threats

Missed Alerts

Stealthy Activity
before major damage occurs.

# SOC Recommendation

Conduct recurring hunts focused on:
PowerShell Abuse
Credential Access
AD Enumeration
Tunneling Services
Rare Parent-Child Process Relationships

# Security Improvements Recommended

Immediate Actions
Block ngrok.io

Block file.io

Review Pastebin Access

Reset Compromised Credentials

Audit Domain Admin Accounts

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

## What Could Be Improved

✓ Earlier detection of OneNote abuse
✓ Earlier detection of PowerShell activity
✓ Earlier detection of Ngrok communications
✓ Better monitoring of credential theft activity

## Final Conclusions

The Stuxbot investigation demonstrates how a modern intrusion can progress from a simple phishing attachment to full Active Directory compromise.
The attack successfully leveraged:
•	User execution
•	PowerShell
•	Public cloud services
•	Tunneling infrastructure
•	Credential theft tooling
to establish persistence, maintain command-and-control access, and attempt domain-wide compromise.
The most important lesson is that successful detection was achieved not through a single alert, but through the correlation of host telemetry, network visibility, PowerShell logs, DNS activity, and threat hunting methodology.
Organizations that combine these data sources and continuously hunt for anomalous behavior will be significantly more capable of detecting and stopping similar attacks in the future.

