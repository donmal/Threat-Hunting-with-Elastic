# Hunting for Stuxbot – Threat Hunting & Incident Response Investigation
Write-up of Hack The Box Academy Threat Hunting with Elastic.

## Overview

This repository documents a hands-on threat hunting and incident response investigation involving **Stuxbot**, a simulated malware intrusion analyzed within a controlled Hack The Box Academy lab environment.  

The investigation aimed to determine whether organizational systems had been compromised, reconstruct the attacker’s activity, identify persistence mechanisms, uncover credential theft attempts, and document indicators of compromise through endpoint and network telemetry analysis.

The investigation was performed using multiple telemetry sources, including:

- Elastic Stack (Kibana)
- Sysmon
- Windows Event Logs
- PowerShell Script Block Logging
- Zeek Network Logs

---

# Investigation Objectives

The investigation focused on the following objectives:

- Identify the initial access vector.
- Determine the initially compromised endpoint.
- Identify downloaded payloads and reconstruct their execution. 
- Investigate attacker persistence mechanisms. 
- Analyze potential command-and-control (C2) communications.
- Investigate credential access attempts.
- Examine internal reconnaissance activity.
- Identify potential lateral movement preparation.

---

# Environment

| Component | Technology |
|------------|------------|
| Endpoint OS | Microsoft Windows |
| Productivity Suite | Microsoft OneNote |
| Browser | Microsoft Edge |
| Authentication | Active Directory |
| Monitoring Platform | Elastic Stack |
| Network Telemetry | Zeek |
| Endpoint Telemetry | Sysmon |
| Script Execution Telemetry | PowerShell Script Block Logging |
| Additional Security Telemetry | Windows Event Logs |

---

# Investigation Methodology

The investigation followed a structured, evidence-driven threat hunting workflow:

1. Identify suspicious file activity.
2. Reconstruct the process execution chain.
3. Analyze network communications.
4. Investigate PowerShell activity.
5. Identify persistence mechanisms.
6. Investigate credential access.
7. Investigate attacker discovery and reconnaissance activity.
8. Correlate evidence into a complete attack timeline.

---

# Repository Structure

This investigation is divided into six sections.

| Section | Description |
|----------|-------------|
| [01 – Initial Access](01-Initial-Access.md) | Investigation of the initial compromise and malicious document execution |
| [02 – Network Investigation](02-Network-Investigation.md) | DNS analysis, C2 infrastructure, and network communications |
| [03 – Execution and Post-Exploitation](03-Execution-and-Post-Exploitation.md) | Process execution chain, PowerShell activity, and persistence mechanisms |
| [04 – Credential Access](04-Credential-Access.md) | Credential theft investigation and Active Directory abuse |
| [05 – IOC and Detections](05-IOC-and-Detections.md) | Indicators of Compromise, detection opportunities, and MITRE ATT&CK mapping |
| [06 – Lessons Learned](06-Lessons-Learned.md) | Investigation summary, lessons learned, and defensive recommendations |

---

# High-Level Attack Timeline

```text
Initial Access
        │
        ▼
Execution
        │
        ▼
Command and Control
        │
        ▼
Persistence
        │
        ▼
Credential Access
        │
        ▼
Discovery
```
This diagram summarizes the attack stages investigated and does not necessarily represent the exact chronological order of every observed event.

---

# Executive Summary

The investigation confirmed that the simulated **Stuxbot** malware was associated with the compromise of a Windows workstation in the simulated environment following user execution of a malicious OneNote document.

Evidence demonstrated the download and execution of additional payloads, communication with external attacker-controlled infrastructure, persistence-related activity, and post-exploitation techniques involving credential access and Active Directory reconnaissance. The investigation also examined activity associated with **Mimikatz DCSync** and **PowerView**.

By correlating endpoint telemetry (Sysmon and Windows Event Logs) with network telemetry (Zeek DNS and connection logs), it was possible to reconstruct key stages of the simulated intrusion and identify multiple Indicators of Compromise (IOCs) and potential detection opportunities for future threat hunting and threat hunting and detection engineering activities. 

---

# Skills Demonstrated

- Threat Hunting
- Incident Response
- Endpoint Investigation
- Windows Event Analysis
- Sysmon Analysis
- Zeek Network Analysis
- PowerShell Investigation
- Process Tree Analysis
- IOC Extraction
- MITRE ATT&CK Mapping
- Detection Engineering
