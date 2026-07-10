# Hunting for Stuxbot – Threat Hunting & Incident Response Investigation

## Overview

This repository documents a complete threat hunting investigation performed against a simulated malware intrusion known as **Stuxbot**.

The investigation aimed to determine whether organizational systems had been compromised, reconstruct the attacker’s activity, identify persistence mechanisms, uncover credential theft attempts, and document indicators of compromise through endpoint and network telemetry analysis.

The investigation was performed using multiple telemetry sources, including:

- Elastic Stack (Kibana)
- Sysmon
- Windows Event Logs
- PowerShell Script Block Logging
- Zeek Network Logs

---

# Investigation Objectives

The investigation focused on answering the following questions:

- How did the attacker gain initial access?
- Which endpoint was compromised first?
- What payloads were downloaded and executed?
- Was persistence established?
- Was command-and-control communication observed?
- Was credential theft attempted?
- Was internal reconnaissance performed?
- Was lateral movement preparation identified?

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

---

# Investigation Methodology

The investigation followed a structured threat hunting workflow:

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

---

# Executive Summary

The investigation confirmed that the simulated **Stuxbot** malware successfully compromised a Windows workstation following user execution of a malicious OneNote document.

Evidence demonstrated the download and execution of additional payloads, communication with external attacker-controlled infrastructure, establishment of persistence, credential theft attempts using **Mimikatz DCSync**, and internal Active Directory reconnaissance through **PowerView**.

By correlating endpoint telemetry (Sysmon and Windows Event Logs) with network telemetry (Zeek DNS and connection logs), it was possible to reconstruct the complete intrusion lifecycle and identify multiple high-confidence Indicators of Compromise (IOCs) suitable for future threat hunting and detection engineering activities.

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
