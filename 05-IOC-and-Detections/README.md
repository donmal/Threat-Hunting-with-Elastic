# 05 – Indicators of Compromise (IOCs) & Detection Engineering

## Executive Summary

Following the reconstruction of the attack chain and the identification of credential theft activity, the investigation shifted toward identifying persistent indicators left by the attacker and developing practical detection opportunities.

This phase consolidates forensic artifacts collected throughout the investigation into actionable Indicators of Compromise (IOCs) that defenders can use to identify similar attacks across enterprise environments.

The investigation identified multiple categories of malicious artifacts, including:

- Host-based indicators
- Network and DNS indicators
- PowerShell execution artifacts
- Attacker tooling
- Detection opportunities
- MITRE ATT&CK mappings

Rather than representing isolated events, these indicators collectively describe the complete intrusion lifecycle observed during the investigation.

---

## Investigation Objectives

The objectives of this phase were to:

- Identify host-based indicators created during execution.
- Document malicious processes and files.
- Identify malicious domains and IP addresses.
- Recover PowerShell execution artifacts.
- Document attacker tooling used during post-exploitation.
- Develop detection opportunities for future investigations.
- Map attacker behavior to the MITRE ATT&CK framework.

---

## IOC Categories

This phase is organized into four sections:

### 01 – Host and Network IOCs

Documents all forensic artifacts discovered on the compromised host, including:

- Files
- Processes
- Domains
- IP addresses
- DNS activity
- Network communications

---

### 02 – PowerShell and Attacker Tooling

Focuses on attacker tradecraft recovered from Windows telemetry, including:

- PowerShell commands
- Script Block Logging
- PowerView
- SharpHound
- Mimikatz
- Batch scripts
- Living-off-the-Land activity

---

### 03 – Detection Engineering

Transforms the collected evidence into actionable detection content by presenting:

- Elastic queries
- Threat hunting techniques
- Detection opportunities
- SOC recommendations
- MITRE ATT&CK mappings

---

### 04 – Investigation Summary

Provides a consolidated overview of:

- Confirmed Indicators of Compromise
- Key findings
- Defensive recommendations
- Final conclusions

---

## Investigation Flow

```
Initial Access
        ↓
Network Communications
        ↓
Execution
        ↓
PowerShell
        ↓
Payload Delivery
        ↓
Credential Theft
        ↓
Indicators of Compromise
        ↓
Detection Engineering
```

---

## Outcome

The resulting IOC catalogue provides defenders with a structured reference for identifying attacker activity across Windows hosts, Active Directory environments, and network telemetry.

These indicators can be incorporated into SIEM detection rules, threat hunting playbooks, and incident response procedures to improve detection coverage against similar intrusion campaigns.