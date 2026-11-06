# 05 – Indicators of Compromise (IOCs) & Detection Engineering
Hack The Box Academy lab write-up | IOC Analysis & Detection Engineering Practice

## Executive Summary

Following the reconstruction of the observed attack sequence and the identification of attempted credential access activity, the investigation shifted toward identifying forensic indicators associated with the intrusion and developing practical detection opportunities.

This phase consolidates forensic artifacts collected throughout the investigation into a structured IOC catalogue and supporting detection opportunities for investigating similar activity across enterprise environments.

The investigation identified multiple categories of suspicious and malicious artifacts, alongside supporting analytical outputs, including:

- Host-based indicators
- Network and DNS indicators
- PowerShell execution artifacts
- Attacker tooling
- Detection opportunities
- MITRE ATT&CK mappings

Rather than representing isolated events, these indicators collectively describe the observable stages of the intrusion and the relationship between endpoint, network and credential access activity.

---

## Investigation Objectives

The objectives of this phase were to:

- Identify host-based indicators created during execution.
- Document malicious processes and files.
- Identify suspicious domains and IP addresses associated with the intrusion.
- Recover PowerShell execution artifacts.
- Document attacker tooling identified during post-exploitation.
- Develop detection opportunities for future investigations.
- Map observed attacker activity and associated techniques to the MITRE ATT&CK framework.

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

The indicators are assessed in the context of the intrusion, distinguishing directly observed artifacts from infrastructure or activity requiring further validation.

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

The analysis emphasizes observed execution activity, recovered script content and the distinction between tooling capabilities and confirmed attacker actions.

---

### 03 – Detection Engineering

Transforms the collected evidence into proposed detection logic and threat hunting opportunities by presenting:

- Elastic queries
- Threat hunting techniques
- Detection opportunities
- SOC recommendations
- MITRE ATT&CK mappings

Where applicable, detection queries are linked to the supporting forensic findings. Proposed detections should be validated against relevant telemetry and legitimate administrative activity before operational deployment.

---

### 04 – Investigation Summary

Provides a consolidated overview of:

- Observed and assessed Indicators of Compromise
- Key findings
- Defensive recommendations
- Final conclusions

---

## Investigation Flow

The investigation and detection development workflow is summarized below:
```
Evidence Collection
(Endpoint, PowerShell and network telemetry)
        ↓
IOC Identification
(Files, processes, domains, IPs and script artifacts)
        ↓
IOC Correlation & Assessment
(Validate context, relationships and confidence)
        ↓
Detection Engineering
(Elastic queries and proposed detection logic)
        ↓
Defensiveness Recommendations
(Threat hunting, triage and detection validation)
 
```

---

## Outcome

The resulting IOC catalogue provides defenders with a structured reference for identifying similar suspicious activity across Windows hosts, Active Directory environments, and network telemetry.

These indicators can be incorporated into SIEM detection rules, threat hunting playbooks, and incident response procedures to improve detection coverage against similar intrusion campaigns.

Operational use requires validation of indicator relevance, environmental context and detection accuracy to minimize false positives and avoid relying on infrastructure indicators alone.
