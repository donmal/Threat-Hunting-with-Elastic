# 04 – Investigation Summary

## Executive Summary

The IOC and Detection Engineering phase concluded the Stuxbot investigation by consolidating forensic evidence collected throughout the incident into a comprehensive set of Indicators of Compromise (IOCs), behavioral detections, and defensive recommendations.

Rather than relying solely on individual artifacts, the investigation correlated endpoint telemetry, PowerShell activity, DNS records, process creation events, and Active Directory reconnaissance to produce reusable detection logic suitable for enterprise environments.

---

# Confirmed Indicators of Compromise

## Malicious Files

- invoice.one
- invoice.bat
- default.exe
- payload.exe
- SharpHound.exe
- mimikatz.exe
- svchost.exe
- XceGuhkzaTr0y.vbs

---

## Malicious Processes

- ONENOTE.EXE
- OneNoteM.exe
- cmd.exe
- powershell.exe
- default.exe
- SharpHound.exe
- mimikatz.exe
- wscript.exe
- cscript.exe

---

## Malicious Domains

- file.io
- pastebin.com
- ngrok.io

---

## IP Addresses

- 34.197.10.85
- 3.213.216.16
- 18.158.249.75
- 3.125.102.39

---

# Confirmed Attacker Tradecraft

The investigation identified attacker behavior across multiple phases of the intrusion lifecycle.

Observed techniques included:

- User execution through a malicious OneNote document
- Command-line execution using cmd.exe
- PowerShell download-and-execute
- Remote payload retrieval
- In-memory execution
- Command-and-Control communications
- Active Directory enumeration
- Credential theft
- DCSync
- VBScript persistence

These activities collectively demonstrate a structured post-exploitation workflow targeting the Active Directory environment.

---

# MITRE ATT&CK Summary

| Tactic | Technique | ID |
|---------|-----------|----|
| Initial Access | Phishing | T1566 |
| Execution | User Execution | T1204 |
| Execution | PowerShell | T1059.001 |
| Command and Control | Ingress Tool Transfer | T1105 |
| Command and Control | Application Layer Protocol | T1071 |
| Command and Control | Protocol Tunneling | T1572 |
| Discovery | Account Discovery | T1087 |
| Discovery | Permission Group Discovery | T1069 |
| Discovery | Network Share Discovery | T1135 |
| Credential Access | DCSync | T1003.006 |
| Persistence | Visual Basic Script | T1059.005 |

---

# High-Confidence Detection Opportunities

The investigation identified several behaviors that should generate immediate alerts.

## High Severity

- Mimikatz execution
- SharpHound execution
- PowerView execution
- DCSync activity
- PowerShell using Invoke-Expression
- PowerShell retrieving remote payloads
- OneNote spawning command interpreters

---

## Medium Severity

- PowerShell Script Block Logging containing reconnaissance functions
- Pastebin communications
- Ngrok communications
- Randomized VBScript execution
- Temporary directory executables

---

## Low Severity

- file.io DNS requests
- Unusual outbound DNS activity
- Unexpected PowerShell execution

---

# Defensive Recommendations

Organizations should consider implementing the following defensive measures:

- Enable Sysmon with comprehensive logging.
- Enable PowerShell Script Block Logging.
- Monitor parent-child process relationships.
- Restrict PowerShell execution where appropriate.
- Alert on Microsoft Office applications spawning command interpreters.
- Monitor Active Directory replication permissions.
- Detect unauthorized execution of SharpHound and Mimikatz.
- Hunt for command-and-control tunneling services such as Ngrok.
- Correlate endpoint and network telemetry during investigations.

---

# Key Findings

The investigation confirmed:

- Successful execution of a malicious OneNote document.
- Download and execution of attacker-controlled payloads.
- Command-and-control communications through Ngrok.
- Active Directory reconnaissance using SharpHound and PowerView.
- Credential theft activity using Mimikatz.
- Attempted DCSync operations against the Active Directory domain.
- Persistence through a randomized VBScript.
- Multiple high-confidence Indicators of Compromise suitable for enterprise detection.

---

# Lessons Learned

Several important lessons emerged throughout the investigation.

- Correlating multiple telemetry sources significantly improves investigative accuracy.
- Parent-child process relationships provide valuable visibility into malware execution chains.
- PowerShell Script Block Logging is highly effective for recovering attacker tradecraft.
- Behavioral detections provide greater resilience than static IOCs.
- Active Directory reconnaissance often precedes credential theft and should be treated as an early warning indicator.
- Detection engineering should focus on attacker behavior rather than individual malware samples.

---

# Conclusion

The IOC and Detection Engineering phase transformed the technical findings of the Stuxbot investigation into actionable intelligence.

The investigation successfully identified malicious host artifacts, network indicators, PowerShell execution patterns, attacker tooling, and Active Directory attack techniques while mapping each stage of the intrusion to the MITRE ATT&CK framework.

By converting forensic evidence into repeatable detection logic, this investigation provides a practical reference for Security Operations Centers, Threat Hunting teams, Detection Engineers, and Incident Responders seeking to identify and respond to similar attacks in enterprise environments.