# 04 – Investigation Summary

## Executive Summary

The IOC and Detection Engineering phase concluded the Stuxbot investigation by consolidating forensic evidence collected throughout the incident into a comprehensive set of Indicators of Compromise (IOCs), behavioral detections, and defensive recommendations.

Rather than relying solely on individual artifacts, the investigation correlated endpoint telemetry, PowerShell activity, DNS records, process creation events, and Active Directory reconnaissance to produce Observed Indicators and Investigation Artifacts.

The following artifacts were identified throughout the investigation. Their presence should be interpreted within the observed execution chain, as not all listed filenames, processes, domains, or IP addresses are inherently malicious.
 
---

# Confirmed Indicators of Compromise

## Processes Observed in the Attack Execution Chain

- ONENOTE.EXE
- OneNoteM.exe
- cmd.exe
- powershell.exe
- default.exe
- SharpHound.exe
- mimikatz.exe
- wscript.exe
- cscript.exe

Several processes in this list, including **ONENOTE.EXE**, **cmd.exe**, **powershell.exe**, **wscript.exe**, and **cscript.exe, are legitimate Windows or application components. Their investigative significance comes from suspicious parent-child relationships, command-line arguments, execution paths, and associated network activity.

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

# Observed Attacker Tradecraft

The investigation identified attacker behavior across multiple phases of the intrusion lifecycle.

Observed techniques included:

- User execution through a malicious OneNote document
- Command-line execution using cmd.exe
- PowerShell download-and-execute
- Remote payload retrieval
- In-memory execution
- Command-and-Control communications
- Active Directory enumeration
- Attempted DCSync operation
- Visual Basic (execution technique; persistence mechanism requires separate validation) | T1059.005 |

The mappings summarize techniques identified or investigated during the intrusion. T1059.005 describes Visual Basic execution rather than persistence itself. Similarly, phishing, protocol tunneling, and other technique mappings should be retained as confirmed only where supported by the corresponding telemetry.

MITRE ATT&CK mappings should distinguish observed execution from inferred attacker objectives, particularly when the available evidence supports an attempted technique rather than a successful outcome.

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

The investigation identified several candidate detection opportunities based on observed attacker behavior. The severity levels below represent proposed priorities and would require validation, false-positive analysis, and environment-specific tuning before deployment.

## High Severity

- Mimikatz execution
- SharpHound execution
- PowerView execution
- Deploy and configure Sysmon to capture relevant capture creation, file creation and network-related events
- PowerShell using Invoke-Expression
- PowerShell retrieving remote payloads
- OneNote spawning command interpreters
- Enable PowerShell Script Block Logging
- Monitor parent-child process relationships
- Restrict PowerShell execution where appropriate
- Alert on Microsoft Office applications spawning command interpreters
- Monitor Active Directory replication permissions
- Detect unauthorized execution of SharpHound and Mimikatz
- Hunt for command-and-control tunneling services such as Ngrok
- Correlate endpoint and network telemetry during investigations 

Detection controls should be prioritized according to the organization's threat model, available telemetry, and operational requirements. Proposed rules should be tested against legitimate administrative activity to reduce false positives.

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

The investigation produced the following findings based on the analyzed telemetry and recovered artifacts:

- Successful execution of a malicious OneNote document.
- Download and execution of attacker-controlled payloads.
- Network activity associated with Ngrok infrastructure, investigated as potential command-and-control communication.
- Active Directory reconnaissance using SharpHound and PowerView.
- Mimikatz execution involving credential-access-related commands.
- Attempted DCSync operations against the Active Directory domain.
- Identification of a randomized VBScript artifact associated with suspected persistence activity.
- Multiple host and network indicators that can support threat hunting and candidate detection development.

The strongest findings were supported by process execution telemetry, PowerShell command-line evidence, Script Block Logging, and correlation with other investigation artifacts. Additional evidence would be required to confirm successful credential theft or persistence where those outcomes were not directly demonstrated.

---

# Lessons Learned

Several important lessons emerged throughout the investigation.

- Correlating multiple telemetry sources significantly improves investigative accuracy.
- Parent-child process relationships provide valuable visibility into malware execution chains.
- PowerShell Script Block Logging is highly effective for recovering attacker tradecraft.
- Behavioral detections provide greater resilience than static IOCs.
- Active Directory reconnaissance often precedes credential theft and should be treated as an early warning indicator.
- Detection engineering should focus on attacker behavior rather than individual malware samples.

The investigation also highlighted the importance of distinguishing observed events from inferred outcomes. For example, detecting Mimikatz with DCSync-related arguments supports an attempted credential-access technique, but successful credential extraction requires additional verification.

Another important takeaway was that broad hunting queries are useful for identifying suspicious activity, but production detection rules require contextual filtering, testing, and false-positive tuning.

---

# Conclusion

The IOC and Detection Engineering phase transformed the technical findings of the Stuxbot investigation into actionable intelligence.

The investigation successfully identified malicious host artifacts, network indicators, PowerShell execution patterns, attacker tooling, and Active Directory attack techniques while mapping each stage of the intrusion to the MITRE ATT&CK framework.

By translating forensic findings into candidate detection logic and documented hunting opportunities, this investigation demonstrates a practical approach to connecting incident analysis with detection engineering. The resulting findings provide a foundation for further rule development, validation, and incident response planning in enterprise security environments.
