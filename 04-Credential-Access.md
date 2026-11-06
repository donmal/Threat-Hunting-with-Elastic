# 04 - Credential-Access Investigation
Hack The Box Academy lab write-up | Practical credential access investigation

## Executive Summary

Following the identification of malicious payload execution and suspicious external network communications, the investigation shifted toward determining whether the attacker attempted to obtain credentials from the Active Directory environment.

Analysis of Sysmon telemetry identified the deployment and execution of two well-known offensive security tools: SharpHound and Mimikatz. Their presence indicates that the attacker had progressed beyond initial compromise and was actively targeting the Active Directory environment. SharpHound was identified as Active Directory reconnaissance tooling, potentially supporting the identification of privilege escalation paths, while Mimikatz was executed with arguments indicating an attempted DCSync attack against the domain.

The findings established evidence of an attempted domain-level credential access operation, significantly increasing the potential severity of the intrusion. Successful credential extraction or domain compromise was not confirmed by the available telemetry.

# Investigation Objectives

The objectives of this investigation phase were:

•	Determine whether attacker activity involved credential theft.

•	Identify credential access tooling used during the intrusion.

•	Analyze execution of SharpHound and Mimikatz.

•	Determine whether Active Directory was targeted.

•	Identify evidence of DCSync activity.

•	Assess the likelihood of domain compromise.

•	Document attacker objectives and impact.


# Previous Investigation Findings

Earlier stages of the investigation established the following attack chain:

invoice.one

      ↓
      
ONENOTE.EXE

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


Previous investigation phases identified malicious execution, remote payload retrieval and Ngrok-related network communications. Potential command-and-control activity and persistence indicators were also identified, although these mechanisms were not conclusively established.

The next objective was to determine whether post-exploitation activity had progressed into Active Directory credential access.
During analysis of the default.exe activity, several additional files were identified:

SharpHound.exe
svchost.exe
payload.exe
XceGuhkzaTr0y.vbs

The appearance of SharpHound immediately raised concerns regarding Active Directory reconnaissance.

# Discovery of SharpHound

Active Directory Reconnaissance Context

SharpHound is the data collection component of the BloodHound framework.
Its purpose is not credential theft directly.
Instead, it performs reconnaissance against Active Directory environments.

SharpHound collects information about domain users, groups, sessions, permissions and trust relationships. In this investigation, its presence was relevant because these capabilities can support the identification of privileged accounts and potential attack paths within Active Directory.

The identified SharpHound activity was assessed in the context of subsequent Mimikatz execution to determine whether the intrusion had progressed from reconnaissance toward credential access.

# Evidence of SharpHound Deployment

During investigation of default.exe, the executable was observed interacting with:

SharpHound.exe

The identified artifact was consistent with the deployment of Active Directory reconnaissance tooling. Confirmation of the specific data collected would require additional execution telemetry or recovered collection output.

# Figure 1 – SharpHound artifact identified during default.exe investigation.

![Figure 1](images/credential-access/figure1_sharphound_artifact.png)

## Reconnaissance Findings and Potential Impact

The deployment of SharpHound indicates that the attacker had moved beyond simple malware execution.

The observed SharpHound artifact suggested an interest in Active Directory relationships, privileged accounts and potential escalation paths. This finding provided relevant context for the subsequent identification of Mimikatz and its DCSync-related command-line arguments.

## MITRE ATT&CK Mapping

Technique	Description
T1087	Account Discovery
T1069	Permission Group Discovery
T1018	Remote System Discovery
T1482	Domain Trust Discovery

These techniques represent reconnaissance capabilities associated with SharpHound. Individual mappings should be considered potential unless the corresponding collection activity is supported by execution telemetry or recovered output.

## Discovery of Mimikatz

Following Active Directory reconnaissance, attention shifted toward identifying evidence of credential theft tooling.

Query used:

process.name:"mimikatz.exe"

# Investigation Methodology 

Sysmon process creation telemetry was filtered for mimikatz.exe to identify credential access tooling within the compromised environment. The investigation focused on confirming process execution and examining associated command-line arguments to determine the technique attempted.

# Figure 2 – Mimikatz process execution identified within Sysmon logs.

![Figure 2](images/credential-access/figure2_mimikatz_process_execution.png)

## Process Argument Analysis

After identifying Mimikatz execution, the next objective was determining how it was used.

The investigation examined process.args and process.command_line to identify the arguments supplied during Mimikatz execution.

# Telemetry Examination

Query:

process.name:"mimikatz.exe"

Fields examined:

process.name
process.args
process.command_line
@timestamp

# Command-Line Analysis

The command-line arguments provided visibility into the functionality requested during Mimikatz execution and enabled the investigation to distinguish domain replication abuse from conventional local credential dumping.

## Findings

Analysis of the command-line arguments indicated that the attacker was attempting a:
DCSync operation rather than performing local credential dumping.

The observed command was:

lsadump::dcsync /domain:eagle.local /all /csv exit

The /domain:eagle.local argument identified the targeted domain, while /all specified an attempt to retrieve replication data for all domain accounts. The command established an attempted domain-level credential access operation, although successful credential extraction was not confirmed.

# Figure 3 – Mimikatz command-line arguments revealing DCSync functionality.

![Figure 3](images/credential-access/figure3_mimikatz_dcsync_arguments.png)

# DCSync Technique Analysis

# Observed Credential Access Technique 

The identified Mimikatz command invoked DCSync functionality, which attempts to abuse Active Directory replication protocols to retrieve credential-related directory data. Successful execution requires an account with sufficient directory replication privileges.

# Credential Access Implications

Unlike local credential dumping, DCSync does not require extracting credentials directly from LSASS memory on the compromised workstation. Instead, it requests sensitive directory data through Active Directory replication mechanisms.

# Potential Targets

A successful DCSync attack may expose:

- Domain Admin Accounts

- Service Accounts

- Privileged Users

- Enterprise Admins

- KRBTGT Account

The observed **/all** argument indicated an attempt to obtain replication data across domain accounts, making the potential impact substantially broader than credential theft from a single endpoint.

## Credential Access Investigation Sequence 

Initial Execution & Payload Delivery 

The investigation correlated the following activities:

      invoice.one
      
          ↓
          
      PowerShell
      
          ↓

     default.exe
     
          ↓
          
    SharpHound
    
          ↓
          
 Active Directory Enumeration
 
          ↓
          
      Mimikatz
      
         ↓
         
      DCSync
      
         ↓

   Credential Theft

The relationship between these activities reflects investigative correlation, not necessarily direct parent-child process execution. 

## Investigative Timeline Overview

The broader investigation documented the following stages:

Phase 1 – Initial Access

Phase 2 – Execution

Phase 3 – Command and Control

Phase 4 – Active Directory Reconnaissance

Phase 5 – Credential Access

Phase 6 – DCSync Attempt

These stages represent an analytical progression of the intrusion rather than a timestamp-verified sequence of individual attacker actions.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Credential Access | OS Credential Dumping | T1003 |
| Credential Access | DCSync | T1003.006 |
| Discovery | Account Discovery | T1087 |
| Discovery | Permission Group Discovery | T1069 |

The observed Mimikatz command directly supported mapping to T1003.006 – OS Credential Dumping: DCSync. Discovery technique mappings were associated with SharpHound capabilities and require supporting evidence to confirm individual collection activities.

## Threat Assessment

The combination of suspicious PowerShell execution, Ngrok-related network communications, SharpHound deployment and Mimikatz DCSync arguments indicated an intrusion involving multiple post-exploitation capabilities. The DCSync attempt represented the most significant credential access indicator because successful execution could expose privileged domain credentials.

The observed activity was consistent with an Active Directory-focused intrusion; however, the available evidence did not establish the attacker's overall sophistication, confirm successful domain compromise or conclusively demonstrate the full extent of access obtained.

## Key Findings

✓ SharpHound.exe was identified on the compromised host.

✓ SharpHound was identified as Active Directory reconnaissance tooling.

✓ Mimikatz.exe was executed successfully.

✓ Process arguments indicate DCSync functionality.

✓ The attacker targeted Active Directory credentials.

✓ The objective extended beyond workstation compromise.

✓ Evidence suggests attempted domain-level credential theft.


No evidence was identified confirming successful extraction of domain credentials.

## Analyst Assessment

Based on the available endpoint telemetry, the attacker progressed from initial execution and payload delivery into activity involving Active Directory reconnaissance tooling and an attempted domain-level credential access operation.

The deployment of both SharpHound and Mimikatz demonstrates deliberate attacker behavior consistent with an Active Directory-focused intrusion.

The Mimikatz DCSync command provided the strongest evidence of an attempt to obtain domain credential material. The absence of confirmed replication results prevented a definitive assessment of successful credential extraction or domain compromise.

## Conclusion

The Credential Access phase of the Stuxbot investigation revealed that the attacker moved beyond simple malware execution and attempted to access sensitive Active Directory credential material.

Evidence showed the deployment of SharpHound for reconnaissance and Mimikatz for credential theft operations. Analysis of process arguments revealed attempted DCSync activity, indicating that the attacker sought access to password hashes stored within Active Directory.

These findings significantly elevate the severity of the incident and suggest that the attacker’s objective was not limited to a single workstation, but potentially included compromise of privileged accounts and broader domain infrastructure.
No evidence was identified confirming successful domain compromise; however, the observed attacker tooling and DCSync activity indicate that the intrusion had reached a critical stage requiring priority investigation, containment of affected systems and assessment of potentially exposed credentials before determining the appropriate credential rotation scope.
