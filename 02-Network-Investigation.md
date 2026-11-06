# 02 – Network Investigation

## Executive Summary 

Following identification of the suspicious OneNote document **invoice.one** through file creation telemetry on workstation **WS001**, the investigation shifted toward network telemetry to determine how the payload entered the environment and whether the affected host established communications with external infrastructure.

The primary objectives of this phase were:

  •	Identify external infrastructure contacted by the affected host.
  
  •	Determine the source of the malicious document.
  
  •	Validate whether download activity occurred.
  
  •	Identify potential command-and-control communications.
  
  •	Correlate DNS activity with network connections.
  
  •	Reconstruct attacker communications.
  
Analysis of Zeek DNS logs, Zeek connection logs, and Sysmon network events enabled reconstruction of the network component of the intrusion. The investigation identified multiple suspicious domains, including **file.io**, **pastebin.com**, and **ngrok.io**.

The observed DNS resolutions and network connections provided evidence of external communications potentially associated with payload delivery, remote content retrieval, and command-and-control (C2) activity. These findings established investigative leads for correlating network activity with endpoint execution and persistence evidence.

# Investigation Objectives 

The objectives of this phase were:

    •	Identify network activity originating from WS001.
    
    •	Identify suspicious DNS queries.
    
    •	Determine the source of invoice.one.
    
    •	Verify network connections following DNS resolution.

    •	Identify potential command-and-control infrastructure.

    •	Correlate host telemetry with network telemetry.

# Starting Point 

The previous phase identified:

**Host**:WS001

**Source IP**: 192.168.28.130

This IP became the pivot point for the remainder of the network investigation.
 
# Data Sources Used

| Data Source | Purpose |
|-------------|---------|
| Zeek DNS Logs | Domain lookups, DNS responses and resolved IP addresses |
| Zeek Connection Logs | Network connections, destination IPs, ports and communication patterns |
| Sysmon Event ID 3 | Process-specific network activity and process attribution |

# DNS Investigation 

The investigation began by examining DNS requests originating from the affected host.

## KQL Query - DNS Activity from WS001:

source.ip:192.168.28.130 AND dns.question.name:*

# Investigation ratoinale 

DNS telemetry was examined to identify domains queried by WS001, establish external infrastructure associated with the affected endpoint, and correlate suspicious domain resolutions with subsequent network connections.

## Initial Findings 

The query returned over two hundred DNS events.
Many were expected:
•	Microsoft services
•	Google services
•	Browser telemetry
•	Update mechanisms
These events represented normal background activity.

# Noise Reduction 

To isolate suspicious domains, common entries were excluded.
Examples:
NOT dns.question.name:www.google.com
NOT dns.question.name:www.google-analytics.com
NOT dns.question.name:30.2.52.216.in-addr.arpa

# Filtering Strategy

Common background DNS queries were excluded to reduce investigative noise and prioritize potentially suspicious domains. This filtering strategy improved the visibility of less frequently observed external infrastructure.

## Evidence

**Figure 1 – DNS Activity Associated with WS001**

Elastic Discover displaying 4,181 matching Zeek events associated with source IP **192.168.28.130 (WS001)** within the selected investigation timeframe. The histogram provides an initial overview of event frequency and activity patterns, establishing a baseline for subsequent DNS-focused threat hunting.

![Figure 1](images/network-investigation/figure1_dns_queries.png)

# Discovery of file.io 

After filtering, a suspicious domain appeared:

**file.io**

The appearance of **file.io** within the investigated activity window prompted further examination of its potential involvement in the delivery of invoice.one. The domain was selected as an investigative pivot for DNS resolution, network connection, and file correlation.
 
# Infrastructure Assessment

**file.io** is a legitimate file-hosting service. However, it can also be used to distribute malicious files through externally accessible download links. Given the suspected OneNote-based initial access technique, the observed file.io activity was treated as a potential delivery indicator requiring further validation.
 
## Investigative Assessment 

The identification of **file.io** provided a basis for correlating DNS queries and network connections with the creation of **invoice.one** on **WS001**. This correlation was used to access whether the service had played a role in the suspected initial access sequence.
 
## Evidence

**Figure 2 – DNS results after filtering common benign domains**

Filtering removed common background DNS traffic, allowing suspicious domains to be identified more efficiently during the investigation.

![Figure 2](images/network-investigation/figure2_dns_noise_reduction.png)

# DNS Resolution Analysis 

Inspection of the DNS event revealed:

34.197.10.85
3.213.216.16

The DNS response associated **file.io** with the resolved IP address 34.197.10.85 and 3.213.216.16, providing specific network indicators for subsequent connection verification. 

# Connection Validation Rationale

A DNS query does not prove communication occurred.

Therefore the next step was verifying network connections.

# Connection Verification 

The investigation pivoted into connection logs.

Zeek connection telemetry was examined to verify whether **WS001** established connections with the IP addresses identified through DNS resolution. 
 
# Evidence Correlation

DNS queries, resolved IP addresses, network connections, and endpoint file creation events were correlated to reconstruct the suspected payload delivery sequency. Although these events support the download hypothesis, confirming the transfer of a specific file requires additional file-transfer or process-level evidence.
 
## Findings 

Network telemetry confirmed connections to the file.io infrastructure.

This provided supporting evidence that **file.io** may have been involved in delivering **invoice.one** to the affected endpoint.

## Evidence

**Figure 3 – Discovery of file.io DNS requests**

DNS telemetry identified repeated queries for **file.io**, indicating potential malware staging or payload delivery activity.

![Figure 3](images/network-investigation/figure3_fileio_discovery.png)

## Timeline Reconstruction

Correlation between:

•	DNS activity
•	Connection activity
•	File creation

revealed a consistent timeline.

DNS Query
      ↓
Connection
      ↓
invoice.one Created

The timing supported the hypothesis that **invoice.one** was delivered through the identified external infrastructure. 

The sequence represents a correlation of observed events. Confirmation of the exact delivery mechanism requires additional evidence linking the network transaction to the created file.

# Discovery of Pastebin

Further analysis identified references to:

**pastebin.com**

Unlike file.io, which appeared to be used for payload delivery, Pastebin was associated with retrieval of PowerShell instructions executed during the next phase of the intrusion. 

# Infrastructure Assessment  

Pastebin is a legitimate text-sharing platform that can also host remotely retrieved scripts and commands. Its presence in the investigated network activity provided an additional lead for correlating external communications with subsequent PowerShell execution.

## Investigative Assessment 

The observed Pastebin-related activity was treated as a potential indicator of remote script retrieval. Correlation with PowerShell Script Block Logging was required to establish whether content hosted on the platform was retrieved and executed. 

## Evidence

**Figure 4 – DNS resolution for file.io**

DNS responses resolved **file.io** to the external IP addresses **34.197.10.85** and **3.213.216.16**, providing infrastructure used later for connection verification.

![Figure 4](images/network-investigation/figure4_fileio_dns_resolution.png)
 
# Discovery of ngrok 

The most significant finding involved:
ngrok.io

Repeated communications over multiple days distinguished ngrok activity from one-time payload delivery and suggested the presence of persistent command-and-control communications.
 
# Infrastructure Assessment 

Ngrok is a legitimate tunneling service.

Ngrok provides tunneling capabilities that can expose internal services through externally accessible endpoints. Within the investigated activity, recurring connections associated with ngrok infrastructure were examined as potential indicators of unauthorized remote access or C2 communications.

# DNS Investigation of ngrok 

DNS telemetry identified multiple resolutions associated with **ngrok.io**.

Returned infrastructure included:

18.158.249.75

3.125.102.39

## Evidence

**Figure 5 – Network connections to resolved file.io infrastructure**

Network telemetry confirmed successful communication between the compromised workstation and the infrastructure associated with **file.io**, supporting the suspected payload delivery sequence. 

![Figure 5](images/network-investigation/figure5_fileio_connections.png)

## Command and Control Assessment 

The investigation observed:

•	Repeated DNS requests
•	Repeated HTTPS connections
•	Activity spanning multiple days

These observations are consistent with potential command-and-control (C2) activity, although recurring communications alone do not establish malicious command exchange.

# Recurring Communication Analysis

The attacker infrastructure continued to appear:

This suggested:

Repeated communications across multiple days raised the possibility of automated callbacks or sustained remote access. Additional endpoint evidence was required to determine whether the activity resulted from an established persistence mechanism.

### Assessment 

Although repeated communications with the identified infrastructure were observed during the investigation, the primary objective of this phase was to identify and validate the external infrastructure used throughout the intrusion.

The collected DNS telemetry, resolved IP addresses, and verified network connections provided sufficient evidence to conclude that the compromised workstation successfully communicated with external infrastructure associated with the suspected intrusion. The recurring communication patterns warranted further investigation for potential C2 activity.

## MITRE ATT&CK Mapping 

| Tactic | Technique |
|---------|-----------|
| Command and Control | T1071 – Application Layer Protocol (potential C2 over application-layer protocol) |
| Command and Control | T1572 – Protocol Tunneling (requires evidence of actual tunneling) |
| Command and Control | T1105 – Ingress Tool Transfer (requires evidence of transferred tools or payloads) |

These mappings represent techniques relevant to the suspected attack behaviour. Network connections and DNS resolution alone do not confirm all mapped techniques.

## Detection Opportunities 

Organizations should monitor:
| Indicator | Detection Opportunity |
|-----------|----------------------|
| file.io | Monitor unexpected access to anonymous file-sharing services |
| Pastebin | Detect PowerShell retrieving remote content |
| ngrok | Monitor tunneling services within enterprise environments |
| Repeated HTTPS callbacks | Identify long-term communications with rare external infrastructure |
| DNS-to-connection correlation | Correlate suspicious DNS resolutions with subsequent outbound connections from the same endpoint |

These detection opportunities represent proposed monitoring use cases rather than production-validated detection rules.

## Key Findings 

- DNS telemetry identified suspicious external infrastructure.
- **file.io** was identified as a suspected malware delivery platform.
- Network connections to resolved **file.io** infrastructure were verified, supporting the suspected payload delivery sequence.
- Pastebin-related activity was identified for correlation with PowerShell execution evidence.
- Repeated ngrok-related activity was identified across the investigated period.
- Recurring external communications were consistent with potential C2 activity requiring further endpoint-level validation. 

## Lessons Learned 

1.	DNS telemetry frequently provides the earliest evidence of compromise.
2.	File-sharing platforms remain common malware delivery mechanisms.
3.	Network telemetry supports suspected download investigations, while attribution of specific transferred files requires additional evidence.
4.	Tunneling platforms such as ngrok should be monitored closely.
5.	Recurring external communications can indicate potential C2 activity and warrant investigation for persistence mechanisms.

## Conclusion 

Network investigation identified external communications associated with the affected workstation and provided supporting evidence for suspected payload delivery.

DNS telemetry identified **file.io**, **pastebin.com**, and **ngrok.io** as external infrastructure associated with the suspected attack sequence.

Connection logs verified communication with resolved infrastructure, while repeated activity across multiple days raised concerns about potential sustained C2 activity.

These findings established the network indicators requiring further investigation and provided the foundation for analyzing process execution, PowerShell activity, persistence mechanisms, and credential access attempts in the next phase of the investigation. 
