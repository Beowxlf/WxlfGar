# Wulfgar
## Product Requirements Document (PRD-lite)
**Version:** 0.1  
**Phase:** Phase 1 – Local Windows CLI  
**Platform:** Windows 10 and Windows 11  

---

# 1. Product Overview

Wulfgar is a Windows-based diagnostic CLI tool designed to reduce time-to-diagnosis for intermittent internet connectivity issues in MSP environments.

Phase 1 delivers a local artifact generation engine that:

- Captures network traffic
- Detects high-signal protocol anomalies
- Extracts focused PCAP slices
- Executes deterministic triage commands
- Produces a structured diagnostic bundle

This phase does not include server communication or persistent background operation.

---

# 2. Target User

Primary user: MSP technician  

User context:

- Customer reports intermittent internet issues.
- Issue is not consistently reproducible.
- Technician requires structured evidence for escalation or deeper analysis.

---

# 3. User Stories

## Core User Story

As an MSP technician, when a customer reports intermittent internet issues, I want to run Wulfgar and receive a structured diagnostic bundle so that I can identify likely failure domains without waiting for the issue to reoccur live.

---

# 4. Functional Requirements

## 4.1 Packet Capture

The system shall:

1. Allow selection of an active network interface.
2. Capture traffic for a configurable duration.
3. Enforce a maximum capture size limit.
4. Save the capture as a PCAP file.
5. Record metadata:
   - Hostname
   - OS version
   - Interface name
   - Interface IP
   - Capture start time
   - Capture end time

---

## 4.2 Protocol Parsing

The system shall parse captured PCAP files for indicators involving:

- DNS
- DHCP
- HTTP
- HTTPS
- SMB
- ICMP

---

## 4.3 Event Detection

The system shall detect and timestamp the following indicators:

### DNS

- NXDOMAIN responses
- SERVFAIL responses
- REFUSED responses
- Repeated queries with no response

### DHCP

- DHCP Discover without Offer
- DHCP Request without Ack

### HTTP and HTTPS

- TCP SYN retransmissions
- TCP connection timeouts
- TCP resets
- TLS handshake failures when inferable

### SMB

- Port 445 connection failures
- TCP resets during SMB session establishment

### ICMP

- Destination unreachable messages
- TTL exceeded messages

Each detected event must include:

- Timestamp
- Protocol
- Source IP
- Destination IP
- Indicator type
- Short description

---

## 4.4 PCAP Slicing

For each detected event, the system shall:

1. Extract packets from:
   - 60 seconds before event timestamp
   - 60 seconds after event timestamp
2. Apply protocol-relevant filtering.
3. Save filtered PCAP file per event.

---

## 4.5 Deterministic Triage

The system shall execute whitelisted commands when relevant conditions are met.

Allowed commands:

- `nslookup google.com`
- `ipconfig /all`
- `route print`
- `arp -a`
- `netsh interface show interface`

Requirements:

- No arbitrary command execution.
- All commands must be logged.
- Output must be saved as text files.

---

## 4.6 Reporting

The system shall generate:

### Human-Readable Report

Must include:

- Capture duration
- Interface information
- DNS error counts
- DHCP anomaly counts
- Connection failure counts
- ICMP error counts
- Event timeline summary
- Triage output summary

### Machine-Readable Report

JSON file containing:

- Schema version
- Capture metadata
- Event list
- Counts per protocol
- Artifact file names
- SHA256 hashes of artifacts

---

## 4.7 Artifact Bundle

The system shall output a structured directory containing:

- Original PCAP
- Filtered PCAP slices
- Summary report
- JSON report
- Triage outputs

The directory must be optionally compressed into a single archive.

---

# 5. Nonfunctional Requirements

## 5.1 Performance

- Must not exceed defined CPU threshold during capture.
- Must enforce capture duration and size limits.
- Must not significantly degrade network performance.

## 5.2 Reliability

- Must fail gracefully if:
  - Npcap is not installed
  - No admin privileges
  - Interface is unavailable
- Must provide meaningful error messages.

## 5.3 Security

- No credential access.
- No packet injection.
- No spoofing.
- No remote command execution.
- All triage actions logged.
- Artifact integrity hashes generated.

## 5.4 Modularity

Architecture must be separated into modules:

- Capture
- Parser
- Detection
- Slicer
- Triage
- Report
- CLI

Modules must communicate via defined interfaces.

---

# 6. Acceptance Criteria

Phase 1 is considered complete when:

1. Tool runs successfully on Windows 10 and 11.
2. DNS NXDOMAIN detection works in controlled test.
3. TCP SYN retransmit detection works in controlled test.
4. ICMP unreachable detection works in controlled test.
5. Sliced PCAP files are generated correctly.
6. Summary report accurately reflects detected events.
7. Triage commands execute and outputs are stored.
8. Artifact bundle structure is consistent across runs.

---

# 7. Constraints

- CLI only.
- Windows-only.
- No background service mode.
- No HTTPS communication in Phase 1.
- No GUI.
- No adaptive behavior based on packet payload content.

---

# 8. Success Metric

Phase 1 is successful if:

- Engineers can identify probable root cause domains faster than manual PCAP inspection.
- Artifact bundles provide actionable data for escalation.
- Real-world intermittent cases are resolved more efficiently using Wulfgar output.

---

# Summary

Wulfgar Phase 1 is a deterministic, modular, Windows-based diagnostic CLI tool that captures, analyzes, and packages network artifacts to reduce time-to-diagnosis for intermittent connectivity issues in MSP environments.
