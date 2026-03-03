# Wulfgar
## Scope and Guardrails
**Version:** 0.1  
**Platform:** Windows 10 and Windows 11  

---

## 1. Purpose of This Document

This document defines the operational boundaries, feature limits, and security constraints for Wulfgar Phase 1.  

Its purpose is to:

- Prevent scope creep  
- Prevent unintended capability drift  
- Maintain a strictly diagnostic posture  
- Ensure professional and ethical deployment within MSP environments  

No feature outside this document may be added without explicit revision.

---

## 2. Phase 1 Scope

### 2.1 In Scope

Wulfgar Phase 1 shall support the following capabilities:

#### 1. Local Packet Capture
- Capture traffic on a selected network interface
- Configurable capture duration
- Maximum file size protection
- Local storage of PCAP file

#### 2. Protocol Analysis

Parse captured PCAP for indicators involving:

- DNS
- DHCP
- HTTP
- HTTPS
- SMB
- ICMP

#### 3. Event Detection

Detect and timestamp:

- DNS errors (NXDOMAIN, SERVFAIL, timeouts)
- DHCP Discover without Offer
- DHCP Request without Ack
- TCP SYN retransmissions
- TCP connection resets
- ICMP unreachable or TTL exceeded messages

#### 4. PCAP Slicing

For each detected event:

- Extract 60 seconds before event
- Extract 60 seconds after event
- Apply protocol-relevant filtering
- Save as separate filtered PCAP file

#### 5. Deterministic Triage Commands

Allowed commands (hardcoded whitelist):

- `nslookup google.com`
- `ipconfig /all`
- `route print`
- `arp -a`
- `netsh interface show interface`

No other system commands may be executed.

#### 6. Artifact Bundling

Generate a structured output bundle containing:

- Original PCAP
- Filtered PCAP slices
- Human-readable summary
- Machine-readable JSON report
- Triage command outputs

---

## 3. Explicit Non-Goals

The following capabilities are explicitly prohibited in Phase 1:

- Packet crafting
- Packet injection
- IP or MAC spoofing
- Raw socket manipulation
- Session hijacking
- Network interference
- Credential access
- Credential extraction
- Process injection
- Privilege escalation mechanisms
- Lateral movement functionality
- Remote shell capability
- Arbitrary command execution
- Stealth persistence mechanisms

Wulfgar is diagnostic only.

---

## 4. Operational Guardrails

### 4.1 Consent Requirement

Wulfgar shall only be deployed:

- On systems owned or administered by the MSP
- With documented administrative consent

### 4.2 Visibility

Wulfgar shall:

- Run visibly as a standard executable
- Not hide processes
- Not attempt evasion of monitoring tools
- Provide clear output and logs

### 4.3 Determinism

Wulfgar shall:

- Execute only predefined diagnostic actions
- Never dynamically generate network traffic based on packet content
- Never modify live network sessions

### 4.4 Data Handling

Wulfgar shall:

- Not inspect encrypted payload contents
- Not extract application-level sensitive data
- Not retain artifacts longer than operationally required
- Support future encryption of artifact bundles

---

## 5. Performance Constraints

Wulfgar must:

- Enforce capture duration limits
- Enforce file size limits
- Avoid excessive CPU utilization
- Avoid degrading network performance

---

## 6. Security Posture

Even in Phase 1 (local-only), Wulfgar must:

- Log all executed triage actions
- Produce checksums for artifact integrity
- Prepare architecture for future HTTPS and mTLS integration
- Avoid hardcoding secrets

---

## 7. Architectural Discipline

All functionality must be modular:

- Capture module
- Parser module
- Detection module
- Slicer module
- Triage module
- Report module

No cross-module hidden dependencies.

---

## 8. Change Control Policy

Any proposal to add:

- Network manipulation
- Raw packet generation
- Remote command execution
- Credential-related functionality

Requires:

1. Written justification
2. Scope document revision
3. Explicit approval before implementation

---

## Summary

Wulfgar Phase 1 is a strictly diagnostic Windows tool designed to capture, analyze, and package network artifacts for intermittent issue investigation.

It is not an offensive tool.
It is not a remote control platform.
It is not a stealth agent.

It is a structured evidence generator for MSP troubleshooting.
