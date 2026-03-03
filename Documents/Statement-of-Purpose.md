# Wulfgar
## Statement of Purpose
**Version:** 0.1  
**Platform:** Windows 10 and Windows 11  

---

## 1. Problem Statement

Managed Service Providers frequently encounter customer reports of **intermittent internet connectivity issues** where:

1. The issue is not reproducible during live troubleshooting.
2. The network appears operational at the time of investigation.
3. No packet capture or structured evidence exists from the moment of failure.
4. Engineers must rely on guesswork or wait for recurrence.

This results in:

- Increased time-to-diagnosis  
- Repeated support calls  
- Inefficient escalation  
- Reduced customer confidence  

---

## 2. Mission

Wulfgar is a Windows-based diagnostic tool designed to automatically capture, analyze, and package structured network evidence in order to reduce the time required to diagnose intermittent internet issues.

---

## 3. Primary Objective

When a technician runs Wulfgar during or immediately after a reported intermittent issue, the tool shall:

1. Capture network traffic.
2. Identify high-signal protocol anomalies.
3. Generate a structured summary of findings.
4. Extract focused PCAP slices around detected error events.
5. Execute predefined deterministic triage commands.
6. Produce a single exportable diagnostic artifact bundle.

---

## 4. Target Use Case

**Primary user:** MSP technician  

**Trigger condition:** Customer reports intermittent connectivity problems including but not limited to:

- DNS resolution failures  
- Web browsing issues  
- SMB access instability  
- Packet loss symptoms  
- Gateway or routing instability  

---

## 5. Scope of Phase 1

### Platform Support

- Windows 10  
- Windows 11  

### Capabilities

- Local packet capture  
- Protocol analysis for:
  - DNS  
  - DHCP  
  - HTTP  
  - HTTPS  
  - SMB  
  - ICMP  
- Event timestamp detection  
- PCAP slicing (60 seconds before and after detected events)  
- Deterministic triage commands such as:
  - `nslookup google.com`  
  - `ipconfig /all`  
  - `route print`  
  - `arp -a`  

### Output

- Human-readable summary report  
- Machine-readable JSON report  
- Original PCAP  
- Filtered PCAP slices  
- Triage output logs  

---

## 6. Non-Goals

Wulfgar shall not:

- Craft or inject packets  
- Spoof IP or MAC addresses  
- Manipulate live sessions  
- Access credential stores  
- Execute arbitrary commands  
- Operate stealthily  
- Perform lateral movement  
- Act as a remote shell  

---

## 7. Success Criteria

Phase 1 is considered successful if:

1. Wulfgar consistently produces usable artifact bundles during intermittent issue investigations.
2. Technicians can identify likely failure domains faster than manual packet inspection alone.
3. Time-to-diagnosis is measurably reduced in targeted incident categories.

---

## 8. Design Philosophy

Wulfgar is:

- Diagnostic, not offensive  
- Deterministic, not adaptive  
- Evidence-focused, not speculative  
- Modular for future expansion  
- Secure by design in preparation for future HTTPS server integration  

---

## Summary

Wulfgar is a Windows-based diagnostic artifact engine that captures and analyzes network traffic to reduce time-to-diagnosis for intermittent internet issues in MSP environments, while strictly avoiding offensive or manipulative capabilities.
