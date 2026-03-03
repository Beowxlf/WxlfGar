# Wulfgar
## Phase Roadmap
**Version:** 0.1  
**Initial Platform:** Windows 10 and Windows 11  

---

## 1. Purpose of This Document

This roadmap defines the structured evolution of Wulfgar from a local diagnostic CLI tool to a secure, modular, distributed diagnostic system for MSP environments.

Each phase includes:

- Objectives
- In-scope features
- Explicit exclusions
- Exit criteria (Definition of Done)

No phase may expand without formal revision.

---

# Phase 1 — Local Diagnostic CLI (Windows)

## Objective

Deliver a stable Windows-based CLI tool that generates structured diagnostic artifact bundles during intermittent internet issue investigations.

## In Scope

- Windows 10 and Windows 11 support
- Local packet capture
- Protocol analysis:
  - DNS
  - DHCP
  - HTTP
  - HTTPS
  - SMB
  - ICMP
- Event timestamp detection
- 60-second pre/post PCAP slicing
- Deterministic triage commands:
  - `nslookup google.com`
  - `ipconfig /all`
  - `route print`
  - `arp -a`
  - `netsh interface show interface`
- Structured output bundle:
  - Original PCAP
  - Filtered PCAP slices
  - Human-readable summary
  - Machine-readable JSON
  - Triage outputs

## Explicit Exclusions

- Background persistent agent
- Server communication
- Multi-tenant support
- GUI interface
- Topology mapping
- Packet injection or crafting
- Remote execution capability

## Exit Criteria

Phase 1 is complete when:

1. Tool runs reliably on Windows 10 and 11.
2. At least DNS, TCP retransmit, and ICMP errors are detected correctly.
3. Artifact bundle is consistent and schema-stable.
4. Tool does not degrade system performance significantly.
5. At least 3 real-world intermittent cases have been successfully analyzed using Wulfgar artifacts.

---

# Phase 2 — Secure Server Integration

## Objective

Enable secure HTTPS-based artifact upload and centralized storage.

## In Scope

- HTTPS communication
- Enrollment token mechanism
- Server-side artifact storage
- Org and site identification
- Authentication and authorization
- Artifact retrieval interface
- Audit logging
- Integrity validation via checksums

## Security Controls

- HTTPS encryption
- Mutual TLS support
- Role-based access control
- Immutable audit logs

## Explicit Exclusions

- Remote command execution
- Live session manipulation
- Active probing of networks
- Stealth persistence

## Exit Criteria

1. Agents can securely enroll.
2. Artifacts upload successfully over HTTPS.
3. Server stores artifacts per organization.
4. Access is restricted and logged.
5. No plaintext sensitive traffic is transmitted.

---

# Phase 3 — Modular Agent Mode

## Objective

Convert Wulfgar from on-demand CLI tool to optional lightweight background agent.

## In Scope

- Service-based Windows agent mode
- Configurable capture triggers:
  - DNS failure rate thresholds
  - Interface state changes
  - Gateway changes
  - Packet loss indicators
- Ring buffer PCAP storage
- Automatic artifact generation upon trigger

## Explicit Exclusions

- Arbitrary remote shell
- Dynamic packet crafting
- Credential harvesting
- Lateral movement capabilities

## Exit Criteria

1. Agent runs with stable resource usage.
2. Triggered captures produce valid artifacts.
3. System remains fully auditable.
4. No stealth behavior is introduced.

---

# Phase 4 — Multi-Platform Expansion

## Objective

Extend support beyond Windows.

## Target Platforms

- Linux
- macOS

## Requirements

- Cross-platform capture compatibility
- Unified schema across OS types
- Consistent artifact structure

## Exit Criteria

1. All platforms generate equivalent artifact bundles.
2. Core detection logic remains consistent.
3. No platform-specific instability.

---

# Phase 5 — Intelligence and Correlation Enhancements

## Objective

Enhance analytical depth without compromising guardrails.

## Possible Additions

- Pattern-based anomaly scoring
- Historical artifact comparison
- Event frequency analytics
- Structured trend reporting

## Hard Constraint

No offensive or manipulative capabilities may be introduced.

---

# Long-Term Vision

Wulfgar evolves into:

- A structured diagnostic artifact engine
- A secure distributed system
- A deterministic troubleshooting accelerator for MSP environments

It does not evolve into:

- A red team framework
- A stealth monitoring tool
- A command-and-control system

---

# Versioning Policy

Each phase must:

1. Lock schema version.
2. Document feature additions.
3. Maintain backward compatibility where possible.
4. Include a changelog.

---

# Summary

Phase 1: Local Windows CLI artifact generator  
Phase 2: Secure HTTPS server integration  
Phase 3: Optional background agent with trigger engine  
Phase 4: Cross-platform support  
Phase 5: Analytical enhancements  

No phase expands scope without formal documentation revision.
