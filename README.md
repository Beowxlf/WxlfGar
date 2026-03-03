# Wulfgar

Wulfgar is a Windows-focused diagnostic artifact engine for MSP technicians investigating intermittent internet connectivity issues. It captures and analyzes network evidence, runs deterministic triage, and outputs a structured artifact bundle to reduce time-to-diagnosis.

## Why Wulfgar Exists

Intermittent connectivity incidents are often difficult to troubleshoot in real time. By the time support engages, conditions may have cleared and no packet-level evidence remains. Wulfgar is designed to provide reproducible, structured diagnostics from the time window around a failure event.

## Phase 1 Scope (Current Product Target)

Phase 1 defines a **local Windows CLI** workflow (Windows 10/11) with no server dependency:

- Select active network interface and capture traffic
- Parse PCAP traffic for key protocols:
  - DNS
  - DHCP
  - HTTP / HTTPS
  - SMB
  - ICMP
- Detect and timestamp high-signal anomalies (examples):
  - DNS NXDOMAIN/SERVFAIL/REFUSED and unanswered repeats
  - DHCP Discover-without-Offer, Request-without-Ack
  - TCP SYN retransmissions, timeouts, resets, inferable TLS handshake failures
  - SMB port 445 failures and resets during session setup
  - ICMP destination unreachable / TTL exceeded
- Slice PCAP data around each event (60s before and 60s after)
- Run deterministic, allowlisted triage commands
- Produce a structured diagnostic bundle with reports and integrity metadata

## Artifact Bundle Output

A run produces a structured artifact directory containing:

- Original PCAP
- Event-focused filtered PCAP slices
- Human-readable summary report
- Machine-readable JSON report
- Triage command output logs
- SHA256 hashes for artifact integrity

## Deterministic Triage Commands (Allowlisted)

- `nslookup google.com`
- `ipconfig /all`
- `route print`
- `arp -a`
- `netsh interface show interface`

Wulfgar explicitly disallows arbitrary command execution.

## Security and Guardrails

Wulfgar is intentionally diagnostic and non-offensive. It does **not**:

- Inject or craft packets
- Spoof IP/MAC addresses
- Manipulate live sessions
- Access credential stores
- Execute remote commands
- Operate stealthily or perform lateral movement

## Roadmap Overview

Wulfgar’s documented roadmap progresses through:

1. **Phase 1:** Local Windows CLI artifact generator
2. **Phase 2:** Secure HTTPS server integration for artifact upload/storage
3. **Phase 3:** Optional background agent mode with trigger-based capture
4. **Phase 4:** Multi-platform expansion (Linux/macOS)
5. **Phase 5:** Correlation and analytical enhancements

## Intended User

Primary user: **MSP technicians** handling customer-reported intermittent internet issues.

## Repository Contents

This repository currently contains product and architecture documentation for Wulfgar, including:

- Statement of purpose
- Scope and guardrails
- Product requirements
- Module architecture
- Artifact/schema definitions
- Security/trust model
- Test plan and technician SOP

## Status

Planning/specification stage focused on a reliable Phase 1 baseline and schema-stable artifact generation.
