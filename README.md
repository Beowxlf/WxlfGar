# Wulfgar

Wulfgar is a Windows-focused diagnostic CLI project for MSP technicians investigating intermittent internet connectivity issues. This repository now includes a **Go project skeleton** aligned to the architecture, schema, and guardrails documented in `Documents/`.

## What this repository contains

- Product and architecture documents in `Documents/`
- Phase 1 Go module skeleton (`cmd/`, `internal/`)
- Machine report JSON schema starter in `schemas/`
- Example artifact-bundle directory shape in `examples/`

## Phase 1 module skeleton (Go)

```
cmd/wulfgar/main.go
internal/
  contracts/
  orchestrator/
  modules/
    capture/
    parser/
    detection/
    slicer/
    triage/
    report/
    bundle/
    integrity/
```

Execution flow (as designed):

`CLI -> Capture -> Parser -> Detection -> Slicer -> Triage -> Report -> Bundle -> Integrity`

## Current status

This is a scaffold implementation intended to establish:

- Module boundaries and contracts
- Bundle layout conventions
- `machine.json` schema direction
- Deterministic, allowlisted triage command list

Modules now perform baseline Phase 1 behavior (offline pcap parse, deterministic detection, slice generation, triage logging, reporting, and hashing). Live capture is guarded to Windows/Npcap and returns a clear error on other platforms.
Most modules currently provide no-op/stub behavior to keep architecture and contracts explicit while implementation is built out.

## Quick start (skeleton run)

```bash
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output --input-pcap ./path/to/capture.pcap
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output
```

Optional:

```bash
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output --input-pcap ./path/to/capture.pcap --compress
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output --compress
```

## Guardrails

Wulfgar is diagnostic-only. This scaffold preserves the documented constraints:

- No packet injection/crafting
- No spoofing
- No arbitrary command execution
- No credential access or remote shell behavior

## Next implementation steps

1. Implement real Windows capture integration (Npcap-backed capture module).
2. Implement parser and protocol-normalization pipeline.
3. Implement detection rules and metrics.
4. Implement slice filtering around event timestamps.
5. Add schema validation tests and end-to-end fixture tests.
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
