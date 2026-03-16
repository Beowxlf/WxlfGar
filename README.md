# Wulfgar

Wulfgar is a Windows-focused diagnostic CLI for MSP technicians investigating intermittent internet connectivity issues. It captures and analyzes network evidence, runs deterministic local triage, and outputs a structured artifact bundle for faster, repeatable diagnosis.

## Problem

Intermittent connectivity incidents are notoriously difficult to diagnose because evidence disappears before a technician can observe the failure state directly. By the time manual checks begin, packet-level context, transient DNS behavior, and route/interface state often look normal.

## Why normal troubleshooting fails

Traditional troubleshooting for "internet is slow/drops sometimes" usually relies on ad-hoc commands and point-in-time observation. That approach fails when failures are brief, non-reproducible, or dependent on timing. Common gaps include:

- No packet evidence captured at failure time
- No consistent artifact format between technicians
- Incomplete timeline correlation across DNS, transport, and host state
- Manual command selection that varies by operator

## Wulfgar approach

Wulfgar standardizes investigation into a deterministic local workflow that:

- Captures bounded packet evidence
- Detects high-signal connectivity events with timestamps
- Slices packet windows around those events
- Runs a fixed triage command allowlist
- Produces a repeatable artifact bundle with integrity hashes

Designed processing flow:

`CLI -> Capture -> Parser -> Detection -> Slicer -> Triage -> Report -> Bundle -> Integrity`

## Guardrails

Wulfgar is diagnostic-only. It does **not**:

- Inject or craft packets
- Spoof network identities
- Execute arbitrary or remote commands
- Access credential stores
- Perform offensive or stealth behavior

## Sample output

A typical run produces:

- Original packet capture input
- Event-focused packet slices
- Human-readable summary report
- Machine-readable JSON report
- Triage command output logs
- SHA256 integrity hashes

See `examples/` for a representative bundle structure.

## Current status

This repository is in an early implementation state: architecture and guardrails are defined, and a Phase 1 Go pipeline is present for end-to-end artifact generation.

Implemented in this Phase 1 baseline:

- Go module and CLI entrypoint (`cmd/wulfgar`)
- Pipeline module layout under `internal/modules`
- Machine-readable schema starter (`schemas/machine.schema.json`)
- Documentation set in `Documents/`
- Example artifact bundle layout in `examples/`

## Roadmap

Wulfgar's phased roadmap is documented in `Documents/03-Phase-Roadmap.md`.

- **Phase 1:** Local Windows diagnostic CLI and artifact generation
- **Phase 2:** Secure server integration for artifact upload and storage
- **Phase 3:** Optional modular agent mode with trigger-based capture
- **Phase 4:** Multi-platform expansion (Linux and macOS)
- **Phase 5:** Intelligence and correlation enhancements

## CLI Usage (Top-Level Flags)

The current CLI is **top-level flags only**.

Subcommands such as `capture` are **not supported** in this release.

### Discover interfaces

```bash
wulfgar.exe --list-interfaces
```

This prints available capture interfaces as reported by Npcap (device name and description when available).

### Live capture (Windows + Npcap)

```bash
wulfgar.exe --interface "Ethernet 3" --duration 30s --out .\output
```

### Offline replay mode (`--input-pcap`)

```bash
wulfgar.exe --input-pcap .\path\to\capture.pcap --out .\output
```

Optional compression flag for either mode:

```bash
wulfgar.exe --interface "Ethernet 3" --duration 30s --out .\output --compress
wulfgar.exe --input-pcap .\path\to\capture.pcap --out .\output --compress
```

## Windows live capture requirements

Live capture requires:

- Windows 10/11
- Npcap installed with WinPcap-compatible API support
- Sufficient privileges to open the capture device (run elevated if required)

If Npcap is unavailable, interface enumeration or live capture will fail with a deterministic error message.

## Deterministic Triage (Allowlisted)

Wulfgar intentionally restricts triage to a fixed command allowlist:

- `nslookup google.com`
- `ipconfig /all`
- `route print`
- `arp -a`
- `netsh interface show interface`

## Documentation Map

Detailed product and architecture documentation is available in `Documents/`:

- `01-Statement-of-Purpose.md`
- `02-Scope-and-Guardrails.md`
- `03-Phase-Roadmap.md`
- `04-Product-Requirments.md`
- `05-Artifact-and-Schema-Spec.md`
- `06-Module-Architecture-Specification.md`
- `07-Security-and-Trust-Model.md`
- `08-Test-Plan.md`
- `09-Technician-SOP.md`

Supplemental status material is available in `Audits/`, `Logs/`, and `Reports/`.
