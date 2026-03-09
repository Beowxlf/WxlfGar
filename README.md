# Wulfgar

Wulfgar is a Windows-focused diagnostic CLI for MSP technicians investigating intermittent internet connectivity issues. It captures and analyzes network evidence, runs deterministic local triage, and outputs a structured artifact bundle for faster, repeatable diagnosis.

## Current Repository Status

This repository is in an early implementation state: architecture and guardrails are defined, and a Phase 1 Go pipeline is present for end-to-end artifact generation.

Implemented in this Phase 1 baseline:

- Go module and CLI entrypoint (`cmd/wulfgar`)
- Pipeline module layout under `internal/modules`
- Machine-readable schema starter (`schemas/machine.schema.json`)
- Documentation set in `Documents/`
- Example artifact bundle layout in `examples/`

## Phase 1 Scope (Windows Local CLI)

Phase 1 targets a **local Windows 10/11 workflow** with no server dependency:

- Select a network interface and run a bounded live capture window
- Parse packet data for high-signal connectivity protocols
- Detect timestamped connectivity anomalies
- Slice packet data around key event windows
- Run deterministic, allowlisted triage commands
- Generate a structured artifact bundle with integrity metadata

Designed processing flow:

`CLI -> Capture -> Parser -> Detection -> Slicer -> Triage -> Report -> Bundle -> Integrity`

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

## Artifact Bundle Output

A typical run produces:

- Original packet capture input
- Event-focused packet slices
- Human-readable summary report
- Machine-readable JSON report
- Triage command output logs
- SHA256 integrity hashes

See `examples/` for a representative bundle structure.

## Deterministic Triage (Allowlisted)

Wulfgar intentionally restricts triage to a fixed command allowlist:

- `nslookup google.com`
- `ipconfig /all`
- `route print`
- `arp -a`
- `netsh interface show interface`

## Security and Guardrails

Wulfgar is diagnostic-only. It does **not**:

- Inject or craft packets
- Spoof network identities
- Execute arbitrary or remote commands
- Access credential stores
- Perform offensive or stealth behavior

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
