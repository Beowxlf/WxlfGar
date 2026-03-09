# Wulfgar
## Technician Standard Operating Procedure (SOP)
Version: 0.2  
Repository State: Phase 1 scaffold / baseline implementation  
Platform: Windows 10 and Windows 11 (intended), Go CLI execution also supported in dev environments

---

## 1. Purpose

This SOP explains how to use Wulfgar **as implemented right now** to generate a deterministic diagnostic artifact bundle for intermittent connectivity investigations.

This document covers:

- Appropriate use cases
- Preconditions and required inputs
- Supported command-line flags
- Recommended execution flow
- Output interpretation and technician handoff guidance

---

## 2. When to Use Wulfgar

Use Wulfgar when you need a structured, repeatable evidence bundle for intermittent or hard-to-reproduce network symptoms such as:

- DNS lookup instability
- Route or gateway flaps
- Packet loss patterns
- TCP reliability anomalies
- Session drops not reproducible during live support

Do **not** use Wulfgar for:

- Known hardware replacement workflows
- Non-network software bug triage
- Any offensive or active network manipulation activity

---

## 3. Current Tool Reality (Important)

As of this repository state:

- The end-to-end module pipeline is wired and executable.
- Offline analysis is supported through `--input-pcap` and is the safest repeatable path.
- Live capture behavior is platform/implementation dependent and should be validated in your environment before production use.
- The tool is focused on deterministic artifact creation and reproducible report generation.

Technicians should treat this SOP as the **current-state operator guide**, not a final GA production runbook.

---

## 4. Pre-Execution Checklist

Before every run, confirm:

1. You are using an elevated terminal if your workflow requires privileged capture access.
2. A target interface name is known (for consistency, even when replaying from offline PCAP).
3. Output destination has adequate free disk space.
4. You have customer consent for diagnostic capture/log collection.
5. You selected one execution mode:
   - Offline replay mode (`--input-pcap`) **recommended for repeatability**
   - Live capture mode (environment dependent)

---

## 5. Command-Line Reference (Current)

Wulfgar currently accepts these primary flags:

- `--interface` (string): network interface name label for the run metadata
- `--duration` (duration): capture duration (default `5m`)
- `--max-bytes` (int64): maximum capture size in bytes (default `536870912`)
- `--out` (string): output root directory (default `./output`)
- `--compress` (bool): create compressed bundle archive
- `--input-pcap` (string): offline PCAP path to analyze instead of live capture

---

## 6. How to Run Wulfgar

### 6.1 Recommended: Offline PCAP Replay

Use this when you already have a PCAP and want deterministic bundle generation:

```bash
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output --input-pcap ./path/to/capture.pcap
```

### 6.2 Live Capture Attempt

Use this only when your runtime environment has validated live capture support:

```bash
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output
```

### 6.3 Optional Compression

Add `--compress` to either mode:

```bash
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output --input-pcap ./path/to/capture.pcap --compress
```

---

## 7. Expected Output Bundle

A successful run produces a timestamped workspace folder containing:

- `original_capture.pcap`
- `slices/` (event-focused packet slices)
- `triage/` (allowlisted command outputs)
- `summary.txt` (human-readable summary)
- `machine.json` (machine-readable report)
- `hashes.txt` (SHA256 manifest)

If `--compress` is enabled, an archive of the bundle is also produced.

---

## 8. Triage Command Scope (Deterministic Allowlist)

Wulfgar intentionally limits triage command execution to:

- `nslookup google.com`
- `ipconfig /all`
- `route print`
- `arp -a`
- `netsh interface show interface`

No arbitrary command execution should be expected.

---

## 9. Technician Handoff Procedure

After each run:

1. Attach `summary.txt` and `machine.json` to the ticket.
2. Attach `hashes.txt` for integrity verification.
3. Include the exact command used (full flag string).
4. Record start/end timestamps and interface value.
5. If run failed, include terminal output and return code.

Recommended ticket note template:

- Run mode: Offline replay / Live capture
- Interface: `<value>`
- Duration: `<value>`
- Output path: `<value>`
- Compression: Enabled / Disabled
- Result: Success / Failed (with error)

---

## 10. Failure Handling

If execution fails:

1. Re-run with the same command to verify reproducibility.
2. Confirm path values (`--out`, `--input-pcap`) exist and are accessible.
3. Validate privilege/context requirements for your environment.
4. Preserve partial outputs for engineering review when present.
5. Escalate with command, stderr/stdout, and environment details.

---

## 11. Guardrails Reminder

Wulfgar is diagnostic-only and must not be used for:

- Packet injection
- Identity spoofing
- Remote command execution
- Credential extraction
- Any offensive or stealth operation

If required investigation steps exceed these constraints, escalate to approved security workflows outside Wulfgar.
