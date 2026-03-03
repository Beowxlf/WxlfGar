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

Most modules currently provide no-op/stub behavior to keep architecture and contracts explicit while implementation is built out.

## Quick start (skeleton run)

```bash
go run ./cmd/wulfgar --interface Ethernet --duration 30s --out ./output
```

Optional:

```bash
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
