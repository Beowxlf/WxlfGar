# Wulfgar Repository State Audit (Phase 1)

**Date:** 2026-03-06  
**Audited Scope:** Current repository implementation vs. `Documents/` Phase 1 requirements.

## Executive Summary

The repository is **buildable and testable**, and the module boundaries align with the intended pipeline (`Capture -> Parser -> Detection -> Slicer -> Triage -> Report -> Bundle -> Integrity`).

However, the implementation is still a **partial Phase 1 scaffold** and does **not yet satisfy Phase 1 completion criteria** from the PRD/Test Plan. The largest blockers are around capture realism, slice fidelity, schema/integrity correctness, and full detection parity.

## Current State Snapshot

- The code compiles and existing unit tests pass (`go test ./...`).
- The CLI runs in offline mode via `--input-pcap` and produces a bundle structure.
- Live capture is Windows-gated and otherwise returns a clear error.
- Triage execution is deterministic and allowlisted (no dynamic command input).
- Parser/detection currently implement core protocol parsing and a subset of detection signals.

## What Must Be Fixed to Accomplish Phase 1

1. **Fix artifact hash lifecycle bug** so `machine.json` hash in `hashes.txt` remains valid after final report generation.
2. **Add end-to-end schema validation tests** for `machine.json` (required by test plan).
3. **Implement true event-window slicing** (60s before/after), rather than full-file copy per event.
4. **Complete detection coverage** for all required indicators (DNS timeout repeats, TCP timeout/TLS inferable failures, SMB failure modes, DHCP sequence robustness).
5. **Implement capture size-limit stop behavior** and metadata/report indication of size-based termination.
6. **Run/automate negative tests** for Npcap missing, no admin privileges, and invalid interface handling on supported Windows targets.
7. **Implement/report validation for artifact-list consistency** (slice files in JSON must match physical files).
8. **Add stability/performance validation artifacts** (repeated-run and longer capture checks) required for acceptance.

## Issues as of Right Now

| ID | Severity | Area | Issue | Why It Matters for Phase 1 | Recommended Fix |
|---|---|---|---|---|---|
| P1-001 | High | Integrity/Report | `hashes.txt` is generated before final `machine.json` rewrite, so `machine.json` hash can become stale. | Violates schema/integrity validation expectations in test plan. | Reorder flow: finalize `machine.json` once, then hash; or regenerate hashes after final write. |
| P1-002 | High | Slicer | Slicer currently copies the full source PCAP for every event rather than extracting ±60s around event timestamp. | Fails functional requirement for targeted event windows. | Add timestamp-based frame filtering and write bounded slices. |
| P1-003 | High | Detection | Detection coverage is incomplete vs PRD (e.g., DNS repeated no-response timeout behavior, TCP timeout/TLS-failure inference depth). | Prevents functional completion and acceptance criteria. | Expand detection rules and tests per protocol matrix in test plan. |
| P1-004 | Medium | Capture | Size limit logic truncates offline copy but does not represent true live capture stop semantics/report signaling. | Size-limit enforcement test case expects safe stop + explicit reporting. | Add capture stop condition tracking and summary flag for size-based termination. |
| P1-005 | Medium | Schema Quality | No automated machine schema validation is currently enforced in Go tests. | Test plan explicitly requires schema conformance each run. | Add schema validation test harness for produced `machine.json`. |
| P1-006 | Medium | Artifact Consistency | No explicit run-level check that slice files listed in JSON always exist and match expected set. | Required validation criterion in test plan. | Add integration test asserting artifact list/file-system parity. |
| P1-007 | Medium | Triage Realism | Triage outputs are stubbed with `output=stub` rather than command execution context from live Windows runs. | Limits practical diagnostic utility in real incidents. | Execute allowlisted commands on Windows path; keep deterministic fallback for unsupported platforms/tests. |
| P1-008 | Medium | Platform Validation | Test plan requires Windows 10/11 validation (Npcap/admin/interface behaviors), not yet represented in repo evidence. | Phase 1 acceptance cannot be claimed without platform validation evidence. | Add CI/manual validation matrix and stored run artifacts for Windows scenarios. |
| P1-009 | Low | Reporting | Summary is minimal and does not yet include richer event timeline/triage summaries described in PRD. | Gaps against report completeness expectations. | Extend summary renderer with timeline + per-domain anomaly narrative. |
| P1-010 | Low | Documentation Hygiene | Existing issue tracker report is initialized but not populated with actionable findings. | Can slow execution tracking toward Phase 1 closure. | Sync this audit into ongoing `Reports/` issue tracking workflow. |

## Recommended Execution Order (Fastest Path to Phase 1)

1. **Integrity and schema correctness first** (P1-001, P1-005, P1-006).
2. **Detection and slicing correctness second** (P1-002, P1-003).
3. **Capture semantics and reporting fidelity third** (P1-004, P1-009).
4. **Windows validation and operational hardening last** (P1-007, P1-008, P1-010).

## Exit Criteria for This Audit

This repository should be considered Phase-1-ready only after:

- Functional and negative tests in `Documents/08-Test-Plan.md` are demonstrably passing on supported Windows targets.
- Schema/integrity checks are automated and green.
- Generated bundles consistently match required structure and event-slice semantics.
- Guardrails remain intact (no dynamic or off-policy behavior introduced).
