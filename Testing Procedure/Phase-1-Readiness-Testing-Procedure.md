# Wulfgar
## Phase 1 Readiness Testing Procedure
Version: 1.0  
Scope: Phase 1 local Windows CLI validation  
Audience: QA engineers, MSP technicians, release reviewers

---

## 1. Objective

This procedure defines the **first rounds of testing** required to verify Wulfgar is **Phase 1 ready**. It provides:

- Tool download and install steps
- Required test environment and device setup
- Structured testing rounds with pass/fail gates
- Evidence collection and reporting workflow

Phase 1 readiness is achieved only when all mandatory round exit criteria are met.

---

## 2. Tool Download and Installation Procedure

### 2.1 Source of Truth

Use only one of the following approved sources:

1. The official release artifact attached to the tagged Phase 1 release.
2. A vetted internal build generated from the release commit SHA.

Do not test untracked binaries.

### 2.2 Download Steps

1. Create a local working directory, for example: `C:\WulfgarTest\build`.
2. Download `wulfgar.exe` from the approved source.
3. Save release notes and checksum file into `C:\WulfgarTest\build\release-metadata`.
4. Compute SHA256 locally:
   - PowerShell: `Get-FileHash .\wulfgar.exe -Algorithm SHA256`
5. Compare with the published checksum.
6. If checksum mismatch occurs, stop testing and raise a build integrity incident.

### 2.3 Installation Steps

1. Copy `wulfgar.exe` to `C:\WulfgarTest\bin`.
2. Create output root `C:\WulfgarTest\output`.
3. Confirm execution permission from an elevated shell.
4. Install Npcap on the device if not already present.
5. Validate Npcap is active before test execution.

---

## 3. Required Test Environment (Device Baseline)

### 3.1 Operating System Matrix

Run test rounds on:

- Windows 10 (latest supported patch level)
- Windows 11 (latest supported patch level)

### 3.2 Device and Runtime Requirements

Each device must include:

- Administrative privileges for capture-related actions
- At least one active Ethernet or Wi-Fi interface
- Stable internet access for baseline protocol generation
- Npcap installed and functioning
- Sufficient disk space for PCAP + slices + reports (minimum 2 GB free)

### 3.3 Controlled Test Conditions

Prepare three network states:

1. **Normal state**: healthy DNS/DHCP/TCP behavior
2. **Degraded state**: intermittent packet loss and DNS disruptions
3. **Failure state**: targeted faults (e.g., blocked DNS, unreachable hosts)

Use repeatable fault injection methods (firewall rules, unreachable endpoints, isolated test gateway) so rounds can be replayed consistently.

---

## 4. First Rounds of Testing

## Round 1: Installation and Smoke Validation

### Goal
Confirm the tool can be downloaded, verified, launched, and complete a basic run.

### Steps

1. Verify checksum for `wulfgar.exe`.
2. Start elevated terminal in `C:\WulfgarTest\bin`.
3. Run a baseline command using a known interface.
4. Confirm the run exits cleanly.
5. Confirm output bundle directory is created.

### Expected Output

- Executable starts without runtime crash
- Output folder contains report artifacts
- Clear error messages appear for invalid flags (if exercised)

### Exit Gate

- PASS: 100% of smoke checks pass on both Windows 10 and Windows 11 devices.
- FAIL: Any startup crash, missing artifact directory, or integrity mismatch.

---

## Round 2: Core Functional Phase 1 Validation

### Goal
Validate all core Phase 1 behaviors under expected and faulted traffic.

### Mandatory Scenario Set

1. Packet capture produces original PCAP.
2. Detection identifies at least one event from each in-scope protocol group tested in the session (DNS/TCP/ICMP minimum).
3. Slicer generates event-focused PCAP slices around timestamps.
4. Triage commands execute only from allowlist and save outputs.
5. Human-readable summary and machine-readable report are generated.
6. Integrity hashes are produced for artifacts.

### Steps

1. Execute a controlled capture during normal traffic.
2. Trigger DNS failure behavior (NXDOMAIN or timeout pattern).
3. Trigger TCP reliability fault (SYN retransmit or reset-heavy flow).
4. Trigger ICMP unreachable event.
5. Re-run and collect output bundles for each scenario.
6. Inspect generated artifacts and event metadata consistency.

### Exit Gate

- PASS: All mandatory scenarios produce expected artifact and report outcomes.
- FAIL: Missing event capture, missing slices, triage non-determinism, or invalid artifact structure.

---

## Round 3: Negative and Resilience Validation

### Goal
Verify predictable, safe failure behavior and non-offensive guardrail compliance.

### Mandatory Negative Cases

1. Npcap missing
2. Non-admin execution
3. Invalid network interface
4. Unsupported argument values
5. Insufficient output disk space (simulated)

### Steps

1. Execute each negative case in isolation.
2. Capture console output and return code.
3. Verify tool fails gracefully and does not leave corrupted partial artifacts.
4. Verify no out-of-scope behavior (packet injection, arbitrary command execution).

### Exit Gate

- PASS: All negative cases produce clear and deterministic failure responses.
- FAIL: Panic, silent failure, unsafe side effects, or broken guardrails.

---

## Round 4: Phase 1 Readiness Confirmation Run

### Goal
Run a final end-to-end confirmation using release-candidate build and full evidence packaging.

### Steps

1. Execute a full capture workflow in a realistic technician session.
2. Trigger at least two distinct anomaly classes during the run.
3. Confirm full artifact bundle creation.
4. Validate hash manifest and report completeness.
5. Archive logs, machine report, and summary report for sign-off.

### Exit Gate

- PASS: Release candidate is marked **Phase 1 Ready**.
- FAIL: Any mandatory artifact, integrity data, or detection output missing.

---

## 5. How Testing Should Be Performed (Execution Rules)

1. Use the same command templates across devices to reduce variation.
2. Record start/end timestamps for every run.
3. Keep one test variable changed per rerun whenever possible.
4. Preserve raw outputs; do not manually edit generated artifacts.
5. Log each failure with:
   - Build SHA
   - OS version
   - Interface tested
   - Reproduction steps
   - Expected vs actual result
6. Re-test failed scenarios after fix using identical environment conditions.

---

## 6. Evidence Collection and Sign-Off

For each round, collect:

- Command history used to run tests
- Console output transcripts
- Generated artifact bundle(s)
- Hash files
- Tester notes and defect links

A release can be signed off as Phase 1 ready only when:

- All round exit gates are PASS
- No unresolved Sev-1 or Sev-2 defects remain
- Artifact output is schema-compliant and reproducible

---

## 7. Minimum Pass Criteria Checklist (Phase 1 Ready)

- [ ] Binary integrity verified by checksum
- [ ] Smoke run passes on Windows 10 and Windows 11
- [ ] Core functional scenarios pass
- [ ] Negative and resilience scenarios pass
- [ ] Guardrails validated (diagnostic-only behavior)
- [ ] Full readiness confirmation run passes
- [ ] Evidence package stored for audit and handoff

When all checklist items are complete, Wulfgar can be declared **Phase 1 ready for controlled rollout**.
