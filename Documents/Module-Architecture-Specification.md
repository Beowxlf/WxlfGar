# Wulfgar
## Module Architecture Specification
Version: 0.1  
Phase: Phase 1 – Local Windows CLI  
Platform: Windows 10 and Windows 11  
Language: Go  

---

# 1. Purpose

This document defines the internal module architecture for Wulfgar Phase 1.

Objectives:

- Enforce strict modular boundaries
- Prevent cross-module coupling
- Enable future HTTPS server integration
- Maintain clean separation of responsibilities
- Support long-term maintainability

All code must conform to this architecture.

---

# 2. Architectural Principles

Wulfgar shall follow these design principles:

1. Single responsibility per module.
2. No hidden cross-module dependencies.
3. Communication through well-defined interfaces.
4. Deterministic execution.
5. No dynamic runtime feature injection.
6. Schema-driven output enforcement.

---

# 3. High-Level Architecture

Wulfgar is a CLI-driven orchestration system composed of the following modules:

- CLI
- Capture
- Parser
- Detection
- Slicer
- Triage
- Report
- Bundle
- Integrity

Execution Flow:

CLI  
→ Capture  
→ Parser  
→ Detection  
→ Slicer  
→ Triage  
→ Report  
→ Bundle  
→ Integrity  

---

# 4. Module Definitions

---

## 4.1 CLI Module

### Responsibility

- Entry point
- Argument parsing
- Orchestration of module execution
- Error handling coordination

### Inputs

- Capture duration
- Interface selection
- Output directory path

### Outputs

- Execution status
- Log output

### Constraints

- No business logic
- No packet parsing
- No artifact writing directly

---

## 4.2 Capture Module

### Responsibility

- Interface enumeration
- Packet capture initialization
- Capture lifecycle management
- PCAP file generation

### Inputs

- Interface name
- Capture duration
- Size limits

### Outputs

- original_capture.pcap
- Capture metadata structure

### Constraints

- Must fail gracefully if Npcap not installed
- Must enforce size and duration limits
- Must not parse traffic

---

## 4.3 Parser Module

### Responsibility

- Read PCAP file
- Extract packet-level metadata
- Normalize protocol structures

### Inputs

- original_capture.pcap

### Outputs

- Parsed packet stream
- Normalized protocol event candidates

### Constraints

- No detection logic
- No slicing
- No triage execution

---

## 4.4 Detection Module

### Responsibility

- Identify high-signal indicators
- Timestamp events
- Generate event list
- Update metrics counters

### Inputs

- Parsed packet data

### Outputs

- events[] list
- metrics object

### Constraints

- No file writing
- No slicing
- No OS command execution
- Must conform to JSON schema

---

## 4.5 Slicer Module

### Responsibility

- Extract 60 seconds before and after each event
- Apply protocol-relevant filtering
- Generate filtered PCAP files

### Inputs

- original_capture.pcap
- events[]

### Outputs

- slice PCAP files
- Updated artifact list entries

### Constraints

- Must not modify original PCAP
- Must not generate synthetic packets

---

## 4.6 Triage Module

### Responsibility

- Execute whitelisted diagnostic commands
- Capture stdout and stderr
- Record exit codes
- Save triage output files

### Allowed Commands

- nslookup google.com
- ipconfig /all
- route print
- arp -a
- netsh interface show interface

### Inputs

- Detection results

### Outputs

- triage/*.txt files

### Constraints

- No arbitrary command execution
- No dynamic parameter injection
- All commands hardcoded
- All execution logged

---

## 4.7 Report Module

### Responsibility

- Generate summary.txt
- Generate machine.json
- Populate JSON according to schema
- Ensure required fields exist

### Inputs

- Capture metadata
- events[]
- metrics
- Artifact file list

### Outputs

- summary.txt
- machine.json

### Constraints

- Must validate schema compliance
- Must not alter event data

---

## 4.8 Bundle Module

### Responsibility

- Construct output directory structure
- Organize artifacts
- Ensure correct naming conventions
- Optionally compress bundle

### Inputs

- All generated artifacts

### Outputs

- Structured output directory
- Optional archive file

### Constraints

- Must not modify artifact contents
- Must enforce directory layout specification

---

## 4.9 Integrity Module

### Responsibility

- Generate SHA256 hashes
- Produce hashes.txt
- Verify required artifact presence

### Inputs

- All artifact file paths

### Outputs

- hashes.txt

### Constraints

- Must fail if required file missing
- Must hash all files before completion

---

# 5. Data Flow Contracts

Modules communicate using defined data structures.

Primary data objects:

- CaptureMetadata
- ParsedPacket
- Event
- Metrics
- ArtifactEntry

No module may directly manipulate another module’s internal state.

---

# 6. Error Handling Strategy

Each module must:

- Return structured errors
- Avoid panic unless unrecoverable
- Log failure context

CLI module handles:

- Fatal termination
- User-facing error messaging

---

# 7. Logging Policy

Logging must include:

- Module name
- Timestamp
- Severity level
- Error context if applicable

Logging must not include:

- Credential data
- Sensitive payload contents

---

# 8. Future Compatibility Requirements

Architecture must allow:

- HTTPS uploader module
- Agent service mode
- Enrollment mechanism
- Org and agent identifiers
- RBAC integration

These shall be added without modifying core detection logic.

---

# 9. Hard Architectural Constraints

The following are prohibited at the architecture level:

- Raw packet crafting
- Packet injection
- IP spoofing
- Remote command execution
- Credential access modules
- Cross-module hidden global state

---

# 10. Definition of Architectural Stability

Architecture is considered stable when:

1. Each module compiles independently.
2. Interfaces are documented and versioned.
3. Schema output remains consistent across runs.
4. No module exceeds its defined responsibility.
5. Unit testing can be written per module without side effects.

---

# Summary

Wulfgar Phase 1 follows a strictly modular, deterministic architecture:

CLI → Capture → Parser → Detection → Slicer → Triage → Report → Bundle → Integrity

Each module has a single responsibility.
No offensive or manipulative capabilities are permitted.
Schema compliance is mandatory.
Architecture must support future HTTPS server expansion without refactoring core logic.
