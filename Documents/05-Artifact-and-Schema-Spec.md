# Wulfgar
## Artifact and Schema Specification
Version: 1.0  
Phase: Phase 1 – Local Windows CLI  
Supported Platforms: Windows 10, Windows 11  

---

# 1. Purpose

This document defines:

- The structure of the Wulfgar diagnostic artifact bundle
- The machine-readable JSON schema
- File naming conventions
- Integrity validation requirements
- Versioning rules

All modules must conform strictly to this specification.

Any structural change requires a schema version increment.

---

# 2. Artifact Bundle Structure

Each execution of Wulfgar produces one structured output directory.

## 2.1 Directory Naming Convention

Wulfgar_<HOSTNAME>_<YYYYMMDD_HHMMSS>/

Example:

Wulfgar_WS01_20260302_184512/

---

## 2.2 Required Directory Layout

Wulfgar_<HOSTNAME>_<TIMESTAMP>/

- original_capture.pcap  
- summary.txt  
- machine.json  
- hashes.txt  
- triage/  
  - nslookup.txt  
  - ipconfig.txt  
  - route.txt  
  - arp.txt  
  - netsh_interface.txt  
- slices/  
  - dns_event_1.pcap  
  - tcp_event_1.pcap  
  - icmp_event_1.pcap  
  - additional slice files as required  

---

# 3. File Definitions

## 3.1 original_capture.pcap

Description:

- Full packet capture for configured duration.
- Must respect size limits.
- Capture metadata must be recorded in machine.json.

---

## 3.2 summary.txt

Human-readable report containing:

- Capture metadata
- System information
- Protocol error counts
- Event timeline
- Triage summary
- Observed anomalies

Must be formatted clearly for technician readability.

---

## 3.3 machine.json

Structured machine-readable output following the schema defined in Section 4.

---

## 3.4 hashes.txt

Contains SHA256 hashes for integrity validation.

Format:

SHA256(original_capture.pcap)=<hash>  
SHA256(machine.json)=<hash>  
SHA256(summary.txt)=<hash>  
SHA256(dns_event_1.pcap)=<hash>  

Every artifact file must have a hash entry.

---

## 3.5 triage/ Directory

Each file must include:

- Command executed
- Timestamp of execution
- Exit code
- Full raw output

Only whitelisted commands are allowed.

---

## 3.6 slices/ Directory

Contains filtered PCAP files generated per detected event.

Naming convention:

<protocol>_event_<index>.pcap

Examples:

- dns_event_1.pcap
- tcp_event_2.pcap
- icmp_event_1.pcap

Each slice must represent:

- 60 seconds before event timestamp
- 60 seconds after event timestamp

---

# 4. JSON Schema Specification (machine.json)

## 4.1 Top-Level Structure

{
  "schema_version": "1.0",
  "tool_version": "0.1",
  "host": {},
  "capture": {},
  "events": [],
  "metrics": {},
  "artifacts": []
}

---

## 4.2 Host Object

{
  "hostname": "WS01",
  "os_version": "Windows 10 Pro 22H2",
  "architecture": "x64",
  "primary_interface": "Ethernet",
  "interface_ip": "192.168.1.100",
  "interface_mac": "00-11-22-33-44-55"
}

Required Fields:

- hostname
- os_version
- primary_interface
- interface_ip

---

## 4.3 Capture Object

{
  "start_time_utc": "2026-03-02T18:45:12Z",
  "end_time_utc": "2026-03-02T18:50:12Z",
  "duration_seconds": 300,
  "interface": "Ethernet",
  "packet_count": 123456,
  "pcap_file": "original_capture.pcap"
}

Required Fields:

- start_time_utc
- end_time_utc
- duration_seconds
- interface
- pcap_file

---

## 4.4 Events Array

Each event object must follow this structure:

{
  "event_id": "dns_1",
  "timestamp_utc": "2026-03-02T18:47:32Z",
  "protocol": "DNS",
  "source_ip": "192.168.1.100",
  "destination_ip": "8.8.8.8",
  "indicator_type": "NXDOMAIN",
  "severity": "medium",
  "description": "Repeated NXDOMAIN responses observed",
  "slice_file": "dns_event_1.pcap"
}

Required Fields:

- event_id
- timestamp_utc
- protocol
- indicator_type
- description
- slice_file

Optional Fields:

- source_port
- destination_port
- retransmit_count
- icmp_type
- icmp_code

---

## 4.5 Metrics Object

All fields must default to zero if not observed.

{
  "dns": {
    "nxdomain_count": 5,
    "servfail_count": 1,
    "timeout_count": 3
  },
  "tcp": {
    "syn_retransmits": 12,
    "connection_resets": 4
  },
  "dhcp": {
    "discover_without_offer": 1,
    "request_without_ack": 0
  },
  "icmp": {
    "destination_unreachable": 2,
    "ttl_exceeded": 0
  }
}

---

## 4.6 Artifacts Array

{
  "file_name": "original_capture.pcap",
  "sha256": "<hash>",
  "type": "pcap"
}

Valid types:

- pcap
- pcap_slice
- report
- triage_output

All artifact files must be listed.

---

# 5. Integrity Rules

The system must:

- Generate SHA256 hashes for all artifact files.
- Validate file existence before JSON generation.
- Fail execution if required files are missing.
- Include schema_version in all machine.json outputs.

---

# 6. Versioning Rules

Schema version must be incremented if:

- Required fields are added
- Fields are removed
- Structure changes
- Naming conventions change

Optional field additions do not require major version change.

---

# 7. Hard Security Constraints

The artifact schema must never include:

- Passwords
- Credential material
- Tokens
- Decrypted application payload contents
- Sensitive user data extraction
- Browser content or form data

Wulfgar is a network diagnostic artifact engine only.

---

# 8. Future Reserved Fields

The following fields may be added in future phases:

- org_id
- agent_id
- trigger_type
- upload_timestamp
- server_received_timestamp

These are reserved for Phase 2 server integration.

---

# Summary

This document defines the structured output contract for Wulfgar Phase 1.

All modules must conform to this specification.
Schema stability is mandatory before server integration.
