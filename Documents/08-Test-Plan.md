# Wulfgar
## Test Plan and Validation Matrix
Version: 0.1  
Phase: Phase 1 – Local Windows CLI  
Platform: Windows 10 and Windows 11  
Language: Go  

---

# 1. Purpose

This document defines:

- Functional test cases
- Negative test cases
- Performance validation
- Stability validation
- Acceptance criteria for Phase 1

Wulfgar Phase 1 is not complete until all required tests pass.

---

# 2. Test Environment

## 2.1 Supported Operating Systems

- Windows 10 (latest supported build)
- Windows 11 (latest supported build)

## 2.2 Required Components

- Npcap installed
- Administrative privileges available
- Active network interface
- Internet connectivity (for DNS testing)

---

# 3. Functional Test Cases

---

## 3.1 Packet Capture Tests

### Test Case 3.1.1 – Basic Capture

Objective:
Verify that Wulfgar captures traffic and produces original_capture.pcap.

Steps:
1. Run Wulfgar for 120 seconds.
2. Generate normal browsing traffic.
3. Verify original_capture.pcap exists.
4. Verify machine.json contains capture metadata.

Expected Result:
- PCAP file created.
- Capture duration matches configuration.
- No crash.

---

### Test Case 3.1.2 – Size Limit Enforcement

Objective:
Ensure capture stops when file size limit is reached.

Steps:
1. Configure small capture size limit.
2. Generate heavy traffic.
3. Verify capture stops automatically.

Expected Result:
- Capture stops safely.
- No file corruption.
- Summary notes size-based termination.

---

## 3.2 DNS Detection Tests

### Test Case 3.2.1 – NXDOMAIN Detection

Objective:
Verify detection of NXDOMAIN responses.

Steps:
1. Query a non-existent domain.
2. Run Wulfgar capture during query.
3. Review machine.json.

Expected Result:
- Event logged with indicator_type = NXDOMAIN.
- DNS metrics incremented.
- dns_event_1.pcap generated.

---

### Test Case 3.2.2 – DNS Timeout Simulation

Objective:
Verify detection of repeated DNS queries without response.

Steps:
1. Temporarily block outbound UDP 53.
2. Perform DNS queries.
3. Run capture.

Expected Result:
- Timeout indicator detected.
- Metrics updated accordingly.

---

## 3.3 TCP Retransmission Tests

### Test Case 3.3.1 – SYN Retransmit

Objective:
Verify TCP SYN retransmission detection.

Steps:
1. Attempt connection to unreachable IP.
2. Capture traffic.
3. Inspect machine.json.

Expected Result:
- Event with indicator_type = SYN_RETRANSMIT.
- tcp metrics incremented.
- tcp_event_1.pcap created.

---

## 3.4 ICMP Tests

### Test Case 3.4.1 – Destination Unreachable

Objective:
Verify ICMP unreachable detection.

Steps:
1. Attempt to ping unreachable network.
2. Capture traffic.
3. Inspect events list.

Expected Result:
- Event with indicator_type = DESTINATION_UNREACHABLE.
- icmp metrics incremented.
- icmp_event_1.pcap generated.

---

## 3.5 DHCP Tests

### Test Case 3.5.1 – DHCP Discover Without Offer

Objective:
Verify detection of repeated Discover packets without Offer.

Steps:
1. Disconnect DHCP server temporarily.
2. Renew IP configuration.
3. Capture traffic.

Expected Result:
- DHCP anomaly detected.
- Metrics updated.

---

## 3.6 PCAP Slicing Tests

### Test Case 3.6.1 – Slice Accuracy

Objective:
Ensure slice includes correct time window.

Steps:
1. Trigger known DNS error at known timestamp.
2. Inspect slice file.
3. Confirm it contains:
   - 60 seconds before event
   - 60 seconds after event

Expected Result:
- Slice duration approximately 120 seconds.
- No packets outside time range.

---

## 3.7 Triage Execution Tests

### Test Case 3.7.1 – DNS Trigger Triage

Objective:
Verify nslookup runs when DNS error detected.

Steps:
1. Trigger DNS error.
2. Run Wulfgar.
3. Inspect triage/nslookup.txt.

Expected Result:
- Command executed.
- Exit code recorded.
- Output stored.

---

### Test Case 3.7.2 – Whitelist Enforcement

Objective:
Ensure arbitrary command execution is impossible.

Steps:
1. Attempt to modify code to pass dynamic command input.
2. Verify system blocks execution.

Expected Result:
- Only hardcoded commands allowed.
- No dynamic command execution.

---

# 4. Negative Test Cases

---

## 4.1 Npcap Missing

Objective:
Verify graceful failure if Npcap not installed.

Expected Result:
- Clear error message.
- No crash.

---

## 4.2 No Administrative Privileges

Objective:
Verify behavior without admin rights.

Expected Result:
- Meaningful error.
- No partial artifact creation.

---

## 4.3 Interface Unavailable

Objective:
Verify failure if interface does not exist.

Expected Result:
- Clear error.
- No panic.

---

# 5. Performance Validation

---

## 5.1 CPU Usage

Requirement:
- Must not exceed acceptable CPU threshold during normal capture.

Validation:
- Monitor Task Manager during 5-minute capture.

Expected Result:
- CPU usage stable and reasonable.

---

## 5.2 Disk Usage

Requirement:
- Capture must respect file size limits.
- Bundle size predictable.

Validation:
- Measure output directory size.

Expected Result:
- Within defined constraints.

---

# 6. Stability Testing

---

## 6.1 Repeated Execution

Objective:
Run tool multiple times consecutively.

Expected Result:
- No memory leaks.
- No file corruption.
- Consistent output structure.

---

## 6.2 Large Capture Duration

Objective:
Run extended capture within allowed limits.

Expected Result:
- No crash.
- No excessive memory growth.

---

# 7. Schema Validation

Each run must validate:

- machine.json conforms to schema.
- All required fields exist.
- hashes.txt contains entries for all files.
- Slice files listed in JSON match actual files.

Failure to meet these conditions fails test.

---

# 8. Real-World Validation

Before Phase 1 completion:

- Use Wulfgar in at least 3 real intermittent issue cases.
- Confirm artifact bundle contributed meaningful diagnostic insight.
- Confirm reduced time-to-diagnosis compared to manual capture alone.

---

# 9. Phase 1 Acceptance Criteria

Phase 1 is complete when:

1. All functional tests pass.
2. All negative tests pass.
3. Performance constraints satisfied.
4. Schema validation consistent.
5. Real-world validation successful.
6. No guardrail violations present.

---

# Summary

Wulfgar Phase 1 is considered production-ready only when:

- Detection logic works in controlled simulations.
- Artifacts are complete and consistent.
- Performance is stable.
- Security guardrails remain intact.
- Real-world troubleshooting benefit is demonstrated.
