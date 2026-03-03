# Wulfgar
## Technician Standard Operating Procedure (SOP)
Version: 0.1  
Phase: Phase 1 – Local Windows CLI  
Platform: Windows 10 and Windows 11  

---

# 1. Purpose

This SOP defines:

- When to use Wulfgar
- How to run Wulfgar
- How to interpret output
- How to handle generated artifacts
- Documentation requirements for MSP ticketing

Wulfgar is a diagnostic artifact generator for intermittent internet issues.

---

# 2. When to Use Wulfgar

Run Wulfgar when a customer reports:

- Intermittent internet connectivity
- DNS resolution failures
- Web browsing instability
- SMB access drops
- Packet loss symptoms
- Gateway or routing instability
- Issues that are not reproducible live

Do not use Wulfgar for:

- Confirmed hardware failures
- Clearly reproducible configuration errors
- Non-network related application bugs

---

# 3. Pre-Execution Checklist

Before running Wulfgar:

1. Confirm you have administrative privileges.
2. Confirm Npcap is installed.
3. Identify the correct active network interface.
4. Inform the customer that packet capture will occur.
5. Confirm capture duration with customer.

---

# 4. How to Run Wulfgar

## 4.1 Standard Execution

1. Open Command Prompt as Administrator.
2. Navigate to Wulfgar executable directory.
3. Run Wulfgar with appropriate capture duration.

Example:
