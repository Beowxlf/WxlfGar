# Program Issues Report (Current Stage)

Created: 2026-03-06
Stage: Planning / Early Implementation

## Purpose
This report tracks issues the Program has come across at the current stage.

## Open Issues

| ID | Date | Area | Issue | Impact | Status | Owner | Notes |
|---|---|---|---|---|---|---|---|
| ISS-002 | 2026-03-06 | Integrity | `hashes.txt` can contain a stale hash for `machine.json` after report regeneration. | High | Open | Unassigned | Blocks strict artifact integrity validation for Phase 1. |
| ISS-003 | 2026-03-06 | Slicer | Event slices are currently full-file copies instead of ±60-second windows around event timestamps. | High | Open | Unassigned | Does not satisfy Phase 1 slice-accuracy requirement. |
| ISS-004 | 2026-03-06 | Detection | Detection matrix is incomplete for some required indicators (timeouts/TLS inferable failures coverage depth). | High | Open | Unassigned | Prevents full functional test-plan closure. |
| ISS-005 | 2026-03-06 | Schema Validation | No enforced machine schema validation in automated tests. | Medium | Open | Unassigned | Test-plan schema checks not fully automated. |
| ISS-006 | 2026-03-06 | Windows Validation | Required Windows negative tests (Npcap/admin/interface) are not yet evidenced in-repo. | Medium | Open | Unassigned | Acceptance criteria evidence gap. |

## Next Actions
- Prioritize ISS-002 and ISS-003 before additional feature work.
- Add automated test coverage and reproducible fixtures for ISS-004 and ISS-005.
- Run and archive Windows 10/11 validation evidence for ISS-006.
- Link this report with `Audits/Phase1-Repository-State-Audit.md` for detailed remediation order.
