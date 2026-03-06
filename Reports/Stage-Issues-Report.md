# Program Issues Report (Current Stage)

Created: 2026-03-06
Stage: Planning / Early Implementation

## Purpose
This report tracks issues the Program has come across at the current stage.

## Open Issues

| ID | Date | Area | Issue | Impact | Status | Owner | Notes |
|---|---|---|---|---|---|---|---|
| ISS-002 | 2026-03-06 | Integrity | `hashes.txt` can contain a stale hash for `machine.json` after report regeneration. | High | Resolved | Agent | Flow now finalizes `machine.json` before final hash write; covered by orchestrator test assertions. |
| ISS-003 | 2026-03-06 | Slicer | Event slices are currently full-file copies instead of ±60-second windows around event timestamps. | High | Resolved | Agent | Slicer now writes windowed slices with tests; includes fallback for malformed fixture PCAPs. |
| ISS-004 | 2026-03-06 | Detection | Detection matrix is incomplete for some required indicators (timeouts/TLS inferable failures coverage depth). | High | In Progress | Agent | Added DNS timeout repeat + SMB timeout inference; additional Windows/live validations still pending. |
| ISS-005 | 2026-03-06 | Schema Validation | No enforced machine schema validation in automated tests. | Medium | Resolved | Agent | Added orchestrator end-to-end test with schema-required key and const validation. |
| ISS-006 | 2026-03-06 | Windows Validation | Required Windows negative tests (Npcap/admin/interface) are not yet evidenced in-repo. | Medium | Open | Unassigned | Acceptance criteria evidence gap. |
| ISS-007 | 2026-03-06 | Artifact Consistency | No run-level check enforces that listed artifacts match files present on disk. | Medium | Resolved | Agent | Orchestrator now validates existence and duplicate safety for produced artifact paths. |

## Next Actions
- Prioritize ISS-002 and ISS-003 before additional feature work.
- Add automated test coverage and reproducible fixtures for ISS-004 and ISS-005.
- Run and archive Windows 10/11 validation evidence for ISS-006.
- Link this report with `Audits/Phase1-Repository-State-Audit.md` for detailed remediation order.
