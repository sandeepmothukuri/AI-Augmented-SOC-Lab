# SOC Validation Scenarios

These scenarios are deterministic test inputs for the laboratory. They validate detection, triage, enrichment, and analyst workflow without requiring a production data source.

| ID | Scenario | Expected disposition | ATT&CK |
|---|---|---|---|
| SOC-001 | SSH authentication failures from one source | Escalate / enrich | T1110 |
| SOC-002 | Network service scan against multiple ports | Escalate | T1046 |
| SOC-003 | Known malware indicator in endpoint telemetry | Escalate / enrich | T1204 |
| SOC-004 | Ransomware-like file encryption behavior | Critical escalation | T1486 |
| SOC-005 | Phishing indicator in email telemetry | Enrich / escalate | T1566 |
| SOC-006 | DNS tunneling pattern | Enrich / escalate | T1071.004 |
| SOC-007 | Expected administrator authentication | Close after validation | N/A |
| SOC-008 | Unknown/ambiguous alert | Enrich; never auto-close | Analyst review |

## Validation rule

The AI engine is not the source of truth. A valid LLM response must satisfy the triage contract (`verdict`, `confidence`, `severity`, and `reasoning`). Invalid or malformed model output fails closed to `ENRICH`, requiring analyst review.

## Evidence standard

A scenario is considered validated only when the repository contains:

1. The input alert or reproducible generator.
2. The resulting detection/triage output.
3. The ATT&CK mapping and analyst disposition.
4. Any downstream case or enrichment evidence actually produced by the lab.

Screenshots must represent a real lab run or clearly be labelled as reference/vendor UI. Do not present reference screenshots as proof of an integration that has not been exercised.
