# Incident Response Runbook

## 1. Triage

- Confirm alert source, timestamp, asset, user, and rule context.
- Check whether the event is duplicate, expected administrative activity, or a known test.
- Validate the AI decision against the original telemetry; do not accept the model output blindly.
- If the model response is malformed or uncertain, keep the case in `ENRICH`.

## 2. Enrichment

- Query endpoint and authentication telemetry for the surrounding time window.
- Enrich source/destination IPs, domains, hashes, and users with available threat-intelligence sources.
- Compare the event with related alerts from the same host, account, and source address.
- Record evidence and confidence, not assumptions.

## 3. Investigation

- Build a short event timeline.
- Identify initial access, execution, persistence, privilege escalation, credential access, lateral movement, command-and-control, and impact where applicable.
- Map confirmed behavior to MITRE ATT&CK techniques.
- Determine affected scope and likely blast radius.

## 4. Containment

Containment requires analyst authorization. Examples include disabling a compromised account, isolating an endpoint, blocking an indicator, or stopping a malicious process. Record who approved the action and the evidence supporting it.

## 5. Eradication and Recovery

- Remove persistence and malicious artifacts.
- Reset or rotate affected credentials.
- Restore systems from a known-good state when required.
- Verify monitoring is healthy before returning systems to normal operation.

## 6. Closure

Close only when the analyst can document:

- Root cause or best-supported explanation.
- Scope and affected assets.
- Evidence collected.
- Containment/remediation actions.
- Residual risk.
- ATT&CK mapping where applicable.
- Follow-up detection or control improvements.

## AI guardrails

The AI component recommends; the SOC workflow validates. Automated case creation may be used for `ESCALATE` or `ENRICH`, but high-impact containment actions remain outside the model's authority.
