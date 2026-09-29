# Contributing

Contributions are accepted under `GPL-3.0-only`.

Changes must preserve:

- FAIL_CLOSED
- APPEND_ONLY
- SHA256_VERIFIED
- POSITIVE_EVIDENCE_REQUIRED
- UNKNOWN_REMAINS_UNKNOWN
- NO_RESOLUTION_FROM_ABSENCE
- NO_BLIND_RETRY
- PRESERVE_FAILURE_EVIDENCE
- NO_AUTOMATIC_REMEDIATION
- NO_AUTOMATIC_RISK_ACCEPTANCE
- NO_AUTOMATIC_DEFERRAL

The directory `src/ia-security-agent-deployment-v1.1/` is the frozen V1.1
source. Do not modify that tree in place for V1.1. Functional changes belong in
a new release with a new manifest, new hashes, new validation evidence and a
new freeze.
