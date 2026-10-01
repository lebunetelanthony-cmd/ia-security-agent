# IA Security Agent Deployment V1.2

V1.2 is the recommended generic deployment pack after the Phase 5 R3 runtime fix.

## Architecture

- `base-v1.1/`: exact immutable V1.1 distribution.
- `overlay-phase5-r3/`: generic Phase 5 runtime overlay.
- `deploy-ia-security-agent-v1.2.sh`: deploys V1.1 then R3.

## Phase 5 R3 correction

R3 preserves `RestrictSUIDSGID=yes` and changes only the incompatible SGID
permission requests:

- `0o2750` -> `0o0750` for attempt creation.
- `0o2550` -> `0o0550` for frozen directories (two occurrences).

No Phase 1–15 canonical artifact is changed. No automatic remediation or
Phase 5 LLM execution is enabled.

## Generic usage

Use the same deployment options as V1.1:

```bash
sudo ./deploy-ia-security-agent-v1.2.sh [V1.1 options]
```

The pack contains no host-specific HEAD, cycles, service logs, local R3
transactions, or nightly run history.
