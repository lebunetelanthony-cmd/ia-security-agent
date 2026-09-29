# Changelog

## 1.1.0 — 2026-09-28

### Added

- Generic Nightly LLM V5 integration.
- Strict output schema and validator alignment.
- Raw request / provider envelope / LLM response preservation.
- Verified-copy publication through `.pending-*`.
- Same-parent final rename.
- Explicit runtime: `num_ctx=16384`, `num_predict=2048`, `temperature=0`,
  `seed=0`, `stream=false`, `think=false`.

### Security

- LLM authority remains `NON_FACTUAL_CONSUMER`.
- No automatic remediation.
- No automatic risk acceptance.
- No automatic deferral.
- No blind retry.
- Failure evidence preserved.
- Inter-directory publication rename disabled.

### Validation

- Synthetic success publication: VALID.
- Synthetic failure publication: VALID.
- Raw evidence preservation: VALID.
- systemd verification: VALID.
- Real Ollama validation: VALID.
- Final assessment: `NO_NEW_DEGRADATION`.
- Distribution pack integrity: VALID.

## 1.0.0

Initial frozen Deployment V1 release.
