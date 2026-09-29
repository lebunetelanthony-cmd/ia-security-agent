# IA Security Agent

Deterministic longitudinal security monitoring for Linux, with optional local
**Nightly LLM V5** analysis through Ollama.

**Current release:** `Deployment V1.1 — CLOSED_VALIDATED_FROZEN`

## Security model

The deterministic core is authoritative. The optional LLM layer is explicitly
`NON_FACTUAL_CONSUMER`: it analyzes deterministic evidence but cannot remediate,
accept risk, defer risk, or assert that a security issue is resolved.

Core invariants:

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

## Repository layout

```text
.
├── LICENSE
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── RELEASE_NOTES_v1.1.0.md
├── docs/
├── scripts/
└── src/
    └── ia-security-agent-deployment-v1.1/
```

`src/ia-security-agent-deployment-v1.1/` is the exact frozen source tree from
Deployment V1.1. GitHub metadata and the license live outside that directory so
they do not alter its fail-closed manifest or canonical SHA-256 values.

## Nightly LLM V5

```text
implementation = nightly-llm-v5-generic
authority      = NON_FACTUAL_CONSUMER
model validated= qwen3:4b-instruct

num_ctx        = 16384
num_predict    = 2048
temperature    = 0
seed           = 0
stream         = false
think          = false
```

Nightly LLM is disabled by default during deployment.

## Install from a Release

Download:

```text
IA-Security-Agent-Deployment-V1.1.tar.gz
IA-Security-Agent-Deployment-V1.1.tar.gz.sha256
```

Verify:

```bash
sha256sum -c IA-Security-Agent-Deployment-V1.1.tar.gz.sha256
```

Expected full-pack SHA256:

```text
dc8e54d896162f712759f30826d9553b737b06ca23e095f7c87ca82818c0fcad
```

Extract and verify:

```bash
tar -xzf IA-Security-Agent-Deployment-V1.1.tar.gz
cd IA-Security-Agent-Deployment-V1.1
./verify-pack-v1.1.sh
```

Expected result:

```text
PACK_STATUS=VALID
```

See `docs/DEPLOYMENT.md`.

## Canonical V1.1 hashes

```text
release archive
76c058348a617e61e9a00253cf3fd126b8d263db03649c8d71bf9ef416d54398

deployment manifest
ffe08d654e2f02a0d38e2b0f7cf347465664c9232aeb169fae1e7914484a75db

CONTROL-SHA256SUMS
d6fc8f9a3ea6bd1ffca2f59841fce857853ffed221374ad6e73b1f6329655e6e

Nightly LLM V5 engine
e5ba4dff39ace96ba42fc30daf668af563cd16a7b1b675221effdc7432cd9c58

release attestation
07d26893e92e5f3777e658af3b9d129675bd4500b63d3d16d452adcaa27d0599

full distribution pack
dc8e54d896162f712759f30826d9553b737b06ca23e095f7c87ca82818c0fcad
```

## License

GNU General Public License v3.0 only — `GPL-3.0-only`.

See [`LICENSE`](LICENSE).

The canonical release archives remain byte-for-byte unchanged. A separate
license notice accompanies the GitHub Release assets so their frozen hashes
remain valid.

---

## Français

IA Security Agent est un agent de supervision de sécurité longitudinal pour
Linux. Le cœur est déterministe ; l'analyse LLM locale est optionnelle,
non autoritative et sans remédiation automatique.

Licence : **GNU GPL v3.0 uniquement (`GPL-3.0-only`)**.
