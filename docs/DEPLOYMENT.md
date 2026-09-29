# Deployment

Use the frozen distribution pack from GitHub Releases.

## Verify

```bash
sha256sum -c IA-Security-Agent-Deployment-V1.1.tar.gz.sha256
```

Expected SHA256:

```text
dc8e54d896162f712759f30826d9553b737b06ca23e095f7c87ca82818c0fcad
```

## Extract and verify

```bash
tar -xzf IA-Security-Agent-Deployment-V1.1.tar.gz
cd IA-Security-Agent-Deployment-V1.1
./verify-pack-v1.1.sh
```

Expected:

```text
PACK_STATUS=VALID
```

## Default install

```bash
./deploy-ia-security-agent-v1.1.sh
```

Default paths:

```text
control root: /opt/ia-security-agent/v1
runtime root: /data/ia-local/security-audit
```

Nightly LLM is disabled by default. Do not alter the canonical pack in place.
