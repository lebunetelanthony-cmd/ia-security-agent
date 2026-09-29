# Integrity

Canonical Deployment V1.1 hashes:

| Artifact | SHA256 |
| --- | --- |
| Release archive | `76c058348a617e61e9a00253cf3fd126b8d263db03649c8d71bf9ef416d54398` |
| Deployment manifest | `ffe08d654e2f02a0d38e2b0f7cf347465664c9232aeb169fae1e7914484a75db` |
| CONTROL-SHA256SUMS | `d6fc8f9a3ea6bd1ffca2f59841fce857853ffed221374ad6e73b1f6329655e6e` |
| Nightly LLM V5 engine | `e5ba4dff39ace96ba42fc30daf668af563cd16a7b1b675221effdc7432cd9c58` |
| Release attestation | `07d26893e92e5f3777e658af3b9d129675bd4500b63d3d16d452adcaa27d0599` |
| Full distribution pack | `dc8e54d896162f712759f30826d9553b737b06ca23e095f7c87ca82818c0fcad` |

Verify the exact frozen source tree:

```bash
cd src/ia-security-agent-deployment-v1.1
sha256sum -c CONTROL-SHA256SUMS
```

Repository metadata lives outside the frozen source directory on purpose.
