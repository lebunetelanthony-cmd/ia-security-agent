# IA Security Agent Deployment V1.2.0

Release date: 2026-10-01

V1.2.0 supersedes V1.1.0 as the recommended generic deployment package.

It fixes the Phase 5 R2 runtime conflict between SGID directory modes and
systemd `RestrictSUIDSGID=yes`.

The V1.1 parent release remains byte-identical and is embedded under
`base-v1.1/`. The R3 correction is installed as an append-only runtime overlay.

Development validation of the equivalent R3 correction drained four pending
Phase 5 generations successfully, advanced the Phase 5 HEAD, preserved the
Phase 4 integrity post-check, and completed with exit code 0.

Host-specific validation evidence is intentionally excluded from this generic
release.
