# Architecture

## Deterministic core

The deterministic core is authoritative for collected evidence, target-local
baseline, longitudinal state, diffs, impact records, commits, and control-plane
integrity.

## Nightly LLM V5

Nightly LLM V5 consumes deterministic `state/HEAD.json` evidence.

Authority:

```text
NON_FACTUAL_CONSUMER
```

It cannot remediate, accept risk, defer risk, assert security resolution, or
infer resolution from absence.

## Publication

```text
attempt
  -> verified copy
  -> .pending-<run-id>
  -> SHA256 verification
  -> final rename in the same parent
```

There is no inter-directory `attempt.rename()` publication path.

## Runtime separation

Each target creates its own runtime state and baseline. Runtime evidence from
the release-building host is not distributed.
