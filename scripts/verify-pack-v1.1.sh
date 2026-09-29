#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$ROOT/PACK-SHA256SUMS" ]; then
    echo "PACK_STATUS=REFUSED"
    echo "REASON=PACK-SHA256SUMS_MISSING"
    exit 20
fi

(
    cd "$ROOT"
    sha256sum -c PACK-SHA256SUMS
)

echo "PACK_STATUS=VALID"
