#!/bin/sh
# Run this container with --network none: Cargo's offline flag alone does not isolate build scripts.
set -eu
work=$(mktemp -d "$TMPDIR/verify.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
spec=/opt/ozpb/subscription-spec.json
if ! ozpb generate --spec "$spec" --rule 0 --out "$work/policy" >"$work/generate.json" 2>"$work/build.log"; then
    # Only this committed synthetic fixture runs here, in a container with no credentials.
    echo 'offline fixture generation failed:' >&2
    tail -n 30 "$work/build.log" >&2
    exit 1
fi
set -- "$work"/policy/*.wasm
test "$#" = 1 && test -f "$1"
if ! ozpb verify --spec "$spec" --rule 0 --generated-dir "$work/policy" \
    --wasm "$1" --manifest "$work/policy/build-manifest.json" >"$work/verify.json" 2>>"$work/build.log"; then
    echo 'offline fixture verification failed:' >&2
    tail -n 30 "$work/build.log" >&2
    exit 1
fi
python3 - "$work/verify.json" <<'PY'
import json, sys
with open(sys.argv[1]) as source:
    result = json.load(source)
if (result.get("matches") is not True
        or result.get("source_reproduction") != "reproduced: generated non-lock files are byte-identical"
        or result.get("wasm_reproduction") != "reproduced: Wasm and BuildManifest are identical"):
    raise SystemExit("offline artifact reproduction failed")
print("offline generate and verify: matching source, Wasm and manifest")
PY
