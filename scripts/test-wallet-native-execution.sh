#!/usr/bin/env bash
# The wallet's account-Wasm check against the actual CLI preparation and native worker: the
# wallet validates the CLI preparation, retains the worker's `--prepare` frame, signs only
# offline-domain requests and recomputes agreement from the CLI's reference expectations.
# Offline: the RPC source is a named placeholder that preparation does not contact. The
# delegate is the runtime process test's public seed. No network write and no real key.
set -euo pipefail
cd "$(dirname "$0")/.."

# The development registry's root is operator input, as for the testnet harness: the spec must
# name the root of the signed snapshot it is checked against, and generation covers that field.
: "${OZPB_REGISTRY_SNAPSHOT_ROOT:?set it to the root of docs/examples/registry.signed.json}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    # The worker still checks the exact pinned account hash.
    cp "$OZPB_ACCOUNT_WASM" "$work/pinned-account.wasm"
else
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$work/pinned-account.wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
python3 scripts/native-execution-fixture.py spec "$work"
python3 - "$work/spec.json" "$OZPB_REGISTRY_SNAPSHOT_ROOT" docs/examples/registry.signed.json <<'PY'
import json, re, sys
path, root, registry = sys.argv[1:]
if not re.fullmatch(r"[0-9a-f]{64}", root):
    raise SystemExit("OZPB_REGISTRY_SNAPSHOT_ROOT must be 64 lowercase hex characters")
spec = json.load(open(path))
policy = spec["rules"][0]["policies"][0]["generated"]
templates = json.load(open(registry))["snapshot"]["templates"]
spec["registry_snapshot"] = root
policy["capability_schema"] = templates[policy["template_family"]]["capability_schema"]
open(path, "w").write(json.dumps(spec, separators=(",", ":")))
PY

target() { cargo metadata --format-version 1 --no-deps --manifest-path "$1" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'; }
cargo build --locked --quiet -p ozpb-cli
cargo build --locked --quiet --manifest-path execution-runtime/Cargo.toml
cli="$work/ozpb"
runtime="$work/ozpb-execution-runtime"
# Private copies: a concurrent build into a shared target directory cannot replace them mid-run.
cp "$(target Cargo.toml)/debug/ozpb" "$cli"
cp "$(target execution-runtime/Cargo.toml)/debug/ozpb-execution-runtime" "$runtime"

( cd contracts/golden-transfer-policy && cargo fetch --locked )
"$cli" generate --spec "$work/spec.json" --rule 0 --out "$work/generated"
printf '%s\n' '{"synthetic-fixture":{"rpc_url":"https://rpc.invalid/","network_passphrase":"Test SDF Network ; September 2015"}}' \
    > "$work/rpc-sources.json"

OZPB_NATIVE_E2E_CLI="$cli" OZPB_NATIVE_E2E_RUNTIME="$runtime" OZPB_NATIVE_E2E_WORK="$work" \
    node --test --test-reporter=spec wallet/tests/native-e2e.test.mjs | tee "$work/result.log"
for name in \
    'the wallet runs the actual worker and accepts only its independently checked report' \
    'the actual worker report is refused against a changed independent expectation' \
    'the actual worker preparation is refused for another proposed rule ID'; do
    grep -qF "✔ $name" "$work/result.log" || {
        echo "required wallet native execution test did not run and pass: $name" >&2
        exit 1
    }
done
