#!/usr/bin/env bash
# Tranche 2 testnet harness, end to end against live Stellar testnet:
#
#   a transfer the smart account really executed → recording → PolicySpec → generated policy
#   → deployed → installed into the account by a signed add_context_rule → the account permits
#   exactly that transfer once and refuses everything else
#
#   bash testnet-harness/run.sh
#   OZPB_BIN=target/debug/ozpb bash testnet-harness/run.sh    # use a built CLI instead of cargo run
#   OZPB_HARNESS_OUT=/tmp/run bash testnet-harness/run.sh     # choose where the artifacts land
#   OZPB_HARNESS_OWNER=passkey OZPB_BROWSER_CHANNEL=chrome bash testnet-harness/run.sh
#                                   # the account's owner is a headless passkey, not an ed25519 key
#
# Everything the run produces is kept under `testnet-harness/runs/<UTC timestamp>-<pid>/` (gitignored):
# run.json (every address and transaction hash), the import bundle, the recording, the spec, the
# generated crate. The throwaway keys are not: they live in a temp directory deleted on exit.
#
# Read the README before presenting a run. In particular: step 3 writes the spec by hand,
# because synthesis cannot run against protocol-29 testnet on this tree, and the denials in
# step 6 are observed in the enforcing simulation, so they have no transaction hash.
set -euo pipefail
HARNESS="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HARNESS/.." && pwd)"
SCRIPTS="$HARNESS/scripts"
cd "$ROOT"

OWNER="${OZPB_HARNESS_OWNER:-ed25519}"
case "$OWNER" in ed25519|passkey) ;; *) echo "OZPB_HARNESS_OWNER is ed25519 or passkey, not $OWNER"; exit 1 ;; esac

for tool in node npm stellar cargo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required"; exit 1; }
done
# @stellar/stellar-sdk 17 declares node >= 22.12.
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 12) ? 0 : 1)' \
    || { echo "node >= 22.12 is required, found $(node --version)"; exit 1; }

ozpb() {
    if [ -n "${OZPB_BIN:-}" ]; then "$OZPB_BIN" "$@"; else cargo run --locked -q -p ozpb-cli -- "$@"; fi
}
say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
field() { node -p 'require(process.argv[1])[process.argv[2]]' "$RUN/run.json" "$1"; }

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN="${OZPB_HARNESS_OUT:-$HARNESS/runs/$RUN_ID}"
mkdir -p "$RUN"
RUN="$(cd "$RUN" && pwd)"
SECRETS="$(mktemp -d)"
trap 'rm -rf "$SECRETS"' EXIT
export OZPB_HARNESS_SECRETS="$SECRETS/keys.json"

# Always, so node_modules is exactly the lockfile rather than whatever an earlier install left.
npm ci --prefix "$SCRIPTS" --no-audit --no-fund --silent
# A passkey owner signs in headless Chromium (Playwright). OZPB_BROWSER_CHANNEL=chrome uses an
# installed Google Chrome; without it, Playwright's own build must have been installed once.
if [ "$OWNER" = passkey ]; then npm ci --prefix "$HARNESS/browser" --no-audit --no-fund --silent; fi

say "1. setup: throwaway keys, the pinned OpenZeppelin account (owner: $OWNER)"
node "$SCRIPTS/setup.mjs" --run-dir "$RUN" --owner "$OWNER" ${OZPB_HARNESS_VERIFIER:+--verifier "$OZPB_HARNESS_VERIFIER"}
AMOUNT="$(field amount)"
RECIPIENT="$(field recipient)"
OTHER="$(field payer)"   # a funded account, so a wrong-recipient transfer cannot fail for lack of one

say "2. record: the owner moves funds out of the account, then ozpb imports the executed transaction"
# The transaction the grant is built from is a real one. The owner authorizes it through rule 0,
# the account's Default rule, which has no policy; `ozpb import` decodes the raw XDR offline.
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --signer owner --rule 0 \
    --amount "$AMOUNT" --to "$RECIPIENT" --expect permit --bundle "$RUN/import-bundle.json"
ozpb import --bundle "$RUN/import-bundle.json" > "$RUN/recording.json"
if [ "$OWNER" = passkey ]; then
    # Negative control: the same transfer, the passkey signing random bytes instead of the account's
    # digest. The WebAuthn verifier must refuse it with its own ChallengeInvalid (#3114).
    node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --signer owner --rule 0 --wrong-challenge yes \
        --amount "$AMOUNT" --to "$RECIPIENT" --expect deny:3114
fi

say "3. spec: the template, filled from the recording (synthesis cannot run here; see README)"
node "$SCRIPTS/write-spec.mjs" --run-dir "$RUN"

say "4. generate: the policy crate and its wasm"
# The generated crate builds offline against the same locked dependencies as the committed
# golden crate, so make sure they are in the cargo cache first.
( cd contracts/golden-transfer-policy && cargo fetch --locked >/dev/null )
# With --out, generate reports on stderr; keep that report with the run.
ozpb generate --spec "$RUN/spec.json" --rule 0 --out "$RUN/policy" 2>&1 | tee "$RUN/generate.log"
shopt -s nullglob
WASMS=("$RUN"/policy/*.wasm)
[ "${#WASMS[@]}" -eq 1 ] || { echo "expected one wasm in $RUN/policy, found ${#WASMS[@]}"; exit 1; }

say "5. install: deploy the policy, add_context_rule signed by the owner ($OWNER)"
node "$SCRIPTS/install.mjs" --run-dir "$RUN" --wasm "${WASMS[0]}"

say "6. permit exactly the recorded transfer, once; deny the rest"
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$RECIPIENT" --expect permit
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$((AMOUNT + 1))" --to "$RECIPIENT" --expect deny:6
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$OTHER" --expect deny:6
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$RECIPIENT" --expect deny:7

say "done"
echo "  account  https://stellar.expert/explorer/testnet/contract/$(field account)  (owner: $OWNER)"
echo "  policy   https://stellar.expert/explorer/testnet/contract/$(field policy)"
echo "  run      $RUN/run.json"
