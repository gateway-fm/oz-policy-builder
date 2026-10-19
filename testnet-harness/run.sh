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
#   OZPB_HARNESS_AUTHORITY_CHECK=cli OZPB_REGISTRY_SNAPSHOT_ROOT=<hex> … bash testnet-harness/run.sh
#                                   # install through the wallet decision on the authority check
#                                   # (README: "The wallet decision on the authority check")
#
# Everything the run produces is kept under `testnet-harness/runs/<UTC timestamp>-<pid>/` (gitignored):
# run.json (every address and transaction hash), the import bundle, the recording, the spec, the
# generated crate. The throwaway keys are not: they live in a temp directory deleted on exit.
#
# Read the README before presenting a run. The real CLI records and synthesizes the grant,
# then reproduces the artifact before installation. Denials are enforcing simulations,
# so they have no transaction hash. This native transfer is not a protocol walkthrough.
set -euo pipefail
HARNESS="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HARNESS/.." && pwd)"
SCRIPTS="$HARNESS/scripts"
cd "$ROOT"

OWNER="${OZPB_HARNESS_OWNER:-ed25519}"
case "$OWNER" in ed25519|passkey) ;; *) echo "OZPB_HARNESS_OWNER is ed25519 or passkey, not $OWNER"; exit 1 ;; esac
WALKTHROUGH="${OZPB_HARNESS_WALKTHROUGH:-native}"
case "$WALKTHROUGH" in
    native) ;;
    subscription)
        [ "${OZPB_HARNESS_AUTHORITY_CHECK:-}" = cli ] || { echo "subscription needs OZPB_HARNESS_AUTHORITY_CHECK=cli"; exit 1; }
        [ -n "${OZPB_SUBSCRIPTION_POLICY:-}" ] || { echo "subscription needs OZPB_SUBSCRIPTION_POLICY=CONTRACT or deploy"; exit 1; }
        node -e 'const n = Number(process.argv[1]); process.exit(Number.isInteger(n) && n >= 12 && n <= 120 ? 0 : 1)' "${OZPB_SUBSCRIPTION_PERIOD_LEDGERS:-}" \
            || { echo "subscription needs explicit OZPB_SUBSCRIPTION_PERIOD_LEDGERS=12..120 (short test window)"; exit 1; }
        ;;
    *) echo "OZPB_HARNESS_WALKTHROUGH is native or subscription"; exit 1 ;;
esac
# Optional: install through the wallet decision on the authority check. The spec then names the
# signed registry root, and install.mjs takes the check's settings from the environment.
INSTALL_ARGS=()
case "${OZPB_HARNESS_AUTHORITY_CHECK:-}" in
    '') ;;
    cli)
        # Checked now, not at step 5 after setup, record and generate have spent their time.
        for var in OZPB_REGISTRY_SNAPSHOT_ROOT OZPB_BIN OZPB_SIGNED_REGISTRY_SNAPSHOT OZPB_REGISTRY_ROOTS_FILE \
            OZPB_REGISTRY_MIN_VERSION OZPB_RPC_SOURCES_FILE; do
            [ -n "${!var:-}" ] || { echo "OZPB_HARNESS_AUTHORITY_CHECK=cli needs $var"; exit 1; }
        done
        case "${OZPB_HARNESS_CONFIRM:-tty}" in tty|operator) ;; *) echo "OZPB_HARNESS_CONFIRM is tty or operator"; exit 1 ;; esac
        if [ "${OZPB_HARNESS_CONFIRM:-tty}" = tty ] && ! ( : < /dev/tty ) 2>/dev/null; then
            echo "OZPB_HARNESS_CONFIRM=tty needs a controlling terminal"; exit 1
        fi
        INSTALL_ARGS=(--authority-check cli --confirm "${OZPB_HARNESS_CONFIRM:-tty}")
        if [ -n "${OZPB_HARNESS_TRUST:-}" ]; then INSTALL_ARGS+=(--trust "$OZPB_HARNESS_TRUST"); fi
        ;;
    *) echo "OZPB_HARNESS_AUTHORITY_CHECK is cli or unset, not $OZPB_HARNESS_AUTHORITY_CHECK"; exit 1 ;;
esac

for tool in node npm stellar cargo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required"; exit 1; }
done
# @stellar/stellar-sdk 17 declares node >= 22.12.
node -e 'const [a, b] = process.versions.node.split(".").map(Number); process.exit(a > 22 || (a === 22 && b >= 12) ? 0 : 1)' \
    || { echo "node >= 22.12 is required, found $(node --version)"; exit 1; }

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
field() { node -p 'require(process.argv[1])[process.argv[2]]' "$RUN/run.json" "$1"; }

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN="${OZPB_HARNESS_OUT:-$HARNESS/runs/$RUN_ID}"
mkdir -p "$RUN"
RUN="$(cd "$RUN" && pwd -P)"
# Capture checkout/CLI identity before any live operation. Existing nonempty directories are
# refused so a failed attempt cannot inherit successful installation evidence from an old run.
node "$SCRIPTS/run-provenance.mjs" start "$RUN"
SECRETS=''
finish_run() {
    local run_status=$?
    trap - EXIT
    if [ -n "$SECRETS" ]; then rm -rf "$SECRETS" || { [ "$run_status" -ne 0 ] || run_status=1; }; fi
    # Finalize and export together, keeping provenance consistent with a reporting failure.
    node "$SCRIPTS/run-provenance.mjs" finalize "$RUN" "$run_status" || { [ "$run_status" -ne 0 ] || run_status=1; }
    exit "$run_status"
}
trap finish_run EXIT
SECRETS="$(mktemp -d)"
export OZPB_HARNESS_SECRETS="$SECRETS/keys.json"

# Always, so node_modules is exactly the lockfile rather than whatever an earlier install left.
npm ci --prefix "$SCRIPTS" --no-audit --no-fund --silent
# A passkey owner signs in headless Chromium (Playwright). OZPB_BROWSER_CHANNEL=chrome uses an
# installed Google Chrome; without it, Playwright's own build must have been installed once.
if [ "$OWNER" = passkey ]; then npm ci --prefix "$HARNESS/browser" --no-audit --no-fund --silent; fi

say "1. setup: throwaway keys, the pinned OpenZeppelin account (owner: $OWNER)"
node "$SCRIPTS/setup.mjs" --run-dir "$RUN" --owner "$OWNER" ${OZPB_HARNESS_VERIFIER:+--verifier "$OZPB_HARNESS_VERIFIER"}
AMOUNT="$(field amount)"
OTHER="$(field payer)"   # a funded account, so a wrong-recipient transfer cannot fail for lack of one
if [ "$WALKTHROUGH" = subscription ]; then
    node "$SCRIPTS/setup-subscription.mjs" --run-dir "$RUN" --policy "$OZPB_SUBSCRIPTION_POLICY" \
        --period-ledgers "$OZPB_SUBSCRIPTION_PERIOD_LEDGERS"
fi
RECIPIENT="$(field recipient)"

say "2. authorize the transfer that will justify the grant"
# The transaction the grant is built from is a real one. The owner authorizes it through rule 0,
# the account's Default rule, which has no policy. Keep raw XDR too; the next step records through RPC.
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --signer owner --rule 0 \
    --amount "$AMOUNT" --to "$RECIPIENT" --expect permit --bundle "$RUN/import-bundle.json"
if [ "$OWNER" = passkey ]; then
    # Negative control: the same transfer, the passkey signing random bytes instead of the account's
    # digest. The WebAuthn verifier must refuse it with its own ChallengeInvalid (#3114).
    node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --signer owner --rule 0 --wrong-challenge yes \
        --amount "$AMOUNT" --to "$RECIPIENT" --expect deny:3114
fi

say "3. record, synthesize, reference-check, generate and reproduce the policy"
# The generated crate builds offline against the same locked dependencies as the committed
# golden crate, so make sure they are in the cargo cache first.
( cd contracts/golden-transfer-policy && cargo fetch --locked >/dev/null )
node "$SCRIPTS/synthesis-flow.mjs" --run-dir "$RUN"
shopt -s nullglob
WASMS=("$RUN"/policy/*.wasm)
[ "${#WASMS[@]}" -eq 1 ] || { echo "expected one wasm in $RUN/policy, found ${#WASMS[@]}"; exit 1; }

say "4. install: deploy the policy, add_context_rule signed by the owner ($OWNER)"
node "$SCRIPTS/install.mjs" --run-dir "$RUN" --wasm "${WASMS[0]}" ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
node "$SCRIPTS/monitor.mjs" --run-dir "$RUN"

if [ "$WALKTHROUGH" = subscription ]; then
    say "5. verify subscription tuple, signer, rolling window and total call cap controls"
    node "$SCRIPTS/subscription-controls.mjs" --run-dir "$RUN"
else
say "5. permit exactly the recorded transfer, once; deny the rest"
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$RECIPIENT" --expect permit
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$((AMOUNT + 1))" --to "$RECIPIENT" --expect deny:6
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$OTHER" --expect deny:6
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$RECIPIENT" --expect deny:7
fi

say "6. inspect the grant, revoke it as owner, and require the account to refuse the removed rule"
node "$SCRIPTS/monitor.mjs" --run-dir "$RUN"
node "$SCRIPTS/lifecycle.mjs" --run-dir "$RUN"
node "$SCRIPTS/invoke.mjs" --run-dir "$RUN" --amount "$AMOUNT" --to "$RECIPIENT" --expect deny-account:3000

say "done"
echo "  account  https://stellar.expert/explorer/testnet/contract/$(field account)  (owner: $OWNER)"
echo "  policy   https://stellar.expert/explorer/testnet/contract/$(field policy)"
echo "  run      $RUN/run.json"
echo "  evidence $RUN/evidence.json (written on exit)"
