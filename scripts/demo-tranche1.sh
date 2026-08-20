#!/usr/bin/env bash
# Tranche 1 verifiable outcome, end to end against live Stellar testnet:
#
#   a recorded testnet transfer becomes a compilable Rust policy
#   that `stellar contract build` accepts
#
# Run it before showing it. Everything here talks to the real network, so it fails for real
# reasons: an endpoint that changed shape, a contract that expired from state archival, a
# transaction that aged out of RPC retention.
#
#   bash scripts/demo-tranche1.sh                     # uses/creates its own testnet identities
#   OZPB_ACCOUNT=C... bash scripts/demo-tranche1.sh    # reuse an existing OZ smart account
#   OZPB_DEMO_OUT=/tmp/run bash scripts/demo-tranche1.sh   # choose where the artifacts land
#
# Every file the run produces is kept, named by the step that produced it, under
# `demo-runs/<UTC timestamp>/` — with a `MANIFEST.md` saying what each one is. That directory is
# the thing to read after a run, or to zip and hand to a reviewer: the terminal output is a
# narration of it, not the evidence itself.
#
# Three things worth knowing before you present it.
#
# 1. **It records a *simulated* transfer, not an executed one.** `simulateTransaction` in
#    `authMode: record` asks the network which authorizations an invocation would require, and
#    returns them — so a recording needs no signature and no custody of anything. Phase 1's
#    recorder covers both the executed and simulated paths; the executed path additionally
#    needs the smart account's signer, which is the install machinery of the next tranche.
#
# 2. **A transaction hash cannot be replayed later.** RPC retention drops it after a few days,
#    so a demo built on "here is a hash from the document" breaks silently. This script makes
#    fresh state every run.
#
# 3. **The authorizer must be an OZ smart account**, not an ordinary G-account: a policy exists
#    to scope a smart account's context rule, so synthesis fails closed without one. The
#    account deployed here is OpenZeppelin's own example, and the code hash the network reports
#    for it must equal the one pinned in `ozpb_domain::pinned_upstream` — the script asserts
#    that, which is also a live check of the pin.
#
# 4. **The last step is supposed to be turned down.** "Minimum permission" is half a claim
#    without "refuses by default", so step 8 re-runs the synthesis of step 4 with one field of
#    one input changed and requires a refusal. It prints the refusal as the expected result and
#    the run still ends green; what would fail the demo there is the synthesis *succeeding*.
#
# Reading it. Each step says what it does and why it is done that way, for a reader who does
# not know the project. The JSON work lives in `scripts/demo/`, one file per job, each with a
# docstring explaining why that job exists here — a step that prints a summary and a step that
# asserts something are separate files on purpose, so that an `assert_*` line below is visibly
# a check that can fail the run rather than another line of output.
set -euo pipefail
cd "$(dirname "$0")/.."

NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
RPC_URL="${OZPB_RPC_URL:-https://rpc.testnet.stellar.gateway.fm}"
# The pinned OpenZeppelin account example; see ozpb_domain::pinned_upstream for provenance.
PINNED_ACCOUNT_WASM=a12747ff6c139dc14fc2fd30d200d6bbb5da7b5d59812c047ce1f9cad226b289
PINNED_SPENDING_LIMIT=4e67aa6ca226d3c16106ff2d95f3b44a8efabc2f2a7655683957e3553ed6a40c

for tool in stellar cargo python3 curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required"; exit 1; }
done

# Two directories, and the split is a security boundary rather than tidiness.
#
# WORK is a run directory that SURVIVES the run, because the point of the run is the artifacts:
# every input the toolkit consumed and every file it produced, named by the step that made it,
# so a reviewer can read them, diff them, or be sent them. Default `demo-runs/<UTC timestamp>/`
# under the repository (gitignored); override with OZPB_DEMO_OUT to put it anywhere.
#
# SECRETS is a temp directory that does NOT survive, and nothing in it is ever an artifact: it
# holds STELLAR_CONFIG_HOME, which is where `stellar keys generate` writes the throwaway
# identities' SECRET keys. They are worthless — testnet, Friendbot-funded, generated for this
# run — but a run directory meant to be zipped and handed to someone must not have private keys
# in it, so the two are separate and only one of them is printed.
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="${OZPB_DEMO_OUT:-demo-runs/$RUN_ID}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"          # absolute, so the paths printed below can be copied anywhere
SECRETS="$(mktemp -d)"
trap 'rm -rf "$SECRETS"' EXIT
export STELLAR_CONFIG_HOME="$SECRETS/stellar"
mkdir -p "$STELLAR_CONFIG_HOME"

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# Every artifact is announced by the step that wrote it, and the same call records it in the
# run's manifest. One function for both so a file cannot be printed without being described,
# or described without being printed — a manifest that drifts from the directory is worse than
# no manifest, because it is read as an inventory.
MANIFEST="$WORK/MANIFEST.md"
printf '# Demo run %s\n\nProduced by `scripts/demo-tranche1.sh` against Stellar testnet.\nEach entry is a file in this directory and what it is.\n\n' "$RUN_ID" > "$MANIFEST"
artifact() {   # $1 = path relative to WORK, $2 = one-line description
    printf '  → %s\n' "$1"
    printf -- '- `%s` — %s\n' "$1" "$2" >> "$MANIFEST"
}
step_note() { printf '\n## %s\n\n' "$1" >> "$MANIFEST"; }

say "0. setup: throwaway testnet identities (Friendbot-funded, no real value)"
# Three addresses, none of them anyone's:
#   payer — pays fees and signs the setup transactions. Funded by Friendbot, which hands
#           testnet XLM to whoever asks, so nothing here has value. STELLAR_CONFIG_HOME above
#           points into the temp directory, so the reader's own identities are never in scope.
#   payee — the transfer's recipient. It never signs, and the transfer to it is only ever
#           simulated, so it is an address to point at and nothing more.
#   SAC   — the Stellar Asset Contract for native XLM: the contract through which XLM moves
#           inside Soroban. Derived rather than deployed — each network has exactly one and
#           `stellar contract id asset` computes its address.
stellar keys generate payer --network testnet --fund >/dev/null 2>&1
stellar keys generate payee --network testnet >/dev/null 2>&1
PAYER="$(stellar keys address payer)"
PAYEE="$(stellar keys address payee)"
SAC="$(stellar contract id asset --asset native --network testnet)"
echo "  fee payer : $PAYER"
echo "  recipient : $PAYEE"
echo "  native SAC: $SAC"
step_note "0. Setup"
{ printf 'Public addresses only; the secret keys stayed in a temp directory this run deleted.\n\n'
  printf -- '- fee payer  `%s`\n- recipient  `%s`\n- native SAC `%s`\n' "$PAYER" "$PAYEE" "$SAC"; } >> "$MANIFEST"

ACCOUNT="${OZPB_ACCOUNT:-}"
if [ -z "$ACCOUNT" ]; then
    say "1. deploy OpenZeppelin's smart-account example"
    # Deployed from a wasm hash, not from a local file. The code is already installed on
    # testnet, and installing it again would mean cloning upstream at the pinned tag and
    # building it with the pinned toolchain — minutes of work whose only output is the hash
    # already written above. `scripts/verify-pinned-upstream.sh` is where that build belongs;
    # this script checks the same pin from the other end, by asking the network what the
    # deployed contract's code hash is (step 3).
    #
    # Deploying from a hash only works while that code is installed on this network, and nothing
    # in this repository guarantees it stays: the blob can be archived, and a network reset drops
    # it outright. If that happened, the deploy below would fail — and a reader checking the
    # delivery would land on the pinned constant as the obvious suspect and conclude the pin is
    # wrong. It would not be. Two very different situations, one indistinguishable symptom, so
    # separate them before deploying anything.
    #
    # `contract info interface --wasm-hash` fetches the blob by hash, which is exactly the
    # question "is this code on the network". Three outcomes, and the third is deliberately
    # non-committal: the message match is against the pinned stellar-cli (27.0.0, enforced by
    # scripts/check-build-input-pins.sh), and anything it does not recognize — an endpoint that is
    # down, an error text that changed between releases — is reported as undiagnosed rather than
    # guessed. A confident wrong diagnosis is what this whole check exists to avoid.
    if ! PROBE="$(stellar contract info interface --wasm-hash "$PINNED_ACCOUNT_WASM" \
            --network testnet 2>&1 >/dev/null)"; then
        echo "  the pinned account wasm could not be fetched from testnet:"
        printf '%s\n' "$PROBE" | sed 's/^/    /'
        case "$PROBE" in
            *"Contract Code not found"*)
                echo "  DIAGNOSIS: the pinned wasm is NOT INSTALLED on testnet. The pin is not in"
                echo "  question — this is the upload having gone away (archived, or a network"
                echo "  reset). Re-upload OpenZeppelin's account example, built at the pinned tag"
                echo "  with the pinned toolchain — scripts/verify-pinned-upstream.sh builds it —"
                echo "  and this demo works again with no change to the pinned constant." ;;
            *)
                echo "  DIAGNOSIS: undiagnosed. This says nothing about whether the pin is right or"
                echo "  whether the code is installed; the error above is not one this script"
                echo "  recognizes. Check the endpoint is up before reading anything into the pin." ;;
        esac
        exit 1
    fi
    echo "  pinned wasm is installed on testnet, so a mismatch in step 3 means the deployed"
    echo "  contract differs from the pin — not that the upload is missing"

    # The constructor arguments make the smallest account that can authorize anything. One
    # `Delegated` signer pointing at the payer: upstream's account delegates the check to that
    # address's ordinary protocol-level signature, so no verifier contract and no key material
    # are needed here. And no policies installed — installing one is the next tranche's flow,
    # and a policy already present would change what step 3 records.
    ACCOUNT="$(stellar contract deploy --wasm-hash "$PINNED_ACCOUNT_WASM" \
        --source payer --network testnet -- \
        --signers "[{\"Delegated\":\"$PAYER\"}]" --policies '{}' 2>/dev/null | tail -1)"
    echo "  account: $ACCOUNT"
else
    say "1. reusing the smart account given in OZPB_ACCOUNT"
    echo "  account: $ACCOUNT"
fi

say "2. fund the smart account so a transfer from it is simulatable"
# Step 3 asks what a transfer *out of the account* would require. Simulation runs the real
# contract against real ledger state, so an account with no balance produces a failed
# invocation and nothing to record. 5 XLM is arbitrary, and five times what step 3 moves.
stellar contract invoke --id "$SAC" --source payer --network testnet -- \
    transfer --from "$PAYER" --to "$ACCOUNT" --amount 50000000 >/dev/null 2>&1
echo "  sent 5 XLM to the account"

say "3. record: what authorization would this transfer require?"
# `--build-only` stops the CLI once the transaction envelope is assembled: it prints the XDR
# instead of signing and submitting. That envelope is the entire input the recorder needs.
#
# `ozpb simulate` then puts that unsigned envelope to RPC with `authMode: record`, which
# answers "which authorizations would this invocation require?" instead of executing it. There
# is no signature on the envelope, so nothing could have been submitted even by accident —
# which is the point: recording never takes custody of the account. (The executed path,
# `ozpb record --tx-hash`, is implemented as well and is what docs/TESTNET-EVIDENCE.md shows;
# it needs the account's signer, hence the next tranche.)
ENVELOPE="$(stellar contract invoke --id "$SAC" --source payer --network testnet --build-only -- \
    transfer --from "$ACCOUNT" --to "$PAYEE" --amount 10000000 2>/dev/null)"
cargo run -q -p ozpb-cli -- simulate --envelope-xdr "$ENVELOPE" \
    --rpc-url "$RPC_URL" --network "$NETWORK_PASSPHRASE" > "$WORK/03-recording.json"
python3 scripts/demo/summarize_recording.py "$WORK/03-recording.json"
step_note "3. Recording"
artifact "03-recording.json" "what RPC said this transfer would require: the authorization tree, the observed code hash of every contract involved, and the evidence trust level. Input to step 4."
# An assertion, not more output: the account's code hash as the network reports it must equal
# the pin, or the registry would not recognize the account and every step after this one would
# be evidence about some other contract. A mismatch exits non-zero and `set -e` stops here.
python3 scripts/demo/assert_account_matches_pin.py \
    "$WORK/03-recording.json" "$ACCOUNT" "$PINNED_ACCOUNT_WASM"

say "4. synthesize: a minimum-permission PolicySpec"
# Synthesis is pure: no network, no keys, no clock. Beyond the recording it takes three kinds
# of input, and the flags below come in that order:
#
#   the account   — which smart account this grant is for and what code it runs. Written just
#                   below; scripts/demo/write_account_record.py says what each field means.
#   the registry  — the signed capability snapshot, the root keys that vouch for it, and the
#                   lowest snapshot version still accepted. Together: what the toolkit is
#                   allowed to recognize — which account releases, which reviewed policies.
#   the decisions — what the user asked for: expiry ledger, call cap, spend limit, signers.
#                   The committed file is a deterministic example, so this live run copies it
#                   and derives expiry from getLatestLedger plus a 120,960-ledger horizon.
#
# The registry and decision template come from `docs/examples/`, committed exactly as a reader
# consumes them. The live decision copy differs in expiry only, because a committed absolute
# ledger necessarily expires.
# The demo deliberately does not regenerate them first: `ozpb dev-registry` would repair any
# drift from `registry::dev` in place and then pass anyway, hiding exactly what running the
# committed inputs is meant to expose. That drift is caught offline instead, by ozpb-toolkit's
# `examples_are_current` test.
#
# The last two flags name capabilities inside that registry: `--template-family` the audited
# codegen template the generated policy is built from, `--spending-limit-capability`
# OpenZeppelin's reviewed spending-limit policy — by wasm hash, because the registry resolves
# reviewed policies by hash and never by claimed kind. Hence a hash here and not a name.
#
# A function rather than a literal command because the last step runs it a second time with one
# field of the account record changed and nothing else, to watch it refuse. Keeping one
# definition is what makes that comparison worth anything.
synthesize() {   # $1 = account record; prints the synthesis JSON on stdout
    cargo run -q -p ozpb-cli -- synthesize \
        --bundle "$WORK/03-recording.json" --selected-authorizer "$ACCOUNT" \
        --account "$1" \
        --signed-registry docs/examples/registry.signed.json \
        --registry-roots docs/examples/registry-roots.json --registry-min-version 1 \
        --decisions "$WORK/04-decisions.json" \
        --template-family policy-templates/scope@1 \
        --spending-limit-capability "$PINNED_SPENDING_LIMIT"
}
curl --fail --silent --show-error --max-time 30 \
    -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"getLatestLedger","params":{}}' \
    "$RPC_URL" > "$WORK/04-latest-ledger.json"
python3 scripts/demo/write_live_decisions.py \
    "$WORK/04-latest-ledger.json" docs/examples/decisions.json "$WORK/04-decisions.json"
python3 scripts/demo/write_account_record.py \
    "$WORK/04-account.json" "$ACCOUNT" "$PINNED_ACCOUNT_WASM"
synthesize "$WORK/04-account.json" > "$WORK/04-synthesis.json"
python3 scripts/demo/summarize_synthesis.py "$WORK/04-synthesis.json"
# `ozpb generate` takes a PolicySpec, while synthesis printed the spec inside an envelope with
# its hash and rationale, so hand codegen the spec on its own.
python3 scripts/demo/extract_spec.py "$WORK/04-synthesis.json" "$WORK/04-spec.json"
step_note "4. Synthesis"
artifact "04-latest-ledger.json" "RPC's unedited answer to getLatestLedger. The step reads one field of it, result.sequence, and derives the grant's expiry from that — which is why a committed absolute ledger would go stale. Kept whole rather than trimmed, so it is the response and not our summary of one; that is also why it is the largest file here, since ~460 KB of it is the metadataXdr blob nothing in this run touches."
artifact "04-decisions.json" "what the user asked for: expiry ledger, call cap, spend limit, signers. docs/examples/decisions.json with the expiry made live."
artifact "04-account.json" "which smart account this grant is for and what code it runs. The toolkit overwrites registry_resolution with the entry it actually resolved."
artifact "04-synthesis.json" "the synthesis output: the PolicySpec, its canonical hash, and the rationale lines printed above."
artifact "04-spec.json" "the PolicySpec alone, lifted out of the envelope. What codegen consumes, and the identity the BuildManifest refers back to."

say "5. generate the policy crate"
# Codegen writes a complete, standalone Soroban crate — source, manifest, pinned lockfile and
# toolchain file — builds it to Wasm, and records what went into it in a BuildManifest. It
# never deploys and never signs.
cargo run -q -p ozpb-cli -- generate --spec "$WORK/04-spec.json" --rule 0 --out "$WORK/05-policy" >/dev/null
# The two greps are the readability claim, made against the generated source rather than
# asserted in prose: the limits are `const`s at the top of the file, so what the policy allows
# can be read without following any configuration, and the error enum names every way the
# policy can refuse, so the deny paths are enumerable by reading too.
echo "  the limits are visible in the source, not buried in configuration:"
grep -E "^const (TARGET|VALID_UNTIL_LEDGER|MAX_CALLS)" "$WORK/05-policy/src/lib.rs" | sed 's/^/    /'
echo "  and every rejection path is named:"
grep -oE "PolicyError::[A-Za-z]+" "$WORK/05-policy/src/lib.rs" | sort -u | tr '\n' ' ' | sed 's/^/    /'; echo

step_note "5. Generated crate"
artifact "05-policy/" "a complete standalone Soroban crate: src/lib.rs, Cargo.toml, the pinned Cargo.lock and rust-toolchain.toml, the unoptimised .wasm, and build-manifest.json. Nothing here was hand-edited."
artifact "05-policy/src/lib.rs" "the policy a reviewer reads: limits as consts at the top, PolicyError naming every way it can refuse."
artifact "05-policy/build-manifest.json" "what went into the build — spec hash, registry snapshot root, source and wasm hashes, toolchain, exact build arguments."

say "6. THE OUTCOME: the real toolchain accepts it"
BUILD_STEP_DIR="$WORK/05-policy"
# The claim of this milestone in one command: the crate that came out of a recorded transaction
# compiles to Wasm under the pinned `stellar contract build`, with nothing edited by hand.
( cd "$BUILD_STEP_DIR" && stellar contract build )
# That build writes ~280 MB of intermediates and its own optimised wasm into the crate's
# `target/`, which would be 99% of a directory whose whole purpose is to be readable and
# sendable. Both are deliberately not evidence: the optimised artifact is not what this project
# pins (see below), and the intermediates are not what anyone reviews. Removing it leaves the
# crate exactly as codegen wrote it, which is also what step 7 compares against.
rm -rf "$BUILD_STEP_DIR/target"
step_note "6. The outcome"
{ printf 'The pinned `stellar contract build` accepted the generated crate unmodified.\n\n'
  printf 'Its optimised output is deliberately not kept. The hash this project pins is the\n'
  printf 'unoptimised one recorded in `05-policy/build-manifest.json`, and that is what a later\n'
  printf 'milestone deploys — so keeping an optimised blob here would only invite comparing the\n'
  printf 'wrong two values.\n'; } >> "$MANIFEST"
say "7. determinism: the same spec produces the same source"
# Generate a second time from the same spec into a different directory, then assert the two
# agree — on the source a reviewer reads, and on the wasm hash the build manifest records.
cargo run -q -p ozpb-cli -- generate --spec "$WORK/04-spec.json" --rule 0 --out "$WORK/07-policy-again" >/dev/null
python3 scripts/demo/assert_regenerated_identically.py "$WORK/05-policy" "$WORK/07-policy-again"
step_note "7. Determinism"
artifact "07-policy-again/" "a second generation from the same spec into a different directory. Byte-identical to 05-policy/ — diff them yourself; that equality is the claim."
echo "  (the hash from step 6 differs because \`stellar contract build\` optimizes;"
echo "   \`ozpb generate\` builds unoptimized so the artifact stays reviewable)"

say "8. fail-closed: the same synthesis refuses an unregistered account code hash"
# Steps 3 to 7 are all the permit path. The project claims two things — minimum permission AND
# refusal by default — and a demo that only ever succeeds evidences the first one. So here is the
# second, made as cheaply and as honestly as it can be made: change one field of one input, run
# the identical command from step 4, and require it to turn the request down.
#
# Account compatibility is established by resolving the RPC-observed code hash through the signed
# registry. It is not a caller boolean. Change only the account record's hash to a syntactically
# valid but unknown value; synthesis must refuse before it can construct a spec.
UNREGISTERED_ACCOUNT_WASM="$(printf '00%.0s' {1..32})"
python3 scripts/demo/write_account_record.py \
    "$WORK/08-account-tampered.json" "$ACCOUNT" "$UNREGISTERED_ACCOUNT_WASM"
echo "  input differs from step 4 in one field: observed_code_hash is now all zeroes"
# Wrapped in `if` rather than called plainly, because `set -e` would read the expected non-zero
# exit as the end of the demo. Note which branch is which: the *success* branch below is the
# failure case, since a spec produced from an account the toolkit cannot vouch for is the defect
# this step exists to catch. The refusal falls through to the assertion.
if synthesize "$WORK/08-account-tampered.json" > "$WORK/08-tampered-synthesis.json" 2> "$WORK/08-refusal.txt"
then
    echo "  FAIL-CLOSED CHECK FAILED: synthesis SUCCEEDED with unregistered account code."
    echo "  A spec was written for an account hash absent from the signed registry:"
    echo "  $WORK/08-tampered-synthesis.json"
    exit 1
fi
python3 scripts/demo/assert_refused_for_account_hash.py "$WORK/08-refusal.txt"
# Empty, because the refusal happened before a spec could be written. Keeping a zero-byte file
# next to the real artifacts would read as "a spec was produced and it was blank".
rm -f "$WORK/08-tampered-synthesis.json"
step_note "8. Fail-closed"
artifact "08-account-tampered.json" "step 4's account record with one field changed: observed_code_hash is all zeroes. Diff it against 04-account.json — that is the whole difference."
artifact "08-refusal.txt" "the refusal as the toolkit wrote it: E_INCOMPATIBLE_ACCOUNT, no registry entry recognises that code hash. This step passing MEANS this file exists."

say "done"
echo "  account   https://stellar.expert/explorer/testnet/contract/$ACCOUNT"
{ printf '\n## Not in this run, deliberately\n\n'
  printf 'The permit/deny dry-run report, the wallet install flow and the hosted endpoint are the\n'
  printf 'next tranche. Nothing here deploys a policy or signs anything: the recording is a\n'
  printf 'simulation, and the generated crate is built but never installed.\n'
  printf -- '\n- account on chain: https://stellar.expert/explorer/testnet/contract/%s\n' "$ACCOUNT"; } >> "$MANIFEST"

# The run directory is the deliverable, so end by showing it rather than by naming one path
# inside it. `find` and not `ls -R`, because the generated crates are the interesting part and
# they are two levels down; the depth cap keeps each crate to its own files rather than the
# hundreds under its `target/` if a reader has built one by hand since.
echo "  artifacts $WORK"
echo
( cd "$WORK" && find . -maxdepth 2 -name target -prune -o -not -name '.' -print | sort | sed 's|^\./|    |' )
echo
echo "  MANIFEST.md in that directory says what each file is, so the directory can be zipped"
echo "  and read by someone who did not watch it run."
echo
echo "  Not shown, deliberately: the permit/deny dry-run report, the wallet install flow and"
echo "  the hosted endpoint are the next tranche's deliverables."
