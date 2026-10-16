# Testnet harness (Tranche 2)

Installs a generated policy into an OpenZeppelin smart account on Stellar testnet and shows the
account enforcing it. Signing is done the way a wallet would do it, with no wallet product
involved. Not to be confused with `crates/harness`, the offline dry-run harness. This one talks to
the live network and spends testnet XLM.

```
bash testnet-harness/run.sh                                                       # owner: an ed25519 key
OZPB_HARNESS_OWNER=passkey OZPB_BROWSER_CHANNEL=chrome bash testnet-harness/run.sh   # owner: a passkey
```

The account's owner is the one signer of its rule 0, and it is what authorizes the recorded
transfer and the install. By default it is an ed25519 key held by the script. With
`OZPB_HARNESS_OWNER=passkey` it is a passkey, created and used headless in Chrome's virtual
authenticator, behind the pinned OpenZeppelin WebAuthn verifier: the kind of account a passkey
wallet such as pollywallet creates. Everything else is the same in both runs, the delegate
included.

One run, on fresh throwaway keys:

1. **setup** deploys the pinned OpenZeppelin account example from its wasm hash. It checks that
   the code hash the network reports is the pin in `ozpb_domain::pinned_upstream`, reads rule 0
   back (Default context, exactly the owner, no policy, no expiry), then funds the account. With a
   passkey owner it first deploys the [pinned WebAuthn verifier](#the-pinned-webauthn-verifier)
   from its hash, checks the code hash, and creates the passkey.
2. **record** has the account's owner authorize a real 1 XLM transfer out of the account,
   through rule 0. `ozpb import` decodes the executed transaction into a recording. With a
   passkey owner, a negative control follows: the passkey signs random bytes instead of the
   account's digest, and the verifier must refuse that with its own `ChallengeInvalid` (#3114).
3. **spec** fills in `native-sac-policy-spec.json` from that recording: exactly that transfer,
   `from = SELF`, granted to a different signer (the delegate), at most once.
4. **generate**: `ozpb generate` builds the policy crate and its wasm.
5. **install** deploys the wasm. It then calls `add_context_rule` on the account, with the owner
   (key or passkey) signing. The policy's own `install` runs inside that call. The script reads
   back `is_installed` from the policy.
6. **permit/deny**: the delegate makes the account call the native SAC's `transfer`.
   - The exact recorded transfer is permitted once.
   - One stroop more is refused with the policy's `NoTupleMatched` (#6).
   - Another recipient is refused with #6.
   - The exact transfer a second time is refused with `CallCountExceeded` (#7).

Every address, transaction hash and outcome goes into `runs/<timestamp>-<pid>/run.json`, which
is gitignored. The run directory also holds the import bundle, the recording, the spec and the
generated crate.

`run.sh` requires an empty output directory. It records the checkout commit, dirty state,
Node version, and start/end timestamps in `provenance.json`. With `OZPB_BIN`, it hashes the
selected executable's bytes; that hash does not prove the binary was built from the checkout.
Cargo mode records the checkout and explicitly leaves the executable hash unavailable.
These observations describe startup, not changes made to the checkout or executable during
the run. The exit status is process bookkeeping, not an acceptance verdict.

On normal shell exit, including a failed step, it writes `evidence.json`: an allowlisted
summary of recorded addresses, transaction IDs, policy-error codes and available artifact
digests. A hard kill can leave provenance unfinished. An exporter error fails the wrapper
and updates its recorded exit code; an existing failure retains its original code. Successful
summaries are published by atomic rename so an interrupted write cannot leave partial JSON
and an output symlink cannot redirect the write. Malformed records, including explicit JSON
`null`, are refused; only absent files count as missing evidence.
The summary omits seeds, passkey credential data, local paths, RPC URLs, free-form errors and
operator trust files. It still reveals public account relationships, so review it before
sharing. It is never published automatically. Raw run files remain local.

To regenerate the summary for a saved run (including an older run without provenance):

```bash
node testnet-harness/scripts/evidence.mjs --run-dir /path/to/run > /path/to/run/evidence.json
```

Old runs say provenance is unavailable. A missing install record means installation was not
recorded, not that nothing was submitted. Permits carry submitted transaction hashes; denials
are labeled enforcing simulations and have no transaction hash. Artifact digests cover exact
file bytes, including whitespace in JSON; they are not the canonical spec hash or independent
Wasm reproduction. Local records can be edited, and neither a zero exit nor this summary
establishes authenticated ledger state or completion of the milestone.

## Prerequisites

- Node ≥ 22.12 (required by `@stellar/stellar-sdk` 17), `stellar` CLI 27.0.0, and the Rust
  toolchain `rust-toolchain.toml` pins, with `wasm32v1-none`. The CLI is used by
  `ozpb generate`.
- Network access to `soroban-testnet.stellar.org` and Friendbot. Override the RPC with
  `OZPB_RPC_URL`. The scripts' own output and `run.json` show only its origin, but an error raised
  inside the RPC client can still print the full URL, so keep credentials out of it. Every script
  that signs first checks that the endpoint serves testnet.
- `run.sh` runs `npm ci` in `scripts/` every time. Dependencies are pinned exactly and locked.
- `ozpb` comes from `cargo run -p ozpb-cli`, or from `OZPB_BIN`. `ozpb generate` builds with
  cargo offline in its build cache (`OZPB_BUILD_CACHE_DIR`), so `run.sh` first fetches the golden
  crate's locked dependencies.
- Before installing, `ozpb reference-suite` validates and canonically hashes the current spec.
  Its hash must match the adjacent build manifest, alongside the Wasm hash, rule index and
  registry root. This runs on both install paths with the same `OZPB_BIN` (or local Cargo CLI)
  as generation. It catches stale artifacts; it trusts the local generator's manifest rather
  than reproducing the Wasm. Use `ozpb verify` for independent artifact reproduction.
- The installer accepts exactly one generated scope+count policy. Composed rules, including
  a reviewed spending limit, are refused before deployment rather than installed incompletely.
  Once deployment succeeds, its address, Wasm hash and transaction hashes are saved before
  asking the wallet to approve. A refused or declined attempt retains those identifiers;
  a rule ID and install transaction are recorded only after a successful install.
- A passkey owner also needs headless Chromium: `run.sh` runs `npm ci` in `browser/` too, and
  `OZPB_BROWSER_CHANNEL=chrome` uses an installed Google Chrome (otherwise run
  `npx playwright install chromium` there once). `OZPB_HARNESS_VERIFIER=C…` reuses an existing
  verifier instance instead of deploying one; its code hash is checked the same way.

## Keys

`setup.mjs` generates these keys with `Keypair.random()` and funds them from Friendbot:

- payer: pays fees and deploys the contracts
- owner: the account's administrator (ed25519 runs only)
- delegate: the grantee
- recipient

The seeds go to the file `OZPB_HARNESS_SECRETS` names. `run.sh` points it into a `mktemp -d`
directory and deletes that directory on exit. Seeds are never printed and never written to the
run directory. Only the payer, owner and delegate seeds are kept; the recipient's is dropped.

A passkey owner has no seed. Its credential lives in Chrome's virtual authenticator, which dies
with the browser, and the run signs from separate scripts with cargo steps in between. So after
creation the credential, private key included, is exported through the DevTools Protocol into the
same secrets file, and each later signature imports it into a fresh virtual authenticator. That
makes the owner a WebAuthn assertion from Chrome's virtual authenticator over a software key the
harness holds; a real authenticator never lets its key out. Playwright's `pw:protocol` and
`pw:channel` debug logs would print that key, so `browser/passkey.mjs` refuses to start when
`DEBUG` could enable them. The passkey's public key and credential id are public and go into
`run.json`.

## How the account is signed for

Whatever the signer, `__check_auth` in `stellar-accounts` 0.7.2 first binds the rule selection
into the payload: `auth_digest = sha256(signature_payload ‖ xdr(context_rule_ids))`. The signer
then proves it authorized that digest. How depends on its kind.

The delegate, and the owner in an ed25519 run, are `Delegated` Stellar accounts. For such a
signer the account calls `signer.require_auth_for_args((auth_digest,))`, so a call from the
account carries two authorization entries:

- **The account's own entry.** Its signature is an `AuthPayload`. It names the signer with an
  empty proof and selects the rule.
- **The signer's entry.** It is rooted at `account.__check_auth(auth_digest)` and signed with the
  signer's ed25519 key.

`scripts/lib.mjs` builds both. `lib.test.mjs` checks the encodings against bytes written out from
the XDR definitions. It also verifies the signer's signature with node's own ed25519, not the
SDK's.

A passkey owner is an `External` signer: `External(verifier, key_data)`, where `key_data` is the
65-byte uncompressed P-256 public key followed by the credential id. pollywallet lays its key data
out the same way. For such a signer `__check_auth` calls
`verifier.verify(auth_digest, key_data, sig_data)`, and there is no second entry. The proof is in
the account's own `AuthPayload`:

- The passkey signs with WebAuthn `navigator.credentials.get`, challenge = the 32-byte
  `auth_digest`. The verifier requires `clientDataJSON` to be a `webauthn.get` whose challenge is
  `base64url(auth_digest)`, and the user-present and user-verified flags to be set. It does not
  check the origin, the relying party or the sign counter.
- `sig_data` is the XDR of `WebAuthnSigData { authenticator_data, client_data, signature }`. The
  signature is 64-byte r ‖ s with s folded into the lower half of the group order. WebAuthn
  returns DER, and the host refuses a high-s signature.

`browser/passkey.mjs` drives the browser, and checks every assertion with node's crypto
(`browser/assertion.mjs`) before it is used. `scripts/owner.mjs` turns it into `sig_data`.
`lib.test.mjs` checks the External signer, `AuthPayload` and `WebAuthnSigData` bytes the same way
as the Delegated ones. It also checks the DER conversion against node's P-256.

## The pinned WebAuthn verifier

The passkey's verifier is OpenZeppelin's WebAuthn verifier example. It comes from the same tag,
commit and toolchain as the pins in `ozpb_domain::pinned_upstream`:

- Source: `github.com/OpenZeppelin/stellar-contracts` `v0.7.2` (`a9c42169000638da937577f592ebf61a7a3c94ca`),
  `examples/multisig-smart-account/webauthn-verifier`.
- Build: `RUSTUP_TOOLCHAIN=1.91.1 stellar contract build` in that directory, with stellar-cli
  27.0.0. That is the command `scripts/verify-pinned-upstream.sh` uses for the other pins, and the
  same build reproduces the pinned account hash.
- Wasm hash: `e63a030d0f1a1481e36059a4837c433083b33e704c1f9625b7314795b6d72b76`
  (`PINNED_WEBAUTHN_VERIFIER_WASM` in `scripts/rpc.mjs`). `setup.mjs` deploys an instance from
  it, which needs the code already on the ledger: like the pinned account wasm, the harness
  never uploads it. On 2026-10-15 its code entry was live until ledger 7878982. After it is
  archived, or after a testnet reset, the deploy fails until someone uploads (or restores) the
  same bytes, built as above.

The verifier can neither change nor remember anything. Its source has no storage, constructor or
upgrade entry point. The built wasm exports only `verify`, `canonicalize_key` and
`batch_canonicalize_key`, and imports no ledger host functions: none of the contract-data calls,
and not `update_current_contract_wasm`, the only way an instance's code can change. So every
instance of this hash gives the same answer for the same input, and nobody, its deployer
included, can change that.

It is pinned for this harness only. The capability registry does not recognize it yet, and
`scripts/verify-pinned-upstream.sh` does not rebuild it. pollywallet's verifier is not this
code: its contract metadata shows a different soroban-sdk and stellar-cli, so it does not
reproduce from our pinned inputs.

## Running the parts

```
cd testnet-harness/scripts && npm ci && npm test       # offline installer and wallet tests
export OZPB_HARNESS_SECRETS=$(mktemp -d)/keys.json
node setup.mjs --run-dir R                     # or --owner passkey, after npm ci in ../browser
node invoke.mjs --run-dir R --signer owner --rule 0 --amount 10000000 --to <recipient> \
    --expect permit --bundle R/import-bundle.json
ozpb import --bundle R/import-bundle.json > R/recording.json
node write-spec.mjs --run-dir R
ozpb generate --spec R/spec.json --rule 0 --out R/policy
node install.mjs --run-dir R --wasm R/policy/<name>.wasm
node invoke.mjs --run-dir R --amount 10000000 --to <recipient> --expect permit
```

CI runs both this suite and `npm test` in `testnet-harness/browser`, with locked dependencies
and pinned Node. The installer tests run the real local CLI (`OZPB_BIN`, or Cargo) but mock
the RPC and key boundaries; they require the Rust dependencies to be cached for offline use.
The browser suite tests the passkey modules without launching a browser. Neither suite signs
or submits a live transaction.

`invoke.mjs --expect deny:<code>` passes only if both of these hold:

- the account's authentication failed;
- the policy contract itself raised that code.

The same number from another contract does not count. The native SAC's #6, for example, is
`AccountMissingError`. The passkey's negative control,
`invoke.mjs --signer owner --rule 0 --wrong-challenge yes --expect deny:3114`, counts the code only
when the WebAuthn verifier contract raised it.

## What a run does and does not show

**Shown**, on live testnet:

- The pinned account runs a generated policy as one of its context rules.
- A wallet-style signed `add_context_rule` installs it. Before any signer of the account signs,
  ed25519 or passkey, `install.mjs` and `invoke.mjs` check that the authorization the RPC asks
  for is exactly the call they mean to make. The fee payer's own deploy, fund and upload
  transactions take the simulation's source-account authorization as returned.
- With a passkey owner, the pinned WebAuthn verifier accepts the passkey's signatures for
  the recorded transfer and the install, and refuses one over a different challenge.
- The account then permits the exact recorded call once.
- It refuses the call with a changed amount, with a changed recipient, and past the call cap.
  Each refusal is the policy's own published error code.

**Not shown, or not as you might assume:**

- **Synthesis does not run.** Step 3 writes the spec by hand, because `ozpb synthesize` cannot
  run against testnet on this tree. There are two reasons:
  - The RPC recorder refuses protocol 29 (`crates/source-rpc` decodes at most 28).
    `ozpb simulate` against testnet fails with `E_RPC: unsupported protocol`.
  - A recording made by `ozpb import` has no observation of the account's executable, and
    synthesis requires one (`E_INCOMPATIBLE_ACCOUNT`).

  `write-spec.mjs` requires the template's exact shape and checks the call constraints
  (contract, function, from, to, amount) and the network against the recording. It cites the
  recording's real hash and `self_supplied` trust. The signer, expiry and call cap are the run's
  decisions, not observations. Nothing in the spec was resolved against the signed registry:
  `registry_snapshot` is all zeroes and `registry_resolution` says so. The
  committed template's own evidence entry is a zero hash labelled `incomplete`, so
  `ozpb generate` refuses the unfilled template.
- **Denials have no transaction hash.** Each one is observed in the enforcing simulation, which
  runs `__check_auth` and the policy exactly as the network would. The authorization entries are
  signed, but the transaction is not, nothing is submitted, and the call count is not spent.
- **By default `run.sh` skips the authority check.** It installs only into the account it
  deployed a moment earlier, whose administrator it knows by construction. That is not evidence
  about anyone else's account. The opt-in wallet decision on the check
  ([`OZPB_HARNESS_AUTHORITY_CHECK=cli`](#the-wallet-decision-on-the-authority-check)) needs an
  `ozpb` with commands this tree does not have yet.
- **No wallet product signs.** With the default owner, a script holding an ed25519 key signs.
  With `OZPB_HARNESS_OWNER=passkey`, the account has a passkey wallet's shape: rule 0 is one
  `External` WebAuthn signer. The passkey signs the recorded transfer and the install, and the
  verifier checks it on chain. But the passkey is Chrome's virtual authenticator over a key the
  harness holds, not a device. And the harness creates the account itself: pollywallet's page,
  relayer and deployer are not involved.
- **The PolicySpec still has no External signers.** The grant's signer is the delegate, an
  ed25519 `Delegated` signer, in both runs. Spec validation refuses External signers on this tree,
  so a passkey can own the account but cannot be the grantee.

## The wallet decision on the authority check

The authority check (`ozpb check-policy-call-surface`) reads who can change the account, or the
policy being installed, and lists them. It refuses what it can rule out on its own. It never says
the install is safe: the wallet that holds the owner key decides. `scripts/wallet-decision.mjs` is
that decision, and `scripts/approve-install.mjs` runs it:

1. Ask `ozpb prepare-install-intent` for the `add_context_rule` arguments. The tool runs the check
   itself and answers only when nothing is refused or unresolved. A refusal or any other error is
   a refusal here too, and its findings are shown.
2. Require the intent's arguments to be exactly the grant the check covered. The answer must be
   about this account, network, target, bound policy, spec rule, spec hash and registry root, and
   its scope must be exactly that target, account and policy.
3. Accept only when all of these hold:
   - the check refused nothing and left nothing unresolved;
   - the grant does not target the account itself or its own policy, and has not expired at the
     ledger the answer was read;
   - every rule that can change the account or the bound policy needs at least one trusted
     signer.
4. Show the confirmation screen and ask.
5. Just before signing, run the check again (a fresh read). Require the same
   `authority_commitment`, a ledger no older than the first read, and the fresh answer accepted
   under step 3. Expiry is outside the commitment, so it is judged again at the fresh ledger.
   As the intent itself instructs, its arguments must also equal the grant the fresh answer
   reports.

Trusted means the run's own owner key plus any identity in `--trust`. Identities are compared by
scheme and key. The verifier address does not count, and an ed25519 key behind a verifier is the
same identity as the classic account with that key. Some identities never count, even when
listed:

- one the check marks as aliasing the restricted key, in any rule;
- one that shares key material with the grant's own signer. The wallet uses the check's test
  (equal bytes, or equal first 32 bytes).

Two choices go beyond the check's contract. An empty authority list is refused, where the
contract would accept it vacuously. Arguments are signed only if they equal, byte for byte, the
rule `install.mjs` builds from the spec.

```
OZPB_HARNESS_AUTHORITY_CHECK=cli OZPB_BIN=<ozpb with the check commands> \
OZPB_REGISTRY_SNAPSHOT_ROOT=<root of the signed snapshot> OZPB_SIGNED_REGISTRY_SNAPSHOT=registry.signed.json \
OZPB_REGISTRY_ROOTS_FILE=registry-roots.json OZPB_REGISTRY_MIN_VERSION=3 OZPB_RPC_SOURCES_FILE=sources.json \
[OZPB_RPC_SOURCE=testnet] [OZPB_HARNESS_CONFIRM=tty|operator] [OZPB_HARNESS_TRUST=trust.json] \
bash testnet-harness/run.sh
```

- **The binary.** `OZPB_BIN` must be an `ozpb` built from a tree that has
  `check-policy-call-surface` and `prepare-install-intent`, which this tree does not. `run.sh` uses
  the same binary for `ozpb generate`, so the check's rebuild of the policy can match.
  `OZPB_RPC_SOURCE` names the entry in the sources file, `testnet` by default. `run.sh` checks all
  of these before setup starts.

- **The registry root.** `write-spec.mjs --registry-root` writes the root into the spec before
  `ozpb generate`. The check refuses a spec whose `registry_snapshot` is not the root of the
  signed snapshot it is given, and a zero root. That names the registry the check uses; nothing in
  the spec is resolved against it. For the development snapshot, recognition rests on a public
  development root, which is testnet only.
- **The policy binding.** It carries the policy's build manifest unmodified, and its deploy
  transaction as `resolution_reference`. The signed snapshot goes into the request byte for byte.
  Parsing it in JavaScript would turn its 64-bit integers into different numbers, and the check
  would refuse it. The check rebuilds the policy offline to recognize it.
  Run it with the same stellar-cli and the same warm build cache as `ozpb generate`
  (`OZPB_STELLAR_BINARY`, `OZPB_BUILD_CACHE_DIR`), or the rebuild cannot match.
- **The trust file.** `trust.json` is
  `{"operator": [{"classic_account": "G…"}, {"scheme": "webauthn_p256", "public_key": "04…"}]}`.
- **The error format.** `scripts/check-runner.mjs` reads the error code only from the first line
  of stderr (`Error: E_CODE: …`). Each `  - …` line after it is one finding. Any other non-zero
  exit counts as a refusal: an unreadable file, a usage error, a crash.

**What this does not show.**

- The trust is **operator-supplied test configuration**. `--trust`, the run's own key and
  `--confirm operator` all come from whoever runs the script, and `--confirm operator` is no
  prompt at all. `--confirm tty` is a terminal prompt, and anyone with that terminal can answer it.
  None of this shows that a human approved the install, or that an agent with the same access
  could not approve itself. That claim needs a real wallet's protected approval screen.
  `run.json` records the decision under that label, with the exact operator-trusted identities.
- It ran on testnet once per path, on 2026-10-15. Both runs used a passkey owner and an `ozpb`
  built from the branch that has the check, because `ozpb check-policy-call-surface` and
  `ozpb prepare-install-intent` are not on this tree. One run was accepted: the intent, the
  decision, the screen, the re-check and the install all ran, and then the delegate's permit and
  denials. The other was refused: a second owner rule for an account the wallet does not trust,
  and no `--trust`. Nothing was signed in that run. The second owner was added by a one-off
  script that is not in this tree. Neither run used `--confirm tty` or `--trust`, and no tool-side
  refusal happened on testnet. The tests drive the decision with fixtures hand-written from the
  check's output types and contract, not captured from the tool. They drive the CLI seam with a
  fake `ozpb` that prints the documented error format.
- Several cases are the check's to catch, and they reach the wallet only as refusals:
  - a signerless permissive policy on the target;
  - the agent added as a classic account's signer;
  - a missing or zero-weight classic account.

  An owner-only rule scoped to the bound policy is not a refusal. The check lists it, and the
  wallet must trust its owner like any other.
- What the check itself does not cover: the RPC endpoint is trusted, with no ledger proof.
  Classic accounts must be master-key only. Threshold and policy-guarded owner rules and nested
  accounts are refused, not analysed. Rules for other contracts are listed as not analysed.

## Against RFP 7

RFP 7 asks for wallet integration with at least one Stellar smart-account wallet, end to end:
record → generate → simulate → sign → install. For each link: what runs in this directory today,
and what does not.

- **record.**
  - Runs, offline only: a transfer the account really executed, decoded by `ozpb import`, with
    `self_supplied` trust.
  - Does not run: the live RPC recorder (`ozpb record`, `ozpb simulate`). It refuses
    protocol-29 testnet on this tree.
- **generate.**
  - Runs: codegen (`ozpb generate`).
  - Does not run: synthesis. `write-spec.mjs` fills the template by hand and checks the call
    constraints against the recording; no registry resolution happens.
- **simulate.**
  - Runs: every transaction that carries the account's authorization is simulated in enforcing
    mode, with the signed entries, before the transaction is signed. Every denial is observed
    there.
  - Not run on the generated policy here: the offline dry-run harness (`crates/harness`) and
    `ozpb evaluate`.
- **sign.**
  - Runs, on chain, with `OZPB_HARNESS_OWNER=passkey`: the account's owner is a passkey. It signs
    the recorded transfer and `add_context_rule` through WebAuthn, and the pinned OpenZeppelin
    WebAuthn verifier checks each signature on chain. A signature over a random challenge instead
    of the account's digest is refused by the verifier with `ChallengeInvalid` (#3114). Before signing, the script checks that the RPC asked for
    exactly the intended call. The delegate signs with an ed25519 key in both runs.
  - Not a device: the passkey is Chrome's virtual authenticator, its key exported to the run's
    secrets between steps.
- **install.**
  - Runs: `add_context_rule` on testnet, after which the policy enforces.
  - Runs, opt-in, with an `ozpb` from the branch that has the authority check: the wallet decision
    on the install intent and the check. It ran on testnet once accepted and once refused, both
    with a passkey owner ([details](#the-wallet-decision-on-the-authority-check)). Neither the
    intent nor the check is on this tree yet.
- **with a wallet.**
  - Runs: pollywallet's own wallet creation, driven headless in its real UI (`browser/`).
  - Closest that runs, with no wallet product involved: an account of pollywallet's shape, created
    by the harness on the pinned account and verifier. It has one passkey `External` signer on
    rule 0, with the same constructor arguments and key-data layout as pollywallet's
    (`src/hooks/useWallet.ts` and `src/lib/passkey.ts` there).
  - Does not run: installing into a stock pollywallet account. Its account wasm is not pinned and
    its verifier does not reproduce from our pinned inputs. pollywallet's UI cannot create the
    pinned account either, because it deploys its own wasm through its own relayer.

The record of a run is the `run.json` in its run directory (`runs/<timestamp>-<pid>/` unless
`OZPB_HARNESS_OUT` says otherwise). Every transaction hash in it can be looked up at
`https://stellar.expert/explorer/testnet/tx/<hash>` until the next testnet reset.
