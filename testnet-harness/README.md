# Testnet harness (Tranche 2)

Installs a generated policy into an OpenZeppelin smart account on Stellar testnet and shows the
account enforcing it. Signing is done the way a wallet would do it, with no wallet involved. Not
to be confused with `crates/harness`, the offline dry-run harness. This one talks to the live
network and spends testnet XLM.

```
bash testnet-harness/run.sh
```

One run, on fresh throwaway keys:

1. **setup** deploys the pinned OpenZeppelin account example from its wasm hash. It checks that
   the code hash the network reports is the pin in `ozpb_domain::pinned_upstream`, then funds
   the account.
2. **record** has the account's owner authorize a real 1 XLM transfer out of the account,
   through rule 0. `ozpb import` decodes the executed transaction into a recording.
3. **spec** fills in `native-sac-policy-spec.json` from that recording: exactly that transfer,
   `from = SELF`, granted to a different signer (the delegate), at most once.
4. **generate**: `ozpb generate` builds the policy crate and its wasm.
5. **install** deploys the wasm. It then calls `add_context_rule` on the account, with the owner
   signing. The policy's own `install` runs inside that call. The script reads back
   `is_installed` from the policy.
6. **permit/deny**: the delegate makes the account call the native SAC's `transfer`.
   - The exact recorded transfer is permitted once.
   - One stroop more is refused with the policy's `NoTupleMatched` (#6).
   - Another recipient is refused with #6.
   - The exact transfer a second time is refused with `CallCountExceeded` (#7).

Every address, transaction hash and outcome goes into `runs/<timestamp>-<pid>/run.json`, which
is gitignored. The run directory also holds the import bundle, the recording, the spec and the
generated crate.

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

## Keys

`setup.mjs` generates four keys with `Keypair.random()` and funds them from Friendbot:

- payer: pays fees
- owner: the account's administrator
- delegate: the grantee
- recipient

The seeds go to the file `OZPB_HARNESS_SECRETS` names. `run.sh` points it into a `mktemp -d`
directory and deletes that directory on exit. Seeds are never printed and never written to the
run directory. Only the payer, owner and delegate seeds are kept; the recipient's is dropped.

## How the account is signed for

The account's signers are `Delegated` Stellar accounts. For such a signer, `__check_auth` in
`stellar-accounts` 0.7.2 does two things:

- It binds the rule selection into the payload:
  `auth_digest = sha256(signature_payload ‖ xdr(context_rule_ids))`.
- It calls `signer.require_auth_for_args((auth_digest,))`.

A call from the account therefore carries two authorization entries:

- **The account's own entry.** Its signature is an `AuthPayload`. It names the signer with an
  empty proof and selects the rule.
- **The signer's entry.** It is rooted at `account.__check_auth(auth_digest)` and signed with the
  signer's ed25519 key.

`scripts/lib.mjs` builds both. `lib.test.mjs` checks the encodings against bytes written out from
the XDR definitions. It also verifies the signer's signature with node's own ed25519, not the
SDK's.

## Running the parts

```
cd testnet-harness/scripts && npm ci && npm test       # offline encoding tests
export OZPB_HARNESS_SECRETS=$(mktemp -d)/keys.json
node setup.mjs --run-dir R
node invoke.mjs --run-dir R --signer owner --rule 0 --amount 10000000 --to <recipient> \
    --expect permit --bundle R/import-bundle.json
ozpb import --bundle R/import-bundle.json > R/recording.json
node write-spec.mjs --run-dir R
ozpb generate --spec R/spec.json --rule 0 --out R/policy
node install.mjs --run-dir R --wasm R/policy/<name>.wasm
node invoke.mjs --run-dir R --amount 10000000 --to <recipient> --expect permit
```

`invoke.mjs --expect deny:<code>` passes only if both of these hold:

- the account's authentication failed;
- the policy contract itself raised that code.

The same number from another contract does not count. The native SAC's #6, for example, is
`AccountMissingError`.

## What a run does and does not show

**Shown**, on live testnet:

- The pinned account runs a generated policy as one of its context rules.
- A wallet-style signed `add_context_rule` installs it. Before a `Delegated` signer signs,
  `install.mjs` and `invoke.mjs` check that the authorization the RPC asks for is exactly the
  call they mean to make. The fee payer's own deploy, fund and upload transactions take the
  simulation's source-account authorization as returned.
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
- **The install skips the safety check.** It does not go through `prepare_install_intent` or the
  authority-surface check. Neither is exported for wallet use on this tree (`docs/SCOPE.md` §1).
  The harness installs only into the account it deployed a moment earlier, whose administrator
  it knows by construction. That is not evidence that installing into someone else's account is
  safe.
- **No wallet product signs.** The signer is a script holding an ed25519 key. A passkey wallet
  would need an `External` WebAuthn signer, and spec validation refuses External signers on this
  tree. [`browser/`](browser/README.md) drives the passkey side headless, but separately: nothing
  connects it to this install.

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
- **sign.** Runs, in two separate places that are not connected:
  - On chain, a script holding an ed25519 key signs as a `Delegated` signer. It first checks that
    the RPC asked for exactly the intended call.
  - Off chain, a headless passkey signs a challenge, and no contract verifies it
    (`browser/webauthn.mjs`).
- **install.**
  - Runs: `add_context_rule` on testnet, after which the policy enforces.
  - Does not run: the install-intent and authority-surface checks.
- **with a wallet.**
  - Runs: pollywallet's passkey wallet creation, driven headless (`browser/`).
  - Does not run: installing into a pollywallet account. Its account wasm is not pinned, and its
    signer is `External`.

The record of a run is the `run.json` in its run directory (`runs/<timestamp>-<pid>/` unless
`OZPB_HARNESS_OUT` says otherwise). Every transaction hash in it can be looked up at
`https://stellar.expert/explorer/testnet/tx/<hash>` until the next testnet reset.
