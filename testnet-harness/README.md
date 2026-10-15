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
cd testnet-harness/scripts && npm ci && npm test       # offline encoding tests
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
- **The install skips the safety check.** It does not go through `prepare_install_intent` or the
  authority-surface check. Neither is exported for wallet use on this tree (`docs/SCOPE.md` §1).
  The harness installs only into the account it deployed a moment earlier, whose administrator
  it knows by construction. That is not evidence that installing into someone else's account is
  safe.
- **No wallet product signs.** With the default owner, a script holding an ed25519 key signs.
  With `OZPB_HARNESS_OWNER=passkey`, the account has a passkey wallet's shape: rule 0 is one
  `External` WebAuthn signer. The passkey signs the recorded transfer and the install, and the
  verifier checks it on chain. But the passkey is Chrome's virtual authenticator over a key the
  harness holds, not a device. And the harness creates the account itself: pollywallet's page,
  relayer and deployer are not involved.
- **The PolicySpec still has no External signers.** The grant's signer is the delegate, an
  ed25519 `Delegated` signer, in both runs. Spec validation refuses External signers on this tree,
  so a passkey can own the account but cannot be the grantee.

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
  - Does not run: the install-intent and authority-surface checks.
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
