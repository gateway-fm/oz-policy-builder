# Atomic live-enforcement helper

The `live_enforcement` layer has to show the candidate policy deciding a real call, through the
pinned account, against current network state. Simulating installation does not show that, and
a policy cannot be exercised by a simulation before it is installed. The helper contract in
[`contracts/atomic-live-helper`](../contracts/atomic-live-helper/src/lib.rs) closes that gap:
one invocation installs the candidate rule through the account's own `add_context_rule` and then
makes one native-asset transfer under it. An enforce-mode simulation of that invocation runs the
generated policy on live state, and nothing is installed because nothing is submitted.

This package is the helper contract and its real-Wasm host tests only. **The `live_enforcement`
layer remains `unavailable`.** The helper is not deployed on any network, no live simulation has
been run with it, and the wallet-side preparation, consent and result validation it needs are
not built yet (see [Outstanding](#outstanding)).

## What the helper does

`install_and_transfer(candidate)` takes the account, the generated policy and its expected Wasm
hash, one delegate, the expected rule ID, the grant name and validity, a recipient and an
amount. In order, it:

1. refuses an amount outside `1..=1,000,001` stroops — the sample permit of 1,000,000 and its
   one-stroop adjacent denial case, so no authorization for this helper can name more;
2. derives the native asset contract of the executing network itself; there is no token or
   function argument;
3. refuses any two of helper, account, policy, delegate, recipient and asset sharing an address;
4. refuses a delegate that is not an existing classic account, an account not running the
   pinned `stellar-accounts` 0.7.2 Wasm, and a policy not running the expected candidate Wasm;
5. calls the account's `add_context_rule` with exactly one `CallContract(native asset)` rule,
   one `Delegated` signer and one policy, and refuses unless the account allocated the expected
   rule ID and returned exactly that rule (registry IDs are checked for count, not value);
6. calls the asset's `transfer(account, recipient, amount)`, and returns the installed rule only
   if the transfer succeeds.

It has no storage, constructor, administrator, upgrade path, relay or arbitrary call surface; its
only export is `install_and_transfer`. It cannot authorize anything: installation needs the
account owner's authorization of `add_context_rule` and the transfer needs the delegate's
authorization under the new rule, exactly as without the helper. A denial is never caught, so it
aborts the invocation and the installation with it.

Refusals are contract errors 1–7: `AmountOutOfScope`, `AliasedIdentity`, `UnsupportedDelegate`,
`UnrecognizedAccount`, `PolicyCodeMismatch`, `UnexpectedRuleId`, `InstalledRuleMismatch`. The
last cannot be reached with the pinned account, which returns the rule it was given; the check
stays so that the helper never relies on that.

The helper declares its own copies of the account's `Signer`, `ContextRuleType` and
`ContextRule` wire types so that its contract spec describes its return value. Their encoding is
checked against the [shared ABI vector](examples/native-runtime-abi.json) offline and against the
real account Wasm in the host tests.

## What the host tests establish

`bash scripts/test-atomic-live-helper.sh` generates the candidate policy, builds the helper from
source, checks its export set, and runs `execution-runtime/tests/atomic_helper.rs` on a
protocol-29 host with the pinned account Wasm, the generated policy Wasm, the reviewed helper
Wasm (its hash is asserted) and the real native asset contract. Every authorization is a real
Ed25519 signature over its address-bound (`AddressV2`) preimage, by distinct synthetic owner and
delegate keys; no authorization is mocked. These are automated keys, not wallet or human
approval. The tests require:

- the permitted 1,000,000-stroop transfer installs rule 1, moves exactly that amount, advances
  the policy's call counter, returns the rule the account now stores, and leaves the helper with
  no state;
- the adjacent 1,000,001-stroop transfer fails with the generated policy's `NoTupleMatched`
  (code 6) attributed to the policy contract, and every ledger entry — installation, balances,
  nonces, counters — is unchanged;
- a missing owner or delegate authorization, a delegate signing the installation, the owner
  signing the transfer, an altered signature preimage, an expired signature and an already
  expired grant are all refused with no state change;
- each reachable helper guard (errors 1–6) refuses with its own code and no state change,
  including an unexpected rule ID after a valid installation.

The tests are `#[ignore]`d in the ordinary `cargo test` run because they need freshly built Wasm.
The scheduled source-build job runs the script through
`scripts/test-pinned-account-authorization.sh`, on the aarch64-apple-darwin host the account pin
needs; the helper hash was recorded on the same host and toolchain.

## How live use is meant to work

Each live case is one atomic simulation from unchanged network state: the captured permit
(`target:original:0`), and separately the amount plus one stroop (`target:argument-denial:0`),
expected to fail with `NoTupleMatched`. This is two named cases, not the derived deny suite; it
cannot stand in for anything the reference, account-Wasm or captured-target layers must cover.

Preconditions, none of which this package performs: the helper and candidate policy are already
deployed and their code is read back and matched to reviewed hashes; the delegate is a funded
classic account whose signer settings are checked; the wallet shows the owner both exact calls,
the expiry and the replay warning and gets explicit consent before any signature exists. Only
`simulateTransaction` in enforce mode is used, never `sendTransaction`. A recording-mode
simulation only discovers the authorization shape and is never evidence. A passing result needs
the exact rule, counter and balance changes; a denial needs the policy-attributed error.

Signatures produced for these simulations are real. Anyone holding them can submit a matching
invocation until they expire. In particular the owner's `add_context_rule` authorization is an
independent subtree: it does not bind the helper call or the transfer, so it could install the
candidate rule on its own. The consent screen has to say so, and expiries have to be short.

## Outstanding

- Deploying the helper on testnet and recognizing it by the reviewed hash.
- The wallet-side preparation, consent, signing, enforce-mode simulation and result validation,
  with its interface agreed before implementation.
- A live run of both cases.
