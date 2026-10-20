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
   one-stroop adjacent denial case. This bounds only the transfer the helper executes, not what
   any signature authorizes (see [Signatures](#signatures-are-real-and-usable-without-the-helper));
2. derives the native asset contract of the executing network itself; there is no token or
   function argument;
3. refuses any two of helper, account, policy, delegate, recipient and asset sharing an address;
4. refuses a delegate that is not an existing classic account, an account not running the
   pinned `stellar-accounts` 0.7.2 Wasm, and a policy not running the expected candidate Wasm;
   the candidate must be a generated policy with a call cap (see step 6);
5. calls the account's `add_context_rule` with exactly one `CallContract(native asset)` rule,
   one `Delegated` signer and one policy, and refuses unless the account allocated the expected
   rule ID and returned exactly that rule (registry IDs are checked for count, not value);
6. reads the candidate policy's remaining call count for the installed rule, calls the asset's
   `transfer(account, recipient, amount)`, reads the count again, and returns the installed rule
   only if the transfer succeeded **and** the count dropped by exactly one.

Step 6 is what ties success to the candidate. The transfer's own authorization names the rule
it is checked against, and the owner's Default rule needs no policy: an owner-signed transfer
under rule 0 moves even the adjacent 1,000,001 stroops without the candidate policy ever running.
That was reproduced against the previous helper, which then succeeded with the policy's counter
untouched; the host test `atomic_helper_refuses_a_transfer_not_authorized_by_the_candidate_rule`
now requires the refusal. The generated policy's `enforce` requires
the account's own authorization and counts only while the account checks a call under the rule
the policy is installed on, so a drop of exactly one in this invocation can only come from the
candidate rule checking this transfer. A generated policy without a cap exports no counter;
the helper then cannot observe its execution and refuses rather than report success.

It has no storage, constructor, administrator, upgrade path, relay or arbitrary call surface; its
only export is `install_and_transfer`. It cannot authorize anything: installation needs the
account owner's authorization of `add_context_rule` and the transfer needs the delegate's
authorization under the new rule, exactly as without the helper. A denial is never caught, so it
aborts the invocation and the installation with it.

Refusals are contract errors 7001–7009: `AmountOutOfScope`, `AliasedIdentity`,
`UnsupportedDelegate`, `UnrecognizedAccount`, `PolicyCodeMismatch`, `UnexpectedRuleId`,
`InstalledRuleMismatch`, `UnobservablePolicy` (no readable counter) and
`CandidateRuleNotExercised` (the counter did not drop by exactly one). `InstalledRuleMismatch`
cannot be reached with the pinned account, which returns the rule it was given; the check stays
so that the helper never relies on that. The range keeps
clear of the asset contract's and the policies' small codes. An error a called contract raises
directly keeps its code — an already expired grant surfaces as the account's `PastValidUntil`
(3005) from `add_context_rule`, a failing transfer as the asset's own error. Any recoverable
failure inside an account's `__check_auth`, a policy denial included, is converted by the host
into `Error(Auth, InvalidAction)`. The helper calls the account and asset without `try_call`, so
that error propagates as is: a transaction or simulation invoking the helper fails with
`Error(Auth, InvalidAction)`. Only a caller using `try_call` — as the host tests do — sees it
narrowed to `Error(Context, InvalidAction)`. A refusal is therefore attributed by the contract ID
of its diagnostic `error` events, never by its code alone.

The helper declares its own copies of the account's `Signer`, `ContextRuleType` and
`ContextRule` wire types so that its contract spec describes its return value. Their encoding is
checked against the [shared ABI vector](examples/native-runtime-abi.json) by
`cargo test -p ozpb-atomic-live-helper` in the CI contracts job, and against the real account
Wasm in the host tests.

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
- the adjacent 1,000,001-stroop transfer fails (as `Error(Context, InvalidAction)` at the tests'
  `try_call`), carries the generated policy's `NoTupleMatched` (code 6) as a diagnostic error
  attributed to the policy contract, and leaves every ledger entry — installation, balances,
  nonces, counters — unchanged;
- a missing owner or delegate authorization, a delegate signing the installation, the owner
  signing the transfer, an altered signature preimage and an expired signature are refused with
  no state change and the same error a policy denial returns. What distinguishes them from a
  denial is that the policy raises no error. Where the cause is specific it is also asserted:
  the delegate signing the installation raises the account's `UnvalidatedContext` (3002), the
  owner signing the transfer its `UnauthorizedSigner` (3016), and the expired signature the
  signer's `Error(Auth, InvalidInput)` ("signature has expired"), all attributed to the account.
  For the missing and altered entries only the host's generic `Error(Auth, InvalidAction)` is
  available, which a policy denial also emits. An already expired grant returns the account's
  `PastValidUntil` (3005), attributed to the account;
- each reachable helper guard (errors 7001–7006) refuses with its own code and no state change,
  including an unexpected rule ID after a valid installation;
- a transfer authorized by the owner under the Default rule 0 instead of the candidate rule is
  refused with `CandidateRuleNotExercised` and no state change, for both the permit and the
  adjacent amount, and the policy raises no error;
- a candidate policy generated without a call cap is refused with `UnobservablePolicy`.

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
simulation only discovers the authorization shape and is never evidence.

Helper success is evidence only together with what the orchestrator checks itself: the
simulation's ledger changes must include the installed rule, the candidate policy's counter
write for that rule and account, and exactly the expected balance changes; and the transfer's
authorization must be the delegate's, selecting the candidate rule. A denial needs the
`NoTupleMatched` error attributed to the candidate policy; a helper refusal such as
`CandidateRuleNotExercised` is not a policy denial and settles nothing about the policy. The
owner must never be asked to sign the transfer: an owner-signed transfer under rule 0 is a real
transfer that no policy checks, should the signatures ever be submitted.

## Signatures are real and usable without the helper

None of the four authorization entries a case needs names the helper. The owner's account entry
is rooted at the account's `add_context_rule` and its signer entry at the account's
`__check_auth`; the delegate's account entry is rooted at the asset's `transfer` and its signer
entry likewise at `__check_auth`. Each is valid on its own, so the set signed for the permit case
is a real, submittable installation of the candidate rule followed by a real 1,000,000-stroop
transfer. The host test `permit_case_authorizations_install_and_transfer_without_the_helper`
submits the first two entries to `add_context_rule` and the other two to the asset's `transfer`
directly, and both succeed. Simulating the set as a helper invocation does not change what was
signed.

The entries cannot be bound to the helper with the pinned account. A single helper-rooted
account authorization would be checked by the account once, at installation, before the rule it
needs for the transfer exists; and the host does not start a second, independent root for the
same address while a helper-rooted one is active.

So the helper's amount bound and identity checks constrain only what the helper executes. The
wallet must enforce the amount, recipient and a short expiry before it signs, and treat consent
to a live case as consent to that installation and that transfer actually happening, for as long
as the signatures are valid. The consent screen has to say so.

## Outstanding

- Deploying the helper on testnet and recognizing it by the reviewed hash.
- The wallet-side preparation, consent, signing, enforce-mode simulation and result validation,
  with its interface agreed before implementation.
- A live run of both cases.
