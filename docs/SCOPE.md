# What this milestone deliberately does not do

Each entry below is scheduled rather than dropped, and says why it is not here yet. The
distinction matters: a reader deciding whether to depend on this tool should be able to tell
what was left out on purpose from what was overlooked.

Section numbers refer to `docs/architecture.md`.

The source-reviewed account method inventory and its limits are described in
[`ACCOUNT-METHOD-INVENTORY.md`](ACCOUNT-METHOD-INVENTORY.md).

1. **Live acquisition adapter** (`getLedgerEntries` → `AccountState` with `NextId`/`Count`
   reconciliation and transitive closure). The largest remaining gap to RFP #7. The pure
   core is implemented and tested over supplied `bounded_next_id` observations. It never
   says an account is safe, and its claim is scoped to the new rule's target, the account's
   management surface and the bound policies. It lists every live rule that can change the
   account or reset a bound policy, each with exactly who must sign, and refuses
   automatically when the new rule's own key could already do either alone, when another rule
   on the target gets around a stateful limit, when the new rule aims at the account or
   something it trusts, or when an in-scope rule has a shape this version does not support
   (any policy on an account-reaching rule, k-of-n, guarded recovery, contract signers,
   unrecognized external signers, classic multisig, a missing classic account). Whether the
   listed identities are the user's, or trusted by the user, is decided by the wallet that
   holds the owner key, which recomputes the result itself (Decision D7). Rules for other
   contracts are listed as not analysed. The bounded reader described below still needs live
   network verification before its observations can support that list.

   `source-rpc` can read bounded contract-instance Wasm hashes and caller-specified contract-data
   keys. It distinguishes live entries, returned archived entries, and omitted keys. A pure
   decoder understands the pinned account's rule, signer, policy, and instance-counter shapes,
   including the code hash carried by the same instance value as its counters.
   An internal consistency check can compare supplied rule slots, `Count`, and transitive
   reference counts; it does not authenticate those values, handle absent counters on a pristine
   account, or inspect reverse lookup keys.
   A bounded account scanner now derives pinned keys, reads every rule slot through `NextId`,
   follows the signer/policy closure, checks reference counts and `Count`, observes the code at
   every installed policy address and at each contract verifier named by an external signer,
   reads the classic account entry (master weight, thresholds, extra signers) of every `G…`
   signer in the closure and of each classic account the caller names, and re-reads the
   account instance; the classic reads count against the same signed batch budget. It retries
   a changed
   endpoint ledger or instance as a whole. Returned archived or undecodable entries, missing
   referenced entries, and a count mismatch fail closed as incomplete account state; exceeded
   scan bounds, including a fixed 24 MiB ceiling on the entry XDR one scan retains, fail closed
   as a budget error. Its output remains an
   endpoint-reported inspection: equal `latestLedger` values across calls are not an
   authenticated ledger-state proof, and an omitted rule key is treated as a removed hole
   only when the stored count reconciles. The scan does not identify the wallet's intended
   administrator or establish complete reviewed method evidence. The scanner hashes the ordered
   XDR keys and values, TTL metadata, and requested absences, including inspected policy and
   verifier instances and classic account entries (whose balances and sequence numbers move it
   on every payment: it is evidence, not the authority commitment). This digest identifies
   endpoint responses, not an authenticated ledger snapshot. Reading every classic signer in
   the closure, out-of-scope and expired rules included, keeps the read simple and archive-safe
   at the cost of batches: an account with many unrelated classic signers can exhaust the
   signed batch budget and fail closed.
   A structural adapter maps the completed scan into the pure authority model, requires
   observed code for every installed policy, and carries the classic account entries. Its
   output keeps the raw XDR/TTL digest separate from the decoded core-state digest: changing a
   TTL or an unmodeled instance field can change the former without changing the latter. The
   adapter decides nothing about authority.
   The signed version-2 development registry example binds the reviewed method-map digest and
   bounded scan protocol to the exact pinned account Wasm. Its public development signing key
   makes this a reproducible code-capability example, not production governance or live-state
   authority evidence. The operator reader below refuses that root unless its pinned network
   is testnet.
   An internal operator-configured reader now pins an RPC endpoint, network passphrase,
   governance roots, and a persisted registry checkpoint. It verifies a signed snapshot on
   each inspection, takes its scan bounds and reviewed method inventory from that snapshot,
   and compares the account and the selected policy bindings with code hashes observed by the
   bounded scanner. It judges nothing else: an unknown policy, an unrecognized verifier or a
   contract-address signer anywhere on the account is reported as observed, and the pure check
   refuses it where it can change the account, a bound policy or the target. Refusing one
   anywhere would refuse every check on an account that has one on an unrelated rule.
   Recognizing a binding (a reviewed registry entry, or a generated artifact rebuilt from its
   spec) is the toolkit's, from the binding set itself; the reader checks only that the
   address runs the expected code.
   The resulting projection is still `rpc_reported`: matching endpoint ledger metadata across
   calls and re-reading the instance do not authenticate a coherent ledger snapshot. A registry
   signature covers implementation capabilities, not live ledger state, and nothing a client
   sends can say who owns the account: owner matching stays with the key-holding wallet. The
   missing assurances are required before a public authority list.

   The toolkit has an internal install-intent draft that checks a spec, binding set, and
   supplied authority artifact for identity and structural consistency, then derives typed
   account arguments. It cannot authenticate the supplied authority list or its ledger reads,
   or establish freshness. It is not exported through the CLI or MCP server; it has to run the
   live check itself before it can be offered for wallet review.

2. **Containerized build, and the BuildManifest provenance fields that go with it** (§4.4,
   §6.3 — container image digest, source commit and dirty-tree status, template-pack hash,
   canonicalization version, build target). The builder is labelled `local-unattested`, which
   is what it is. Adding manifest fields rehashes every manifest, so the container and the
   fields land together at a release gate. The memory, disk and cgroup limits in §4.6 are part
   of that work and are **not** claimed today. §6.3 carries a scope note listing the fields the
   manifest holds against the ones it does not, so the gap is stated rather than left for a
   reader to find by diffing the document against the struct.

3. **A real reviewed policy wasm at layer 2** (F5d). The blocker is not a dependency bump:
   `stellar-accounts` 0.7.2 ships `src/policies/*.rs` as *library helpers*, and its
   `#[contract]` wrappers exist only under `src/*/test/` — so **OpenZeppelin publishes no
   policy wasm**. Pinning one means building a policy contract from their source and deciding
   what review status that artifact has. Related: `simple_threshold` and `weighted_threshold`
   appear in the documentation and never in code.

4. **Encoded-literal rendering** — template-pack v2, and one deliberate artifact-hash break.

5. **Complete generated-suite reason agreement.** The golden transfer fixture's generated suite
   (`contracts/differential/tests/generated_suite.rs`) now replays every constraint-derived case
   through the compiled policy and checks permit/deny. For the golden fixture's unambiguous
   function, argument, signer, target, expiry, missing-state, and exhausted-counter mutations,
   it also checks the exact denial reason against a hand-stated expectation, including the
   account's refusals for unknown signers and unvalidated context. Other generated cases remain
   verdict-only. The Soroswap fixture's generated mutations also run
   through a registered account (`contracts/differential/tests/swap_generated_suite.rs`), with
   permit/deny checks over its bounded amounts, exact route, recipient, and caller-chosen deadline;
   cap, floor, route, and recipient denials must return the policy's `NoTupleMatched` reason.
   Both suites mock management setup and delegated-signer authentication. They execute the
   account and policy logic, but do not test the delegate's digest-bound signature.
   The golden fixture also checks that direct `install`, `enforce`, and `uninstall` calls
   without account authorization fail without changing its installed state. This checks
   the generated policy's gate; it does not exercise a weaker alternate account rule.
   A separate Wasm gate (`scripts/test-pinned-account-authorization.sh`) builds the exact
   recognized account from pinned public source and a generated transfer policy with a fixed
   test signer. The account reproduces byte-for-byte only on an Apple Silicon build host
   ([rust-lang/cargo#8140](https://github.com/rust-lang/cargo/issues/8140)); elsewhere it differs
   only in function order and the gate fails, so the scheduled job runs on macOS arm64. It
   checks real delegated Ed25519 authorization through the account's complete
   `__check_auth` path and rejects a changed payload. Entries that name the requested digest but
   carry a signature over another digest, a flipped signature bit, or another key are refused
   by account authentication, not invocation matching. It also commits counts across ledger
   advances and checks N+1 denial and rollback. The test pins the generated policy's Wasm hash,
   so a change to code generation or its templates, the example spec, pinned build inputs, or
   the account authorization path must rerun the script before merge. The scheduled workflow
   also runs it in its own job and fails when a prerequisite or hash is unavailable, but that is
   a backstop after merge, not the review gate.
   The ordinary contracts suite explicitly ignores this test because it needs source-built Wasm.
   This account-path test covers one fixture and one account code hash. It does not establish
   general layer-2 coverage or live preflight.
   The hand-written `differential.rs` checks both verdict and reason for its own cases. Extending
   exact-reason checks to every generated case remains future work. A local two-rule account test
   demonstrates that overlapping counted grants have independent rule-ID counters and can exceed
   one installation's cap in aggregate. Its rule setup uses mocked management authorization; it
   does not establish a safe reconfiguration flow, disposable target execution, or live preflight.
   An internal reader can check a target instance against fetched Wasm bytes. A separate
   selected-key capture can acquire that instance, its matching code, and caller-specified
   target storage keys in one final `getLedgerEntries` response, rejecting missing, archived,
   or inconsistent entries. Its preliminary discovery reads carry separate endpoint-reported
   ledgers; the final response is endpoint-reported evidence, not a historical snapshot. The
   caller-selected keys do not establish all state an invocation can read. A narrow test runs
   a small target Wasm fixture through `Env::from_ledger_snapshot` with these captured entries
   and SDK test ledger defaults; a strict source rejects an uncaptured storage read. The RPC
   capture does not supply a full ledger header or network configuration. That earlier narrow
   test does not reconstruct the original call or authorize through the account and policy.
   It does not demonstrate a stateful mutation suite. It updates one already captured
   storage key, advances the disposable ledger, and observes the committed value in a fresh
   SDK environment. A separate footprint reader captures every key declared by one original
   Soroban envelope in one bounded `getLedgerEntries` reply, including dependency contract
   keys. It validates all captured Wasm instance-to-code links. Omitted keys are unavailable
   because the endpoint does not identify their absence or archive history. The declared
   footprint is the envelope's own claim; the network enforces it only when the transaction
   executes, and the reader does not compare it with any simulation. The original footprint
   does not prove which additional keys a candidate account, policy, or changed invocation
   could read.
   One exact-footprint fixture derives the original target call from its envelope XDR,
   captures its declared instance, code, and fixed storage key in one fixture RPC reply,
   executes that Wasm from a strict SDK snapshot, and observes a committed known-key write
   after a ledger advance. Missing declared state and a changed call's uncaptured key refuse.
   A second, source-built target fixture calls `require_auth` before writing its one fixed
   balance key. It combines target entries from one checked fixture RPC reply with a freshly
   constructed account and policy snapshot, and executes the captured transfer call with
   locally signed authorization through the pinned account Wasm and generated policy Wasm.
   Only four exact new nonce keys may begin absent, and the run must read each of them. The
   target fixture debits one balance key; it does not credit a recipient.
   A direct signed account check returns the policy's exact denial for an adjacent amount.
   The target call returns only the host's generic context error, which a missing or
   mismatched authorization entry would also produce; the policy's diagnostic error event
   attributes that refusal to the same denial. The target has sufficient balance in both
   cases. The permitted write and call count commit. The committed state differs from the
   combined captured and candidate state in exactly seven keys: the balance and call count
   change value only, the permitted call's two nonces are new, and three account entries
   read by its authorization path change TTL only. Any other committed data or TTL change,
   including a deletion, fails. These tests use
   deterministic fixture RPC data, synthetic candidate account/policy state, and SDK default
   ledger header/configuration apart from the reported sequence and network ID. They
   demonstrate only these fixed-key calls. They do not establish key closure or authorization
   for arbitrary target code, reconstruct actual network account state, or provide a public
   complete dry-run report.

6. **Complete four-layer dry run** (§4.5). `reference_suite` is deterministic layer-1
   evidence, while the fixture suites above provide partial account-path layer-2 evidence.
   `source-rpc::preflight_transaction` now makes a separate `simulateTransaction` request with
   `authMode=enforce` for one caller-supplied envelope, after refusing locally an envelope the
   endpoint would refuse before simulating, such as one with a memo. It records the endpoint's
   ledger and labels success, a failed simulation, or required archival restoration as
   state-dependent RPC evidence. A failed simulation covers an invocation or authorization
   failure and an error inside the endpoint's simulator alike, because the endpoint's text that
   would distinguish them is withheld; a refusal before the endpoint reads its ledger is an RPC
   error rather than an outcome. Restoration is reported whether the endpoint returns a separate
   restoration preamble or, as current stellar-rpc does for an invocation, restores archived
   entries inside the simulation and lists them in the simulated transaction data; neither is a
   success against the endpoint's current state. The endpoint simulates only the envelope's source
   account, its operation's host function, and its authorization entries. It does not evaluate
   signatures, the transaction fee, the sequence number, or time bounds and other
   preconditions, and for an invocation it ignores the envelope's own Soroban footprint and
   resource limits. The adapter therefore requires each declared footprint list to be exactly
   the simulated one and the declared disk-read and write bytes to cover the simulated use,
   which the endpoint reports unpadded, and reports a separate outcome naming each dimension
   that fails, without naming keys. The endpoint reports instructions and the resource fee
   only as padded estimates, so a declaration below either estimate is reported as advice
   beside the outcome and never changes it. A successful simulation says only that this
   invocation succeeded under the endpoint's state with the envelope's declared footprint and
   at least the simulated disk-read and write bytes: it does not establish that the declared
   instructions and fee suffice, that a particular installed policy was selected, that the
   same transaction will succeed at a later ledger, or that any writes committed. The caller
   must supply signed authorization entries in the envelope where the invocation needs them.
   The source adapter does not return raw RPC error details that could echo confidential
   envelope contents. General disposable execution against complete captured target and
   dependency state with a full ledger context, and a policy-bound live preflight remain
   scheduled.

   The CLI `preflight-transaction` command and the MCP `preflight_transaction` tool expose this
   observation for one exact envelope, with the failing dimensions in
   `insufficient_declared_resources` and the advice in `below_endpoint_estimate`, apart from
   the outcome. That does not make it a dry run: they identify no
   installed policy, run no mutation suite, and give no authority verdict. Signed authorization
   entries in the envelope stay live authorizations until their expiration ledger, so a hosted
   server refuses an envelope carrying signatures, while the CLI and a stdio server send it to
   the caller's chosen endpoint.
