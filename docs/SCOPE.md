# What this milestone deliberately does not do

Each entry below is scheduled rather than dropped, and says why it is not here yet. The
distinction matters: a reader deciding whether to depend on this tool should be able to tell
what was left out on purpose from what was overlooked.

Section numbers refer to `docs/architecture.md`.

The source-reviewed account method inventory and its limits are described in
[`ACCOUNT-METHOD-INVENTORY.md`](ACCOUNT-METHOD-INVENTORY.md).

1. **Live acquisition adapter** (`getLedgerEntries` → `AccountState` with `NextId`/`Count`
   reconciliation and transitive closure). The largest remaining gap to RFP #7:
   `prepare_install_intent` requires a `Safe` authority-surface verdict. The pure core is
   implemented and tested over supplied `bounded_next_id` observations, but it rejects
   policy-bearing administrative rules until signer enforcement can be proven. The bounded
   reader described below still needs live network verification before its observations
   can support an authority verdict.

   `source-rpc` can read bounded contract-instance Wasm hashes and caller-specified contract-data
   keys. It distinguishes live entries, returned archived entries, and omitted keys. A pure
   decoder understands the pinned account's rule, signer, policy, and instance-counter shapes,
   including the code hash carried by the same instance value as its counters.
   An internal consistency check can compare supplied rule slots, `Count`, and transitive
   reference counts; it does not authenticate those values, handle absent counters on a pristine
   account, or inspect reverse lookup keys.
   A bounded account scanner now derives pinned keys, reads every rule slot through `NextId`,
   follows the signer/policy closure, checks reference counts and `Count`, observes the code at
   every installed policy address, and re-reads the account instance. It retries a changed
   endpoint ledger or instance as a whole. Returned archived entries, missing referenced
   entries, a count mismatch, and exceeded scan bounds fail closed. Its output remains an
   endpoint-reported inspection: equal `latestLedger` values across calls are not an
   authenticated ledger-state proof, and an omitted rule key is treated as a removed hole
   only when the stored count reconciles. The scan does not identify the wallet's intended
   administrator or establish complete reviewed method evidence. The scanner hashes the ordered
   XDR keys and values, TTL metadata, and requested absences, including inspected policy
   instances. This digest identifies endpoint responses, not an authenticated ledger snapshot.
   A structural adapter maps the completed scan into the pure authority model, requires
   observed code for every installed policy, and lists eligible policy-free management rules
   with observed fingerprints. Its output keeps the raw XDR/TTL digest separate from the
   decoded core-state digest: changing a TTL or an unmodeled instance field can change the
   former without changing the latter. These are candidates; the adapter does not choose
   an administrator or turn endpoint data into a trusted verdict.
   This tree has no operator-pinned authenticated source for a live account snapshot and no
   wallet-authenticated binding to the intended administrator. A registry signature covers
   implementation capabilities, not live ledger state; a client-provided fingerprint cannot
   establish wallet intent. Those trust anchors are required before a public authority verdict.

   The toolkit has an internal install-intent draft that checks a spec, binding set, and
   supplied authority artifact for identity and structural consistency, then derives typed
   account arguments. It cannot authenticate the supplied `Safe` claim, prove a complete
   exported-method inventory or transitive ledger reads, or establish freshness. It is not
   exported through the CLI or MCP server; a trusted reader and complete method-level evidence
   are required before that operation can be offered for wallet review.

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
   test signer. It checks real delegated Ed25519 authorization through the account's complete
   `__check_auth` path, rejects a changed payload, commits counts across ledger advances, and
   checks N+1 denial and rollback. Run the script before merging changes to this path; the
   scheduled toolchain job also runs it and fails when a prerequisite or hash is unavailable.
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
   because the endpoint does not identify their absence or archive history. The original
   footprint does not prove which additional keys a candidate account, policy, or changed
   invocation could read.
   One exact-footprint fixture derives the original target call from its envelope XDR,
   captures its declared instance, code, and fixed storage key in one fixture RPC reply,
   executes that Wasm from a strict SDK snapshot, and observes a committed known-key write
   after a ledger advance. Missing declared state and a changed call's uncaptured key refuse.
   A second, source-built target fixture calls `require_auth` before writing its one fixed
   balance key. It combines target entries from one checked fixture RPC reply with a freshly
   constructed account and policy snapshot, uses exact new nonce-key allowances, and executes
   the captured transfer call with locally signed authorization through the pinned account
   Wasm and generated policy Wasm. The target fixture debits one balance key; it does not
   credit a recipient.
   A direct signed account check returns the policy's exact denial for an adjacent amount,
   while the target call refuses it with a host context error; the target has sufficient
   balance in both cases. The permitted write and call count commit. These tests use
   deterministic fixture RPC data, synthetic candidate account/policy state, and SDK default
   ledger header/configuration apart from the reported sequence and network ID. They
   demonstrate only these fixed-key calls. They do not establish key closure or authorization
   for arbitrary target code, reconstruct actual network account state, or provide a public
   complete dry-run report.

6. **Complete four-layer dry run** (§4.5). `reference_suite` is deterministic layer-1
   evidence, while the fixture suites above provide partial account-path layer-2 evidence.
   `source-rpc::preflight_transaction` now makes a separate `simulateTransaction` request with
   `authMode=enforce` for one caller-supplied envelope. It records the endpoint's ledger and
   labels success, execution failure, or required archival restoration as state-dependent RPC
   evidence. A successful simulation says only that this exact envelope simulated under the
   endpoint's state: it does not prove that a particular installed policy was selected, that
   the same transaction will succeed at a later ledger, or that any writes committed. The
   caller must supply signed authorization entries in the envelope where the invocation needs
   them. The source adapter does not return raw RPC error details that could echo confidential
   envelope contents. General disposable execution against complete captured target and
   dependency state with a full ledger context, and a policy-bound live preflight remain
   scheduled.
