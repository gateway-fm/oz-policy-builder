# What this milestone deliberately does not do

Each entry below is scheduled rather than dropped, and says why it is not here yet. The
distinction matters: a reader deciding whether to depend on this tool should be able to tell
what was left out on purpose from what was overlooked.

Section numbers refer to `docs/architecture.md`.

1. **Live acquisition adapter** (`getLedgerEntries` → `AccountState` with `NextId`/`Count`
   reconciliation and transitive closure). The largest remaining gap to RFP #7:
   `prepare_install_intent` requires a `Safe` authority-surface verdict. The pure core is
   implemented and tested over supplied `bounded_next_id` observations, but it rejects
   policy-bearing administrative rules until signer enforcement can be proven. The full live
   rule-state reader requires live network verification and remains scheduled.

   `source-rpc` can read bounded contract-instance Wasm hashes and caller-specified contract-data
   keys. It distinguishes returned entries with usable TTL metadata from omitted keys, and a pure
   decoder understands the pinned account's rule, signer, policy, and instance-counter shapes.
   An internal consistency check can compare supplied rule slots, `Count`, and transitive
   reference counts; it does not authenticate those values, handle absent counters on a pristine
   account, or inspect reverse lookup keys.
   The RPC's reported ledger sequence is endpoint metadata, not proof of a coherent account-state
   snapshot. These pieces do not derive the complete rule set, resolve archive uncertainty, or
   identify the administrator. Live endpoint behavior needs separate verification.

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

5. **Generated-suite verdict agreement.** The golden transfer fixture's generated suite
   (`contracts/differential/tests/generated_suite.rs`) now replays every constraint-derived case
   through the compiled policy and checks permit/deny. It does not compare exact denial reasons.
   The hand-written `differential.rs` checks both verdict and reason for fewer cases. Extending
   that reason check to every generated case remains future work.
