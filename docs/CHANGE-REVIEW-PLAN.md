# Change review plan

Use this plan for changes to policy evidence, verification, account authority, and
installation. Record the result in each PR description. A green test run is one part of the
review; the reviewer must also check that each claim follows from evidence the code actually
has.

## Sources and invariants

- `docs/architecture.md` §§4.5, 4.8, 4.10, 4.11, 6.1, and 6.3 define evidence layers,
  account authority, recognition, crate boundaries, minimum permission, and verification.
- `docs/ECOSYSTEM-CONFORMANCE.md` records platform choices and known qualifications;
  `docs/CANONICAL-HASHING.md` defines artifact identity.
- `docs/SCOPE.md` separates delivered behavior from scheduled behavior. Review it whenever a
  change makes an operation available or changes what a report can establish.
- `crates/api-types` is the wire contract. Core crates stay synchronous and free of network
  and transport dependencies. CLI and MCP shells share toolkit behavior and error codes.

The recurring checks are: exact permissions unless a user explicitly widens them; refusal
on unknown or incomplete security state; recognition by observed code as well as address;
trust labels earned by acquisition, never accepted from a request; deterministic artifacts;
and evidence that says exactly which layers ran. The toolkit prepares artifacts and intents;
the user and wallet decide whether to sign and submit.

## Before writing code

1. Name the operation and the smallest reviewable PR. List its trusted inputs, untrusted
   request fields, output fields, side effects, and required evidence. Mark any required
   evidence that the current tree cannot acquire. If an output cannot be populated honestly,
   change the design or keep the operation internal until its prerequisite exists.
2. Trace each security claim through the wire type, toolkit, core, registry, and shell. Ask
   whether a caller can supply the answer to a question that only a trusted reader should
   answer. Ask whether an address can change code, a rule can be archived or restored, or a
   second rule can reach the same protected method.
3. Criticize the proposed PR boundary: can it compile and pass `cargo test --workspace` on
   its own? Does it expose a partial feature as complete? Would stacking make the review
   simpler, and can independent changes be reviewed against the same base?

## Review passes for every PR

| Pass | Inspect | Required evidence |
| --- | --- | --- |
| Contract and scope | API types, implementation, docs, names, and release claims | Every output is supported by the inputs and actual execution; missing layers and future work are explicit. Modules are named by purpose. |
| Trust boundary | Request parsing, registry roots, snapshots, code hashes, ledger anchors, error mapping | Untrusted values cannot declare recognition, acquisition trust, admin status, or a safe verdict. Unknown, stale, malformed, or incomplete state fails closed. |
| Authorization | Original permit, mutation denials, signer semantics, rule selection, policy composition | Tests cover a valid control and adversarial changes; the expected result is derived independently of the implementation under test. |
| Artifact identity | Canonical hashes, file sets, manifests, ordering, and optional claims | Reproduction checks exact bytes and complete sets; absence, malformed input, and mismatch have distinct results. |
| Shell behavior | CLI and MCP schema, error codes, operator configuration, network access | Shells do not contain policy logic. Trust roots and build programs stay operator-controlled. HTTP mode accepts only operator-allowlisted RPC endpoints; CLI and stdio mode accept caller-selected endpoints. |
| Maintenance | Diff, dependencies, docs, examples, release gates | No unrelated changes, private material, stale claims, unexplained dependency, or missing DCO signoff. |

Read the complete diff once for behavior and a second time for claims and omissions. For
each found defect, add a test only when it distinguishes a real failure from a passing
control. Re-run the affected crate tests after the fix, then the workspace gate. Review the
final committed diff and PR text after all fixes; a review of an earlier revision does not
approve a later one.

## Checks for the next operations

**Dry-run and harness.** A layer-1 reference report is labeled layer 1. The full dry-run
requires contract integration through the account, a disposable execution environment,
and state-dependent live preflight, each with its own evidence and failure status (§4.5).
Do not infer contract or live behavior from evaluator agreement. Check that deny cases are
actually denials, including cross-products of accepted tuples and dynamic signer predicates.
The golden generated-contract comparison in `contracts/differential/tests/generated_suite.rs`
is partial layer-2 evidence: it runs one fixture's generated mutations against the compiled
policy through the smart-account authorization helper, but does not cover the full layer-2
contract integration and stateful behavior in §4.5. Label it as partial layer 2 in harness
claims and reports; never present it as complete layer-2 evidence.
Reports state what was committed, mocked, captured, or observed live.

**Authority-surface check.** The trusted reader acquires one coherent ledger snapshot,
binds the observed account and network to the request, reconciles the active count and
complete rule/transitive closure, and checks observed code hashes against verified registry
entries. It derives the designated administrator rather than accepting one from the client.
Examine both direct policy calls and account-management
calls, including every exported security-relevant method. Missing method inventory,
unrecognized code, mixed ledgers, archive uncertainty, or exceeded scan bounds cannot yield
a public `Safe` verdict. A pure core result is not a complete live wire verdict (§4.8).

**Install intent.** Require an exact spec/binding match and a complete `Safe` authority
verdict for the same account, network, code, bindings, and observation. Reject stale or
internally inconsistent artifacts. The result is an intent for wallet review, not an
authorization to sign or submit. A fresh surface check is required immediately before
signing; a time window is retry policy, not a safety guarantee (§4.8).

**CLI and MCP exposure.** Exercise the same successful and refused requests through both
shells. Check schema discovery, malformed JSON, stable `E_*` errors, stdout/stdio framing,
and that a network-read tool really obtains the evidence its response promises. Do not add
a command merely because a corresponding request type exists.

## Gates and PR record

For Rust changes run `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
Run the `contracts` differential tests, Clippy, and formatting when that workspace changes
**or** when host-side dependencies of its generated/differential tests change, including
`harness`, `evaluator`, `policy-spec`, and `codegen`. Run `bash scripts/check-dep-rules.sh`
for crate-edge changes and the relevant part of `scripts/verify-phase1.sh` for changed
first-milestone guarantees.
If a local gate cannot run, record the exact reason and use CI evidence before merge.

Each PR description should record: intended behavior; trusted and untrusted inputs; what
was exercised; unavailable evidence; security and compatibility risks; test commands and
results; and a short final-diff review. Link a relevant spec section rather than treating
the checklist as a replacement for the specification. Ensure every commit has a DCO
`Signed-off-by` trailer.
