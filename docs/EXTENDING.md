# Extending the toolkit

Three kinds of extension, each with the steps, the tests it must add and the gates it must pass.
The working detail is in the documents linked from each section; this page is the checklist.
Every change follows [CONTRIBUTING.md](../CONTRIBUTING.md): a failing test first, DCO sign-off,
and documents changed in the same commit as the behaviour they describe.

## A new policy primitive or constraint kind

The full path is [DEVELOPERS.md §3](DEVELOPERS.md#3-extending-the-toolkit-with-a-new-policy-primitive).
In order, test first at each step:

1. **`crates/policy-spec`** — add the `Constraint` variant; update `is_widening()` if it relaxes a
   call, add validation for any provenance rule, and add it to a fixture.
2. **`crates/evaluator`** — its arm in `constraint_satisfied`. This is the executable meaning of the
   constraint, and it must not share code with codegen.
3. **`crates/codegen`** — emit the check in `emit_lib`, embedding values only as validated
   literals, with pre-emission validation; regenerate both committed crates with the two
   `UPDATE_GOLDEN=1` commands in DEVELOPERS.md, never by hand.
4. **`crates/harness`** — mutation cases in `build_suite` so the derived deny suite covers the new
   boundary, and its `concrete_for` arm.
5. **`crates/synthesizer`** — how it enters a spec: exact by default, or through an explicit
   `Widening` or an adapter. Never heuristically.
6. **`contracts/differential`** — explicit evaluator-versus-contract cases, so the generated Wasm
   and the evaluator are shown to agree on it.

A new template family or a newly recognized prebuilt policy also needs a capability entry in
`crates/registry`, keyed by the reviewed Wasm hash, and a signed registry successor before any
consumer recognizes it ([registry governance](REGISTRY-GOVERNANCE.md#making-and-signing-a-version)).

**Gates** ([invariants CI enforces](DEVELOPERS.md#invariants-ci-enforces-dont-break-these)):

- `scripts/check-dep-rules.sh` — the evaluator and harness never depend on codegen.
- `scripts/check-codegen-fixtures.sh` — byte determinism, and the committed crates matching what
  codegen emits.
- Every generated crate builds standalone and passes the same `rustfmt` and `clippy -D warnings` as
  handwritten code.
- **The mutation gate** (`scripts/mutation-test.sh`, `.github/workflows/mutation.yml`): a pull
  request touching one of the eight pure cores fails if a mutant on a changed line survives that
  crate's own tests or times out. Run it locally with
  `bash scripts/mutation-test.sh --in-diff origin/main` after
  `cargo install cargo-mutants --locked --version 27.1.0`. Answer a survivor with a test; exclude
  one in `.cargo/mutants.toml` only when no input can observe it, with the reason.
- `bash scripts/verify-phase1.sh --offline` locally, the full gate before release
  ([CONTRIBUTING.md](../CONTRIBUTING.md#what-the-gates-expect)).

## A new target adapter

An adapter declares the safe direction of each argument of one function of one target contract,
and applies only to the exact code hash a signed registry binds it to. It is the only path besides
a user decision by which a bound enters a spec. Read [TARGET-ADAPTERS.md](TARGET-ADAPTERS.md)
first; `soroswap-router@2` is the worked example.

1. **Declare the semantics** in `crates/domain/src/target_adapters.rs`: an `AdapterSemantics` with a
   versioned name (`<target>@1`), and for each function its exact argument types and roles
   (`MaxInput`, `MinOutput`, `CallerChosen`, `ExactOnly`); list it in `implemented()`. Never change
   a published version's meaning: a new interpretation is a new version, as `@2` was for the
   Soroswap deadline.
2. **A new role or argument type** also needs its mapping in `crates/synthesizer/src/adapters.rs`:
   `ArgRole::widening` decides the bound a role permits and `Adapter::matches_call` the type check.
   A role never derives a direction from the XDR type, and a floor needs a trusted quote, so
   `MinOutput` derives nothing.
3. **Review the target** from source and try to reproduce its deployed Wasm hash. If it does not
   reproduce, the binding must say so, as the Soroswap one does.
4. **Bind it**: a registry successor whose `target_adapters` entry maps the target's exact Wasm hash
   to `implementation`, `semantics_digest` (from `.digest()` of the semantics) and
   `review_reference`, signed by the custodians
   ([registry governance](REGISTRY-GOVERNANCE.md#making-and-signing-a-version)). An adapter cannot
   share a hash with an account, policy or verifier. It is withdrawn by revoking
   `target_adapter/<hash>`.
5. **Tests**: resolution and aliasing in `crates/registry/src/target_adapter_tests.rs`; that a
   binding routes semantics, that an absent or different binding stays exact and that a user
   widening keeps its own provenance in `crates/toolkit/src/target_adapter_tests.rs`; role and
   signature matching in the synthesizer; and, for a walkthrough-grade adapter, a harness run with
   live derived denials ([W3](WALKTHROUGH-PROTOCOLS.md#w3-soroswap)).

Adapter-derived constraints record the adapter and target hash, and the rule refuses drift; the
generated policy does not check target code on-chain, so a wallet or live checker must compare the
current code before relying on them.

## A new wallet integration

The toolkit's wallet-facing surface is small and advisory; the wallet does the deciding
([architecture §4.8](architecture.md#48-wallet-integration-wallet), Decision D7). Each operation is
an MCP tool and a CLI command (`ozpb check-policy-call-surface` and so on):

| Operation | Gives the wallet |
| --- | --- |
| `check_policy_call_surface` | Who can change the account or reset the bound policies, with refusals, unresolved items and an `authority_commitment`; never "safe" |
| `prepare_install_intent` | The exact `add_context_rule` arguments, only when nothing is refused or unresolved |
| `assemble_install_transaction` | An unsigned install (or restoration) transaction with current sequence and fees, valid for at most 120 ledgers ([INSTALL-ASSEMBLY.md](INSTALL-ASSEMBLY.md)) |
| `check_against_policy` | A permit, deny or `unsupported` prediction for one call against an installed rule ([LIVE-POLICY-CHECK.md](LIVE-POLICY-CHECK.md)) |
| `ozpb check-installed-grant` (CLI only) | A monitoring observation of one installed grant against its installation commitment |

What the wallet must do itself, every time: decode and validate every field of the unsigned
transaction against its own RPC; recompute the authority check and match each listed identity to
the user's own keys or trusted identities; regenerate any agent proposal from the transaction hash
rather than trust it ([`wallet-proposal.md`](../skills/policy-builder/references/wallet-proposal.md));
build the owner authorization itself; enforce-simulate; show the user what they sign; and verify
the installation from the account's events and a readback. It must support the recognized
account's signing protocol (the 0.7.3 example; a 0.8 account is not recognized,
[SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md)).

The worked example is the [Pollywallet integration](POLLYWALLET-INTEGRATION.md): its independent
validators are `wallet/shared` (assembly, approval, revocation, replacement, live-enforcement), its
backend `wallet/server`, and its agent handoff [AGENT-WALLET-HANDOFF.md](AGENT-WALLET-HANDOFF.md).
Its tests in `wallet/tests` are a checklist of what a second integration has to refuse.
