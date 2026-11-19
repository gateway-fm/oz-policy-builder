# Extending the toolkit

Three kinds of extension, each with the steps, the tests it must add and the gates it must pass.
The working detail is in the documents linked from each section; this page is the checklist.
Every change follows [CONTRIBUTING.md](../CONTRIBUTING.md) — DCO sign-off, the gates, documents
changed in the commit that changes the behaviour — and DEVELOPERS.md asks for the failing test
first.

## A new policy primitive or constraint kind

Follow [DEVELOPERS.md §3](DEVELOPERS.md#3-extending-the-toolkit-with-a-new-policy-primitive): the
crates to touch in order, test first, from `crates/policy-spec` to the differential suite, and the
[invariants CI enforces](DEVELOPERS.md#invariants-ci-enforces-dont-break-these), including the
mutation gate and how to run it locally. Two consequences worth stating on their own:

- **Code is not enough to reach users.** A template family's registry entry declares the
  constraint kinds and signer predicates it covers, and synthesis refuses a spec that uses anything
  else (`within_declared_capabilities` in `crates/toolkit`). A new kind is usable only after a
  signed registry successor whose template entry declares it
  ([registry governance](REGISTRY-GOVERNANCE.md#making-and-signing-a-version)).
- **Generated crates are regenerated, never edited**: the golden tests hold the committed crates
  to what codegen emits ([CONTRIBUTING.md](../CONTRIBUTING.md#what-the-gates-expect)).

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
an MCP tool and a CLI command (`ozpb check-policy-call-surface` and so on), except where marked:

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
