# Security audit scope

> **Draft for scoping.** The audited revision is fixed by a freeze commit named here when the
> audit starts. Until then this document describes the tree it is committed in, and its line
> counts move with that tree.

The entry point for an external security audit of the OZ Accounts Policy Builder: what is in
scope and why, where the claims and their limits are already written down, and how to run every
gate. It links rather than restates. Where it disagrees with a linked document, the linked
document is the one kept against the code.

## What the system does

A user or an agent points at a Stellar transaction already performed — fetched from RPC by hash,
simulated, or imported as raw XDR — and the toolkit turns it into a minimum-permission grant on an
OpenZeppelin smart account: a context rule plus a generated Soroban policy contract implementing
OpenZeppelin's `Policy` trait, which permits exactly the recorded calls (or explicit,
provenance-tagged widenings of them) for exactly the declared signers, call count and expiry. A
deterministic pipeline (recorder → PolicySpec → synthesizer → codegen) emits Rust source, a
reproducible Wasm and a BuildManifest. An independent reference evaluator, a constraint-derived
permit/deny suite and execution through the pinned account Wasm check the artifact. Before
installation a live authority check reads the account and refuses when the agent could already
change the account or reset the grant through another rule. The toolkit never signs, deploys or
installs: it prepares unsigned XDR, and the wallet re-validates it against its own RPC and has the
owner sign the installation with a passkey. Agents reach it through an MCP server and a Claude
skill, people through a CLI and the Pollywallet integration. In this tree the wallet backend and
the testnet harness are bound to testnet.

## Trust boundaries and what is claimed

Read before scoping findings:

- [architecture §6](architecture.md#6-trust-security-and-privacy-model): §6.1 separates the
  claimed *authorization-minimal* guarantee from the adapter-gated *effect-minimal* one; §6.2 is
  the custody and signing boundary; §6.5 covers the confidentiality of unsigned and simulated
  transactions.
- [architecture §6.4](architecture.md#64-audit-scope-committed), the committed audit scope.
  This document is its working form.
- [architecture §10, "Acceptance gates before any mainnet use"](architecture.md#10-delivery-plan):
  the properties a mainnet release is held to.
- [SECURITY.md](../SECURITY.md#what-this-milestone-does-and-does-not-claim): what is
  deliberately not claimed.
- [SCOPE.md](SCOPE.md#implementation-boundaries): what is implemented, and the limits each part
  keeps.

| Boundary | Trusted side | Untrusted side | What crosses it |
| --- | --- | --- | --- |
| Recording | Pinned decoder, verified network passphrase | RPC responses, imported bundles, JSON over MCP | Evidence labelled by how it was acquired; serialized input is downgraded to `self_supplied` |
| Registry | Operator-configured governance roots and checkpoint | Signed snapshots, from the operator or the request | Capabilities keyed by exact Wasm hash; anything unknown is refused |
| Code generation | The template snippets in `crates/codegen` | Every recorded value | Render-safe literals only |
| Account state | The pure call-surface core | The RPC endpoint's view of the account | An `rpc_reported` observation at one ledger, not a proof |
| Signing | The wallet and the owner's passkey | MCP server, agent, hosted endpoint | Unsigned XDR only |

## Components in scope

Counted on 19 November 2026 from the tree that carries this table. *Non-test* is every non-blank
line of tracked `.rs` and `.mjs` files that is not a `//` comment (nor a `/*` or `*` comment line
in JavaScript) and is not test code. *Test* is the same measure over `tests/` directories,
`#[cfg(test)]` modules, files named `test.rs`, `tests.rs`, `*_tests.rs` or `test_support.rs`, and
`*.test.mjs`. Declaration files (`.d.mts`), TypeScript, JSON fixtures and Markdown are not counted.
To recount, define this function at the repository root and pass it the paths in a row:

```sh
loc() {
  git ls-files -- "$@" | grep -E '\.(rs|mjs)$' | xargs awk '
    FNR == 1 { whole = FILENAME ~ /(^|\/)tests\/|(^|\/)(test|tests|test_support|[a-z_]+_tests)\.rs$|\.test\.mjs$/
               js = FILENAME ~ /\.mjs$/; block = 0; attr = 0 }
    { t = whole
      if (!js) {
        if (block) { t = 1; if ($0 ~ /^}/) block = 0 }
        else if ($0 ~ /^#\[cfg\(test\)\]/) { t = 1; attr = 1 }
        else if (attr) { t = 1
          if ($0 ~ /^(pub(\(crate\))? )?mod [A-Za-z0-9_]+ \{/) { block = 1; attr = 0 }
          else if ($0 !~ /^#\[/) attr = 0 } }
      l = $0; sub(/^[ \t]+/, "", l)
      if (l == "" || l ~ /^\/\// || (js && l ~ /^(\/\*|\*)/)) next
      if (t) test++; else code++ }
    END { printf "%d non-test, %d test\n", code, test }'
}
loc crates/codegen    # 1602 non-test, 2032 test
```

The OpenZeppelin rows were counted with the same function in a checkout of
`OpenZeppelin/stellar-contracts` at tag v0.7.2. The account wrapper's Rust source is the same at
v0.7.3, which changes only the library's `smart_account/{mod,storage}.rs`, tests, documentation
and package versions
([SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc)). The Python
launcher row counts lines that are neither blank nor `#` comments.

### Tier 1 — on-chain code and security roots

| Component | Path | Why it is here | Non-test | Test |
| --- | --- | --- | ---: | ---: |
| Code generator | `crates/codegen` (`src/lib.rs`, `src/render.rs`) | The only source of generated statements ([architecture §5](architecture.md#5-why-generated-policies-stay-small-and-auditable), ring 1) and the render-safe literal types | 1,602 | 2,032 |
| Generated policies | `contracts/golden-transfer-policy`, `contracts/soroswap-swap-policy` | The on-chain artifact, committed exactly as codegen emits it | 562 | tested below |
| Atomic live helper | `contracts/atomic-live-helper` | On-chain contract the owner signs into for the [live-enforcement check](ATOMIC-LIVE-HELPER.md) | 163 | 50 |
| Registry | `crates/registry` | Governance roots, rollback and equivocation resistance, capabilities by exact hash, the account method inventory | 1,169 | 1,539 |
| Call-surface core | `crates/call-surface-core` | The install-time authority verdict | 1,101 | 1,386 |
| Synthesizer | `crates/synthesizer` | Exact-by-default decisions, adapters, composition checks | 1,348 | 1,427 |
| PolicySpec | `crates/policy-spec` | Schema, validation typestate, signer-set hash | 1,307 | 942 |
| Reference evaluator | `crates/evaluator` | The independent oracle generated code is compared with | 364 | 625 |
| Domain | `crates/domain` | Canonical hashing, trust labels and the pinned upstream hashes every row above depends on | 841 | 502 |
| Contract tests | `contracts/differential` | Differential, generated-suite, event, TTL and pinned-account tests of the contracts above | — | 6,526 |
| Pinned OpenZeppelin account | `examples/multisig-smart-account/account` at v0.7.3 | The account every grant is installed into; see below | 57 | not counted |
| Other pinned OpenZeppelin wrappers | `examples/multisig-smart-account/{spending-limit-policy,ed25519-verifier,webauthn-verifier}` at v0.7.2 | Recognized by exact hash; the spending limit is composed in the [subscription walkthrough](WALKTHROUGH-SEP41.md) | 112 | not counted |
| **Tier 1** | | | **8,626** | **15,029** |

**The pinned account is outside OpenZeppelin's own audit.** Their v0.7.0 audit report (in the
`audits/` directory of their repository) lists only `packages/` files in scope. The account this
repository recognizes is the *example* wrapper in `examples/multisig-smart-account/account`: 57
lines that choose which library traits to expose (`SmartAccount`, `ExecutionEntryPoint`,
`Upgradeable`) and add a constructor and `batch_add_signer`. The library it delegates to is in
that scope; the wrapper, and this repository's reliance on it, are not. The authority check's
model of it is the reviewed method inventory in `crates/registry/src/account_methods.rs`
([limits](ACCOUNT-METHOD-INVENTORY.md)). Its exact hash is `OZ_SMART_ACCOUNT_WASM` in
`ozpb_domain::pinned_upstream` (`crates/domain/src/lib.rs`);
[SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md) states which release is recognized, and
`scripts/verify-pinned-upstream.sh` rebuilds it from source.

### Tier 2 — paths that feed trust decisions

| Component | Path | Why it is here | Non-test | Test |
| --- | --- | --- | ---: | ---: |
| Recorder core | `crates/recorder-core` | Authorizer selection, evidence trust derivation, attribution | 1,697 | 1,842 |
| RPC acquisition | `crates/source-rpc`: `account_*.rs`, `checked_account_observation.rs`, `classic_account.rs`, `contract_code.rs`, `contract_data.rs`, `ledger_witness.rs`, `assembly.rs`, `policy_state_capture.rs`, `lib.rs`, with their tests | The account scan behind the authority check, transaction recording, the reads behind install assembly and the live policy check | 4,790 | 6,229 |
| Toolkit operations | `crates/toolkit`: `lib.rs`, `verification.rs`, `install_intent.rs`, `install_assembly.rs`, `call_surface.rs`, `call_surface_live.rs`, `authority_text.rs`, `installed_grant.rs`, `policy_check.rs`, with their tests | Trust lowering at the synthesis boundary, recognition of generated artifacts by rebuilding them, install intent and unsigned assembly | 3,309 | 4,070 |
| Wallet validators | `wallet/shared` | Independent re-validation of assembly, consent, revocation and replacement | 1,711 | 9,781 |
| Wallet backend install path | `wallet/server/`: `actions.mjs`, `install.mjs`, `network.mjs`, `live-signing.mjs`, `http.mjs`, `session.mjs`, `tool.mjs` | Consent, signature collection, submission, event-verified records | 2,058 | in the row above (all of `wallet/tests`) |
| Build runner and worker isolation | `crates/build-runner`, `deployment/worker-launcher.py` (tested by `scripts/test-worker-launcher.py` and `scripts/test-worker-containment.py`) | Bounded builds, manifest reconciliation against the Wasm's own metadata, [disposable workers](ISOLATED-BUILDS.md) | 1,951 | 1,777 |
| **Tier 2** | | | **15,516** | **23,699** |

### Informational — not in scope

| Component | Non-test | Test | Note |
| --- | ---: | ---: | --- |
| `crates/mcp-server` | 1,929 | 3,487 | Thin shell. The hosted HTTP boundary (`src/http.rs`, `src/preflight.rs`) matters if a hosted deployment is in scope |
| `crates/cli` | 2,623 | 1,350 | Thin shell, except that `ozpb dry-run` holds a delegate key (`src/dry_run/`; see SECURITY.md) |
| `crates/api-types` | 1,115 | 1,104 | Wire types and stable error codes |
| `crates/harness` | 1,079 | 839 | Derives the permit/deny suite: evidence, not enforcement |
| `crates/source-bundle` | 47 | 198 | Import adapter whose output is `self_supplied` |
| Rest of `crates/source-rpc` (target and footprint capture, target Wasm, preflight) | 1,694 | 2,672 | Dry-run and preflight evidence |
| Rest of `crates/toolkit` (dry run, its report, preflight, capture) | 1,680 | 1,173 | Same |
| `execution-runtime` | 2,577 | 2,133 | Offline native worker for the account-Wasm layer |
| Rest of `wallet/server` | 1,516 | — | Live check, monitoring, native worker glue |
| `testnet-harness`, `scripts/demo-tranche1.sh`, `skills/`, `wallet/overlay`, docs | — | — | Testnet demonstration, agent instructions, wallet UI |

## Entry points

| Surface | Entry points | Trust-bearing |
| --- | --- | --- |
| MCP server (`crates/mcp-server`: stdio, or streamable HTTP with bearer authentication) | `synthesize_policy`, `generate_code`, `verify` | Yes: they decide what a grant permits and whether an artifact is recognized as generated |
| | `check_policy_call_surface`, `prepare_install_intent`, `assemble_install_transaction` | Yes: the install-time authority verdict and the unsigned `add_context_rule` the owner signs |
| | `record_transaction`, `record_simulation`, `import_recording`, `capture_target` | Yes, for the evidence label they assign. Network reads go only through operator-named RPC sources |
| | `evaluate_spec`, `reference_suite`, `prepare_dry_run`, `check_against_policy`, `preflight_transaction` | Advisory: evidence or prediction, never an authorization |
| | `connect_wallet`, `send_wallet_proposal` | Handoff only: the wallet regenerates the grant itself |
| CLI `ozpb` (`crates/cli`) | The same operations (`record`, `simulate`, `import`, `synthesize`, `evaluate`, `generate`, `reference-suite`, `prepare-dry-run`, `verify`, `check-policy-call-surface`, `prepare-install-intent`, `assemble-install-transaction`, `check-against-policy`, `check-installed-grant`, `capture-target`, `preflight-transaction`), plus `dry-run` and `dev-registry` | As for MCP. `dry-run` is the one command that holds a key |
| Wallet backend (`wallet/server`, localhost only) | `POST /api/policy-builder/<action>` with the session secret; the trust-bearing actions in `wallet/server/actions.mjs` are `prepare-deploy`/`confirm-deploy`, `check-account`, `review`, `consent-live`/`run-live`, `assemble`, `submit`, `use-grant`, `prepare-revoke`/`confirm-revoke` and `prepare-replacement`/`confirm-replacement` | Yes: owner consent, signature collection and submission |
| | `POST /agent/connect`, `POST /agent/proposal` | Draft delivery only: a pairing code, then a bearer capability; cannot start a wallet action |
| On-chain | A generated policy's `enforce`, `install`, `uninstall`, `is_installed`, `remaining_calls`; the atomic live helper | Yes |

## Threat model

**Assets.** Authority over the user's smart account (its rules, signers, policies and code); what
a grant can move; agreement between the installed Wasm and the reviewed spec; the owner's consents
and signed authorization entries, each live until it expires; the confidentiality of unsigned and
simulated transactions; the registry's roots and checkpoint.

| Actor | Can try to | What stops it | Tested in |
| --- | --- | --- | --- |
| Malicious agent or delegate, holding the grant's key and possibly other rules on the account | Call outside the grant; exceed its count or expiry; reset the cap or create rules through another rule it holds; hand the wallet a broader proposal | The generated policy's checks; the call-surface check, which refuses a rule the agent's key can use alone (`E_DELEGATE_HAS_AUTHORITY`); the wallet regenerating every proposal | `contracts/differential/tests/differential.rs`, `generated_suite.rs`, `account_wasm_invariants.rs` ([map](SCOPE.md#state-invariants-and-direct-calls)); `crates/call-surface-core/src/tests.rs`; `wallet/tests/proposal-actions.test.mjs` |
| Malicious recording input: an RPC response, an imported bundle, JSON over MCP | Raise its own evidence label; inject Rust through a symbol, string or byte value; get a bound or wildcard synthesized | Trust derived from the acquisition path and lowered at the boundary; render-safe literal types; exact-by-default synthesis, with widenings only from explicit decisions | `caller_supplied_provenance_labels_are_downgraded_before_synthesis` (`crates/toolkit/src/lib.rs`); `imported_snapshots_are_self_supplied_at_most` (`crates/recorder-core`); `every_string_literal_in_generated_source_is_a_bare_identifier_or_strkey`, `a_hostile_template_family_cannot_inject_header_lines_or_crate_attributes` (`crates/codegen`); `widening_with_observed_exact_provenance_fails` (`crates/policy-spec`); `hostile_numeric_widening_fails_during_synthesis` (`crates/synthesizer`) |
| Malicious RPC endpoint | Misreport a transaction or the account's rules; omit or archive keys; answer for another network | Network passphrase binding; scans that fail closed on missing, archived, undecodable or count-mismatched entries; only operator-named sources; the wallet re-reading before signing. A consistent lie is not detectable (limit 1 below) | `missing_and_archived_entries_fail_closed`, `a_count_that_disagrees_with_its_response_is_incomplete` (`crates/source-rpc/src/account_state_scan.rs`); `crates/source-rpc/tests/rpc_conformance.rs` |
| Malicious registry snapshot | Roll back, freeze or equivocate; add a capability; revive a revoked entry | Threshold signatures over operator roots, version and persisted checkpoint, append-only revocations, exact-hash keys, unknown means refused | `rollback_and_freeze_are_rejected`, `a_persisted_checkpoint_rejects_same_version_equivocation_after_restart`, `bad_signature_is_rejected`, `unknown_hashes_fail_closed`, `accepted_revocations_are_append_only_and_immutable` (`crates/registry/src/lib.rs`) |
| Compromised hosted MCP server | Return a wrong spec, artifact or transaction; collect signed material | It holds no keys and prepares unsigned XDR only; it refuses envelopes carrying signatures; the wallet validates assembly and regenerates grants independently; `verify` reproduces an artifact locally | `hosted_preflight_refuses_signed_material_before_any_request` (`crates/mcp-server/src/preflight.rs`); `assembly_is_unsigned_and_uses_operator_trust_and_rpc_sources` (`crates/mcp-server/tests/mcp_stdio_authority.rs`); `wallet/tests/assembly.test.mjs` |

| Invariant | Enforced in | Tested in |
| --- | --- | --- |
| **Signer predicate.** Right after its installation and expiry checks, and before it looks at the call, a generated policy refuses an authorization whose authenticated signers do not satisfy its predicate, the empty set included (the account defers signer checks to policies). For named identities it also refuses when the rule's live signer set differs from the compiled one: validation requires strict mode for them. | `enforce` in each generated `src/contract.rs`, emitted by `crates/codegen` | `zero_signers_denies_in_both`, `unrecognized_signer_denies_in_both`, `strict_mode_denies_grown_and_swapped_signer_sets_in_both` (`differential.rs`); `named_identities_require_strict_signer_set` (`crates/policy-spec`); through the pinned account, `weak_account_rule_cannot_widen_the_grant_signers_but_can_strip_its_policy` |
| **Exact tuples.** A permitted `(contract, function, args)` deep-equals a compiled-in tuple; bounds and wildcards enter only through explicit, provenance-tagged decisions; tuples are never combined into a Cartesian product. | `crates/synthesizer`, `crates/policy-spec`, `crates/codegen` | `amount_mutations_deny_in_both`, `function_and_target_mutations_deny_in_both`, `arg_arity_and_type_confusion_deny_in_both` (`differential.rs`); `generated_suite.rs`, `swap_generated_suite.rs`; `incomplete_tuples_fail` (`crates/policy-spec`); `widening_applies_only_with_explicit_decision_and_only_to_amounts`, `tuple_dedup_merges_identical_and_keeps_distinct` (`crates/synthesizer`) |
| **Fail-closed recognition.** Unknown account, policy or verifier code, an unloaded registry or an unverifiable snapshot is an error, never a guess. | `crates/registry`, `crates/call-surface-core` | The registry tests in the table above; `queries_before_load_fail_closed` (`crates/registry/src/lib.rs`); `unrecognized_account_fails_closed` (`crates/call-surface-core/src/tests.rs`) |
| **Authority surface.** Before installation, every live rule that can change the account or reset a bound policy is listed with its exact signers; the check refuses when the agent's key can do either alone, when another rule on the target gets around a stateful limit, or when a rule shape is unsupported. | `crates/call-surface-core`, `crates/toolkit/src/call_surface_live.rs`, the scan in `crates/source-rpc` | `crates/call-surface-core/src/tests.rs`, e.g. `case_6_restricted_key_that_can_manage_alone_is_refused`, `stateful_grant_beside_another_usable_rule_on_the_target_is_refused`, `new_rule_cannot_target_the_account_or_a_bound_policy`; through the pinned account, the direct-call and weak-management rows of the [state-invariant map](SCOPE.md#state-invariants-and-direct-calls) |
| **Stateful invariants.** Only `install` initializes state; missing state denies; a cap never resets within an installation; TTL extension is bounded; archival is not revocation; reinstalling is a new grant; a failed composition rolls back. | `install`, `enforce`, `uninstall` of each generated policy | The [state-invariant map](SCOPE.md#state-invariants-and-direct-calls), row by row; `contracts/differential/tests/ttl.rs`; `missing_state_denies_in_both`, `install_is_the_only_initializer_and_double_install_fails` (`differential.rs`) |
| **Evidence labels are earned.** A caller cannot raise a recording's trust level. | `crates/domain`, `crates/recorder-core`, the synthesis boundary in `crates/toolkit` | `downgrading_to_self_supplied_never_raises_a_level` (`crates/domain/src/lib.rs`) and the recording-input row above |
| **Independent oracle, deterministic output.** The evaluator does not depend on codegen (both build on `policy-spec` and `domain`); the same spec yields byte-identical source. | `scripts/check-dep-rules.sh`, `crates/codegen` | `scripts/test-check-dep-rules.sh`; `generation_is_byte_deterministic`, `golden_crate_matches_committed_output`, `soroswap_crate_matches_committed_output`, `two_payment_crate_matches_committed_output` (run by `scripts/check-codegen-fixtures.sh`) |
| **No deployment or installation without the user.** The library and the MCP server never sign or submit; deployment needs the owner's explicit consent, and installation the owner's own signature over the exact reviewed transaction. | `crates/toolkit`, `wallet/shared`, `wallet/server` | `assembly_is_unsigned_and_uses_operator_trust_and_rpc_sources`; `wallet/tests/controller.test.mjs` ("deploy consent is separate and install validates and shows its consent before requesting a passkey"); `wallet/tests/install-actions.test.mjs` ("submit refuses an envelope differing from the reviewed assembly") |

[MAINNET-GATES.md](MAINNET-GATES.md) maps each of architecture §10's acceptance gates before any
mainnet use to the tests that establish it, with its status (closed, narrowed to the shipped
grant shape, open, or a review gate) and the deviations it states. `scripts/check-mainnet-gates.sh`
reads that document and runs each named test by its full name.

## Known limits — not findings

Each is documented and deliberate in this tree. A report that one of them is *false* — that a path
said to fail closed opens — is a finding.

1. **Observations are not proofs.** The authority check reads one endpoint at one ledger; its
   result is `rpc_reported`, and owner identity is matched by the key-holding wallet, not by the
   toolkit. Account recognition establishes generation compatibility only
   ([SCOPE.md item 1](SCOPE.md#implementation-boundaries), [SECURITY.md](../SECURITY.md)).
2. **Authorization-minimal, not effect-minimal.** A rule binds an address, not code; a target
   upgrade changes what a permitted call does
   ([architecture §6.1](architecture.md#61-what-is-actually-guaranteed-authorization-minimal-vs-effect-minimal)).
   The Soroswap router binding is a development-registry assertion and there is no Blend adapter
   ([deviations](TRANCHE-2-VERIFICATION.md#deviations-and-open-gaps-against-the-phase-2-design)).
3. **Development registry governance.** The committed root is a public development key, accepted
   by the operator reader only for testnet; production governance is Tranche 3 work
   ([architecture §10](architecture.md#10-delivery-plan),
   [ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §10).
4. **Caps are per installation.** A holder of a rule matching the policy's or the account's
   address can reset a cap; the check refuses such a rule the agent can use alone and lists the
   others, and a rule added later is detected only by the on-demand check
   ([architecture §4.4](architecture.md#44-code-generation-cratescodegen),
   [state-invariant map](SCOPE.md#state-invariants-and-direct-calls)).
5. **Partial dry run.** All four layers exist only for one native-SAC transfer shape; a reviewed
   policy is not executed in the offline account-Wasm composition
   ([SCOPE.md items 3, 5 and 6](SCOPE.md#implementation-boundaries)); the evaluator returns
   `indeterminate` for a policy it does not model ([SECURITY.md](../SECURITY.md)).
6. **Build provenance.** The builder is labelled `local-unattested`; the manifest lacks the source
   commit, template-pack hash, container digest and other fields; the default host builder does
   not isolate one build from another ([SCOPE.md item 2](SCOPE.md#implementation-boundaries)).
7. **Reproducibility.** The pinned account Wasm reproduces byte-for-byte only on an Apple Silicon
   build host; generated Wasm reproduces on comparable hosts
   ([DEVELOPERS.md](DEVELOPERS.md#verifying-the-pinned-upstream-trust-anchors),
   [ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §2).
8. **Unsupported shapes are refused, not handled.** A new spec cannot name an external-verifier
   signer; muxed contract addresses are refused ([SECURITY.md](../SECURITY.md),
   [SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md#protocol-30-compatibility)).
9. **Denials leave no on-chain event**, because a panic reverts the publish
   ([ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §6).
10. **Local key handling.** `ozpb dry-run` reads a delegate key from a 0600 file, and the native
    worker it starts runs unsandboxed as the caller ([SECURITY.md](../SECURITY.md)).
11. **Hosted operation** is a shared-token, trusted-client boundary
    ([deviations](TRANCHE-2-VERIFICATION.md#deviations-and-open-gaps-against-the-phase-2-design)).
12. **RUSTSEC-2026-0387** is accepted temporarily, with an expiry
    ([SECURITY-EXCEPTIONS.md](SECURITY-EXCEPTIONS.md)).

## Prior relevant findings

- **GHSA-jpg9-m7w4-c7wc**, delegated signer bypass in `stellar-accounts` before 0.7.3. The account
  recognized up to development registry version 5, OpenZeppelin's 0.7.2 example, is inside the
  affected range, and generated grants authorize through delegated signers. The recognized account
  is now the 0.7.3 build, and version 6 revokes the 0.7.2 entry; the revocation binds only under a
  registry floor of 6 or a version-6 checkpoint ([SECURITY.md](../SECURITY.md#upstream-advisories)).
  [SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc) names the
  recognized release and the delegation-back cases the fix cannot see, and
  `ozpb_domain::pinned_upstream` holds its hash.
- **OpenZeppelin v0.7.0 audit, L-06**: the spending-limit policy accepted a negative amount and
  reduced the amount spent. Upstream fixed it in the policy, so the pinned 0.7.2 spending-limit
  source refuses a negative amount. Here, the evaluator's spending model denies one
  (`negative_amount_and_i128_overflow_never_permit`, `crates/evaluator/src/spending_limit.rs`),
  and validation refuses a spending-limit composition whose amount constraint admits no
  non-negative amount within the limit (`spending_limit_requires_transfer_amount_at_argument_two`
  in `crates/policy-spec`, `spending_limit_constraint_intersections_include_only_their_boundaries`
  in `crates/synthesizer`). The generated scope policy does not refuse negative values on its
  own: an upper bound (`LeI128`), which the Soroswap adapter derives for a maximum-input argument
  and a user widening can add, admits every smaller value, negatives included, and leaves a
  negative amount to the target to refuse. That is the assumption L-06 advises against, and a
  question for this audit.
- **Unbounded enforce events** in OpenZeppelin's policies, found during the conventions pass:
  embedding the whole `Context` lets a permitted call fail on the network's event-size limit.
  Generated policies publish a digest instead
  ([ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) §15, divergence 9); the upstream report
  is [OpenZeppelin/stellar-contracts#852](https://github.com/OpenZeppelin/stellar-contracts/issues/852).

## Building and running the gates

Prerequisites and pinned tool versions are in the
[Tranche 1 guide](TRANCHE-1-VERIFICATION.md#1-run-the-release-gate): Rust 1.91.1 with
`wasm32v1-none` (`rust-toolchain.toml`), `stellar-cli` 27.0.0 at its recorded revision,
`cargo-deny` 0.20.2, `cargo-machete` 0.9.2 and Python 3. The wallet suite needs Node 22.12 or
later (CI uses 24.15.0). From the repository root:

```sh
# Release gate: dependency rules, publication and quoted-hash invariants, fmt and clippy over
# both workspaces and both generated crates, all tests, the differential suite, codegen
# determinism, clean-rebuild Wasm reproducibility, licences and advisories — then the Phase 2
# evidence checks and a Soroswap Wasm build. `--offline` is the reduced form and says what it skips.
bash scripts/verify-phase2.sh

# Generated policy Wasm through the exact pinned account Wasm: signed delegated authorization,
# the state-invariant suite, the native worker and captured-target layers. Apple Silicon host.
bash scripts/test-pinned-account-authorization.sh

# Rebuild the pinned OpenZeppelin artifacts from their tag and compare hashes.
bash scripts/verify-pinned-upstream.sh

# Native execution worker.
cargo test --manifest-path execution-runtime/Cargo.toml --locked

# Wallet validators and backend, as CI runs them.
cargo build --locked -p ozpb-cli -p ozpb-mcp-server
npm ci --prefix wallet --ignore-scripts --no-audit --no-fund
OZPB_BIN="$PWD/target/debug/ozpb" OZPB_MCP_BIN="$PWD/target/debug/ozpb-mcp-server" \
  npm test --prefix wallet

# Every test docs/MAINNET-GATES.md names, by full name, each required to pass exactly once
# (wallet titles need the npm ci above). It names the Wasm-gated ones without running them.
bash scripts/check-mainnet-gates.sh
```

Disposable build workers have their own acceptance run on the chosen Linux host
([ISOLATED-BUILDS.md](ISOLATED-BUILDS.md#acceptance-on-the-chosen-host)). The scheduled and
path-triggered jobs that run the pinned-account gate on macOS arm64 are in
`.github/workflows/nightly-live.yml`. What each gate does and does not establish is in the
[Tranche 2 guide](TRANCHE-2-VERIFICATION.md#what-the-focused-checks-establish).

Report findings through the private channel in [SECURITY.md](../SECURITY.md).
