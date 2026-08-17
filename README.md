# OZ Accounts Policy Builder

Record a transaction, generate a minimum-permission Soroban policy.

A **record-and-generate** toolkit for OpenZeppelin Stellar smart accounts: point at a
transaction you already performed (on-chain by hash, or locally simulated) and the toolkit
synthesizes a context rule plus a small, validated composition of policies that permits
exactly what you approved — and denies everything else it can observe. Output is
human-readable Rust implementing the OpenZeppelin `Policy` trait, produced by a
deterministic, auditable pipeline. **Code-first, deploy-second:** nothing is ever deployed
automatically.

The full technical architecture (v0.8) lives in `docs/architecture.md`. This repository is
the Phase 1 implementation: the core pipeline — recorder → PolicySpec → synthesizer →
codegen — plus the independent reference evaluator, capability registries, and an MCP
server (stdio) exposing `record_transaction`, `record_simulation`, `import_recording`,
`synthesize_policy`, `evaluate_spec`, and `generate_code`.

Later phases are described in the architecture and marked there; they are not shipped, not
verified, and not claimed complete by this repository.

## Design invariants (enforced, not aspirational)

- **Determinism:** same canonical PolicySpec + identical pinned build inputs ⇒
  byte-identical generated source. CI runs codegen twice, cold, and diffs the bytes.
- **Exact-by-default synthesis:** every observed argument becomes a deep exact-equality
  constraint; widening only via explicit, provenance-tagged user decisions.
- **Mandatory signer predicate:** the OZ smart account defers signer validation to policies
  when a rule has policies attached — so every generated policy enforces its signer
  predicate first, and strict signer-set checking is the default for named identities.
- **Independent evaluator:** the reference evaluator shares no code with codegen; a CI
  check on the cargo dependency graph fails if that edge ever appears.
- **Fail-closed:** unknown credentials, unknown policies, ambiguous observations, and
  unregistered account/verifier hashes are machine-readable errors, never guesses.

## Workspace

```
crates/
  domain            pure shared vocabulary: hashes, newtypes, trust levels, provenance
  recorder-core     pure: EvidenceSnapshot -> RecordingBundle
  source-bundle     acquisition adapter for imported evidence bundles (pure)
  source-rpc        async acquisition adapter over Soroban RPC
  policy-spec       PolicySpec v1: schema, validation (typestate), canonical hashing
  synthesizer       pure: RecordingBundle(s) + user decisions -> PolicySpec
  evaluator         independent reference evaluator (never depends on codegen)
  codegen           pure: ValidatedSpec -> Rust policy crate source
  build-runner      bounded local builds + BuildManifest attestation of the wasm
  registry          signed capability registries (policy / account / verifier)
  api-types         MCP DTOs + stable machine-readable error codes
  toolkit           the operations both shells call, and the only place they live
  mcp-server        rmcp stdio shell over the library (no domain logic)
  cli               human-oriented shell over the same library
contracts/          separate cargo workspace: golden generated policy + soroban tests
scripts/            dependency-rule check, determinism check
```

Development is **test-first** throughout: a failing test precedes the implementation that
makes it pass, and every declared error code has a test that demands it.

## License

Apache-2.0. Built in the open by [Gateway.fm](https://gateway.fm).
