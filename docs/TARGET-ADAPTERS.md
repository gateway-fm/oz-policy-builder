# Reviewed target adapters

Synthesis resolves optional target adapters from the operator-trusted signed registry. A
binding names an exact observed target Wasm hash, a locally supported adapter implementation,
a digest of its semantics, and a source-review reference. Clients cannot supply an adapter
implementation or override a target hash through the synthesis request.

`RegistrySnapshot.target_adapters` maps lowercase Wasm hashes to records with
`implementation`, `semantics_digest`, and `review_reference`. An empty map is omitted when
serialized: previously published snapshots retain their roots and signatures. Governance must
publish new bindings as a signed successor under its existing version/checkpoint policy.
Revocations use `target_adapter/<wasm hash>` and remain effective if the binding is removed.
An adapter cannot share a code hash with an account, policy or verifier capability.

The implemented descriptor is `soroswap-router@1`. Its digest uses the
`ozpb:v1:target-adapter-semantics` domain over the complete descriptor, including implementation
name, function name, exact arity, ordered argument types and roles. Registry tooling can obtain
it from `ozpb_domain::target_adapters::soroswap_router().digest()`. A changed interpretation
requires a new descriptor version and reviewed binding; unknown identities or mismatched
digests are refused.

For `swap_exact_tokens_for_tokens(i128, i128, Vec<Address>, Address, u64)`, the roles are:

| Argument | Default constraint from the adapter |
| --- | --- |
| Input amount | Upper bound at the observed amount |
| Minimum output | Exact observed value; no quote or output floor is invented |
| Token path | Exact observed vector |
| Recipient | Exact observed address, with the usual runtime SELF binding |
| Deadline | Explicitly unconstrained according to the reviewed caller-chosen role |

The entire argument signature must match before any adapter-derived widening is applied.
Short, extended, differently typed or malformed calls retain exact constraints. No binding,
unknown target code, or missing executable observation also leaves synthesis exact unless the
user explicitly widens it. Explicit user decisions remain separate: for example, a user may
supply an absolute minimum-output floor, carrying `user_widened` provenance and intent. The
adapter does not certify that decision or turn it into a trusted quote.

Adapter-derived constraints retain the adapter identity and target code hash. The resulting
rule requires that hash and marks drift as a refusal. A wallet or live checker must compare
current code before relying on those semantics; the generated policy does not inspect target
code hashes on-chain.

The registry signature authenticates a governance assertion. Its review reference is not a
proof that deployed code implements the declared semantics, and caller-carried recording
observations remain `self_supplied` at the synthesis boundary. Governance must review the
actual implementation before binding its hash. Tests use explicitly synthetic bindings; the
shipped development registry adds no unverified live router hash. This feature alone does not
establish a live swap walkthrough or effect guarantee.
