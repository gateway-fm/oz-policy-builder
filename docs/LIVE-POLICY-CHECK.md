# Live prediction for one installed rule

`ozpb check-against-policy` and the MCP tool `check_against_policy` predict a proposed
invocation against one installed context rule. A permit is conditional on the supplied
candidate signer identities successfully authenticating later. The operation does not check
signatures or establish who owns the account. The wallet must use the same installed rule,
repeat the check immediately before signing, and enforce-simulate the actual transaction
and authorization tree.

```sh
ozpb check-against-policy \
  --request policy-check.json \
  --registry-roots registry-roots.json \
  --registry-min-version 3 \
  --rpc-sources rpc-sources.json
```

The request is the typed `CheckAgainstPolicyInput`: a PolicySpec, exact PolicyBindingSet,
signed registry snapshot, spec `rule_index`, actual `installed_context_rule_id`, account and
network IDs, an operator-configured `rpc_source` name, candidate signer identities, and an
invocation. The chain's rule ID is independent of the spec index. Neither caller-supplied
evaluator state nor a caller-selected endpoint is accepted. Registry roots, rollback floors,
optional durable checkpoints, build settings and RPC source configuration belong to the
operator. Hosted operation also applies the endpoint allowlist and shares the existing build
and live-read budgets across sessions.

## Recognition and modeled behavior

The account must use the exact pinned implementation with the supported storage and
authorization semantics. Every policy binding is checked against the signed registry and
spec. Generated policies require local reproduction of their source, Wasm and BuildManifest;
a caller's manifest alone is insufficient. The final observed instance code must match the
recognized hash. Registry validity is checked again after the builds and network reads.

The current model covers the generated scope/count policy and composition with the pinned
reviewed spending-limit policy. It checks the live rule's context, name, expiry, signers and
exact policy set, generated installation marker and per-installation counter, and the reviewed
policy's installed limit, window and spending history. Missing state never becomes a fresh
counter. The spending model follows the upstream cutoff and history-capacity behavior and
rejects inconsistent history. Rules expire after their inclusive `valid_until` ledger.

All supplied candidates must belong to the selected rule. An authorized signer accompanied
by a stranger yields `deny` with `unauthorized_signer`. Named predicates require the specified
live signer set; the explicitly dynamic predicate uses the observed current set. Empty
candidates cannot satisfy a generated policy. Delegated contract signers and unsupported
classic signing configurations return `unsupported`. External verifier recognition uses
observed code and the supported key scheme; it never verifies a future signature.

Adapter-required target identities and explicit refuse-on-drift constraints stop a prediction
after a code change. An evidence-only warn-on-drift identity is reported in `target_drift`;
it does not become an enforcement guarantee.

## Ledger evidence and refusals

Discovery reads only identify required keys. The reader then fetches the complete key set in
one `getLedgerEntries` response bracketed by matching `getLatestLedger` hashes, sequences and
protocol versions. It rederives the selected rule's dependencies from that final response.
If the ledger or dependencies change, the entire attempt is discarded and retried, at most
twice. More than 200 final keys is refused. Requests and XDR responses have separate count,
size and depth bounds.

Every returned key must match its exact decoded entry. Duplicate or unexpected entries,
future modification ledgers, missing TTL metadata, incorrect code bytes/hashes and malformed
XDR fail closed. The returned `ledger_hash` is the endpoint's actual ledger identifier, never
a digest of locally collected entries. Matching endpoint responses are not a cryptographic
ledger inclusion proof.

`permit` and `deny` contain the full request hash, spec/binding/registry identities, ledger
anchor, exact canonical LedgerKey and full LedgerEntryData XDR, last-modified ledgers, TTLs,
the explicit authentication assumption, `rpc_reported` trust and mandatory recheck label.
Classic account entries are separate because they have no TTL. Code entries are associated
with the contract instances that reference them. State/configuration evidence remains an
observation of the configured endpoint.

Unrecognized implementations or unsupported models return `unsupported`. When a complete
capture is available, the unsupported result includes it. An explicitly expired TTL reports
restoration `required`; an omitted persistent key reports `unknown`, because omission cannot
distinguish an archive from a key that never existed. This operation performs no restoration
and never claims `restored`. Network or malformed-response failures retain structured tool
errors and withhold endpoint-controlled diagnostics.

The prediction covers only this invocation and selected installed rule. It does not enumerate
alternate rules or determine account safety, ownership, available balances, transaction fees,
footprint/resource sufficiency or whether another ledger change will occur before submission.
Use the authority check for its separately stated scope and live enforce simulation for the
actual authorization. Neither replaces the wallet's decision.

## Validation

Tests exercise ledger/hash drift, changed dependency closure, malformed or mismatched XDR,
code drift, unavailable/archived state, distinct chain/spec rule IDs and foreign candidates.
The independent spending-window model is compared with the pinned upstream policy around
amount, cutoff and history-capacity boundaries. The synthetic 1,000-entry history test disables
the SDK's transaction resource limits to reach the policy's own capacity check; it does not
show that such a state fits a network ledger entry or transaction. These are automated local
checks; this change does not claim a new live network run or complete milestone acceptance.
