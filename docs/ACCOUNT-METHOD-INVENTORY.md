# Account method inventory limits

The registry has a source-reviewed candidate for the pinned OpenZeppelin multisig example's
17 methods, including wrapper entrypoints outside the `SmartAccount` trait. An exact-hash
copy of the pinned Wasm has 17 matching function exports. `scripts/verify-pinned-upstream.sh`
reproduces that artifact and checks the names. The account authorization guards and direct
and transitive effects come from source review, not from export names.

The signed version-2 development example commits to the exact reviewed method-table digest
and bounded scan protocol for this account Wasm hash. It extends the original example root;
its signing key is public development material, not production governance. The registry
resolver checks the code-capability binding, but has no authority-verdict consumer. It does not
establish the current rule set, administrator identity, policy-call effects, or a coherent ledger
snapshot. A trusted reader and complete method-level analysis remain necessary before a live
`Safe` authority verdict can be offered (§§4.8 and 4.10 of `architecture.md`).

`AccountMethodInventory` is constructed in Rust and can be serialized. JSON deserialization
is intentionally unavailable until duplicate method keys can be rejected explicitly.
