# Account method inventory limits

The registry has a source-reviewed candidate for the pinned OpenZeppelin multisig example's
17 methods, including wrapper entrypoints outside the `SmartAccount` trait. An exact-hash
copy of the pinned Wasm has 17 matching function exports. `scripts/verify-pinned-upstream.sh`
reproduces that artifact and checks the names. The account authorization guards and direct
and transitive effects come from source review, not from export names.

An optional signed account entry can commit to the exact reviewed method-table digest and
bounded scan protocol. The registry resolver checks that binding for the exact pinned Wasm
hash; the committed example snapshot does not contain these optional fields. Resolution is
only a code-capability check and has no authority-verdict consumer. It does not establish
the current rule set, administrator identity, policy-call effects, or a coherent ledger snapshot.
A trusted reader and complete method-level analysis
remain necessary before a live `Safe` authority verdict can be offered (§§4.8 and 4.10 of
`architecture.md`).

`AccountMethodInventory` is constructed in Rust and can be serialized. JSON deserialization
is intentionally unavailable until duplicate method keys can be rejected explicitly.
