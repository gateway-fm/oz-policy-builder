# Account method inventory limits

The registry has a source-reviewed candidate for the pinned OpenZeppelin multisig example's
17 methods, including wrapper entrypoints outside the `SmartAccount` trait. An exact-hash
copy of the pinned Wasm has 17 matching function exports. `scripts/verify-pinned-upstream.sh`
reproduces that artifact, byte-for-byte on an Apple Silicon host only (see
`docs/TRANCHE-1-VERIFICATION.md` §3), and checks the names. The account authorization guards
and direct and transitive effects come from source review, not from export names.

The signed development example (version 2 onward) commits to the exact reviewed method-table digest
and bounded scan protocol for this account Wasm hash. It extends the original example root;
its signing key is public development material, not production governance, and the
operator account reader accepts that root only for testnet. The live authority check uses the
signed scan protocol to bound its read; it does not use the method table to decide anything,
because it treats every method of the account as reachable by any rule that matches the
account's address. The table records which methods exist so that assumption can be reviewed.
Nothing here establishes the current rule set or a coherent ledger snapshot, and nothing says
an account is safe (§§4.8 and 4.10 of `architecture.md`, Decision D7).

`AccountMethodInventory` is constructed in Rust and can be serialized. JSON deserialization
is intentionally unavailable until duplicate method keys can be rejected explicitly.
