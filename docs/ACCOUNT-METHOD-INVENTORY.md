# Account method inventory limits

The registry has a source-reviewed candidate for the pinned OpenZeppelin multisig example's
17 methods, including wrapper entrypoints outside the `SmartAccount` trait. An exact-hash
copy of the pinned Wasm has 17 matching function exports. `scripts/verify-pinned-upstream.sh`
reproduces that artifact, byte-for-byte on an Apple Silicon host only (see
`docs/TRANCHE-1-VERIFICATION.md` §3), and checks the names. The account authorization guards
and direct and transitive effects come from source review, not from export names.

## Review for 0.7.3

The table was first reviewed against OpenZeppelin `stellar-contracts` v0.7.2 (`a9c4216`). The
recognized account is now the same example built at v0.7.3 (`252b35f`), for
[GHSA-jpg9-m7w4-c7wc](SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc). The v0.7.2→v0.7.3
diff leaves the wrapper (`examples/multisig-smart-account/account/src/contract.rs`) and its 17
exports unchanged and changes `packages/accounts/src/smart_account/{mod,storage}.rs` only:

| Method | Change in 0.7.3 | Effect on its row |
|---|---|---|
| `__check_auth` | `do_check_auth` refuses a `Delegated` signer whose address is the contract of a context being authorized (`DelegatedSignerIsContextContract`, 3017), before `authenticate` calls `require_auth_for_args` on it. | None: the check reads only the signer and the authorization contexts. No storage, verifier or policy call is added, and the signed digest is unchanged. |
| `add_context_rule`, and so `__constructor` | Refuses a signer `Delegated` to the account itself (`SelfDelegatedSigner`, 3018). | None: the check compares with `current_contract_address()`. |
| `add_signer`, `batch_add_signer` | The same 3018 refusal for each new signer. | None, for the same reason. |
| All others | Unchanged. | None. |

The table records guards and effects, not refusals, so its contents and digest are the same for
both builds. It is bound to the 0.7.3 hash alone: `validate_source_reviewed_candidate` and
`Registry::resolve_account_authority` refuse the 0.7.2 hash, whatever a signed snapshot says.
`SmartAccountError` now runs from 3000 to 3018.

## Registry commitment

The signed development example (version 2 onward) commits to the exact reviewed method-table digest
and bounded scan protocol for the recognized account Wasm hash: the 0.7.2 build in versions 2 to 5,
the 0.7.3 build in version 6, which revokes the 0.7.2 entry. It extends the original example root;
its signing key is public development material, not production governance, and registry
trust built for any network but testnet refuses that root (`E_REGISTRY_ROOT_POLICY`), for every
consumer — synthesis, the live checks and the operator account reader alike. The live authority check uses the
signed scan protocol to bound its read; it does not use the method table to decide anything,
because it treats every method of the account as reachable by any rule that matches the
account's address. The table records which methods exist so that assumption can be reviewed.
Nothing here establishes the current rule set or a coherent ledger snapshot, and nothing says
an account is safe (§§4.8 and 4.10 of `architecture.md`, Decision D7).

`AccountMethodInventory` is constructed in Rust and can be serialized. JSON deserialization
is intentionally unavailable until duplicate method keys can be rejected explicitly.
