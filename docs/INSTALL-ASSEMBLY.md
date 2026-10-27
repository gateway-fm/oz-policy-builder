# Unsigned install transaction assembly

`assemble_install_transaction` (MCP) and `ozpb assemble-install-transaction` (CLI) turn a
freshly checked installation request into unsigned XDR. The tool re-runs the authority
check and derives `add_context_rule` arguments itself. It accepts neither a caller's
authority verdict nor a previously assembled transaction. It never signs or submits.

The request wraps the existing `prepare_install_intent` request:

```json
{
  "intent_request": {
    "spec": {},
    "rule_index": 0,
    "binding_set": {},
    "signed_registry_snapshot": {},
    "account_address": "<smart account C-address>",
    "network_id": "<network ID from the spec>",
    "rpc_source": "testnet"
  },
  "fee_payer": "<classic G-address>",
  "max_fee_stroops": 1000000,
  "validity_ledgers": 20
}
```

The empty objects and addresses above are placeholders: use the complete validated spec,
bindings and signed registry snapshot. The operator configures trusted roots, the registry
minimum version and named RPC endpoints. The caller cannot supply an endpoint URL or build
configuration. Run the CLI with the same trust files as the authority commands:

```sh
ozpb assemble-install-transaction --request assembly-request.json \
  --registry-roots registry-roots.json --registry-min-version 4 \
  --rpc-sources rpc-sources.json > unsigned-assembly.json
```

The five account arguments include every policy's exact installation parameters. Generated
scope policies receive `0`; the reviewed spending-limit policy receives its positive limit
and period. Policy addresses are encoded in the contract host's map order. A differing
authority grant, duplicate policy address, or invalid parameter is refused.

After the check, the assembler reads the payer's account entry and sequence, reads the RPC's
Soroban inclusion-fee estimate, and simulates the intended call in **recording mode**. It
accepts only the account's unsigned authorization for that exact call, with no extra calls
or nested authorizations. Unsupported authorization shapes are refused. The envelope has
one operation, no memo or transaction signatures, sequence plus one, a bounded ledger
interval, and a total fee no higher than the caller's ceiling. The inclusion bid uses the
reported 90th percentile with a 100-stroop minimum; it is an estimate, not an inclusion
guarantee.

`validity_ledgers` must be 1–120. The maximum ledger is exclusive, measured from the sequence
read; the assembled authorization expires no later than the preceding ledger. Because the
simulation's latest ledger is already closed, at least the next ledger must fit below that
maximum. This applies to installation and separate restoration drafts: a one-ledger window
cannot produce a usable draft, and a two-ledger window requires a same-ledger simulation.
Acquisition
must proceed monotonically and finish within 12 ledgers of the authority observation, or
the caller must retry. These are transaction and retry bounds, **not a guarantee that
account authority stayed unchanged**. Sequence, authority and simulation observations are
labeled separately; they are not one atomic snapshot.

## Restoration and the wallet boundary

The `restoration` field distinguishes three outcomes:

| Value | Returned envelope and next step |
| --- | --- |
| `none` | Unsigned installation draft. Independently review and complete it in the wallet. |
| `automatic_within_invocation` | Installation draft includes protocol-level restoration resources. Review those resources during wallet preflight. |
| `separate_transaction_reassemble_required` | Only a `RestoreFootprint` transaction is returned. After wallet-approved restoration succeeds, acquire a new authority check and assemble again. There is no installation envelope to reuse. |

Restoration is limited to contract code or persistent contract data. A separate restoration
may include only keys already present in the invocation footprint; automatic restoration
indices must identify eligible writable keys. These checks establish response coherence,
not proof that an entry is archived.

Recording mode does not execute the smart account's owner-authorization checks, so its
footprint and fee estimate may change when owner authorization is constructed. A wallet
must independently decode and validate every field against the intended operation, network,
fee payer and fee ceiling using its own RPC; re-run the authority check and match the
listed authorities to the user's trusted identities; obtain protected user approval; and
construct the owner authorization itself. It must then simulate with authorization
enforcement, reconcile the resulting resources and fees, and validate the exact transaction
before requesting transaction signatures. A service response must never be signed unchecked.

The response remains `rpc_reported`, state-dependent advice with `writes_committed: false`.
Its envelope digest is SHA-256 of envelope bytes, not a Stellar transaction hash. This
operation does not demonstrate a wallet product integration, human approval, deployment,
installation finality or four-layer behavioral verification.

The RPC semantics come from Stellar's [simulation method](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction)
and [fee statistics](https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getFeeStats).
See the [wallet ownership boundary](architecture.md#48-wallet-integration-wallet) for the
authorization and confirmation requirements.
