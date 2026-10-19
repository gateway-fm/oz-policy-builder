# Recording evidence

New recordings use `recording/v2`. Verification rebuilds decoded views from the preserved
XDR and checks their agreement before the recording can be used for synthesis. A recording
hash identifies the complete artifact; it does not authenticate a ledger or an RPC endpoint.

## Results and simulation changes

Executed recordings preserve `raw.result_xdr_base64` from RPC acquisition or raw evidence
imports. Verification checks the transaction outcome, successful operation count, operation
kinds, every operation's success code, and fee-bump inner transaction identity and outcome.
The result remains an endpoint or importer assertion: internal consistency is not a proof
that the result belongs to a transaction included in a particular ledger.

An executed import without a transaction result remains viewable as `incomplete` evidence.
Changing its trust label cannot make it eligible for synthesis. Simulations cannot carry
transaction-result or result-meta XDR.

Simulation state changes preserve their exact key and before/after XDR. Both admission and
verification decode these values, check that their keys agree and their presence matches the
change kind, and derive entry type and contract address from the key. These changes remain
explanatory evidence; they do not automatically become policy constraints.

## Acquisition context

Live RPC recordings include `acquisition.protocol_version`, `decoder_version`, and
`decoder_xdr_revision`. The protocol is the endpoint's current `getNetwork` response at
acquisition time, **not the historical protocol of the recorded transaction's ledger**.
The decoder identity describes the XDR implementation used to read the evidence. Unsupported
protocols and decoder identities are refused rather than treated as compatible silently.
Raw imports without this context leave it absent.

Executable observations retain `observed_ledger`, `last_modified_ledger`, and
`live_until_ledger` from the contract-instance read. RPC acquisition requires these values
and rejects modification after the observed ledger, expired instances, and malformed ledger
numbers. Optional fields on imported observations are never filled with guessed values.
Each observation has its own ledger anchor; a load-balanced endpoint may return it from a
ledger behind the transaction or simulation response.

## Existing artifacts

A `recording/v1` artifact cannot be silently upgraded: it did not preserve enough evidence
to recheck the claimed execution outcome. Reimport the original raw evidence bundle or record
the transaction again while the endpoint retains it. Raw import documents keep their existing
format; imports that already include a transaction result produce fully checkable v2 results.
An unavailable historical result must remain unavailable, rather than being reconstructed
from a claimed success label.

Changing the schema changes recording hashes and downstream derived identities. Historical
published artifacts keep their original bytes and meaning. Current synthetic examples can be
regenerated from their source fixtures and reviewed as a complete derived chain.
