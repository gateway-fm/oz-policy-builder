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

## Which authorization entries are evidence

An executed envelope carries the authorization entries its submitter attached, and the network
checks only some of them. The host authenticates an address credential when a `require_auth`
call reaches that entry's invocation tree. A transaction still succeeds when an entry is never
reached, and that entry's signature is never verified (soroban-env-host 30, `test/auth.rs`:
"Correct call with an unused extra contract signature"). So anyone can attach an entry naming
another account and a payment out of it to their own successful transaction.

`authorizations` therefore holds an executed `Address`, `AddressV2` or `AddressWithDelegates`
credential only when the selected operation's meta shows its nonce consumed. The proof is a
created temporary contract-data entry under the entry's address, keyed `LedgerKeyNonce` with the
entry's nonce. The host's `consume_nonce` is the only writer of that key, and it runs only after
the signature has verified. Contract code cannot write it: `LedgerKeyNonce` has no `Val` form.
Every other entry is reported in `evidence_notes` as
`authorization entry <index> for <address> is not authorization evidence: <reason>`, with its
index in the operation's `auth` list. Such an entry is never an authorizer that synthesis can
derive or select. This covers:

- an entry whose nonce the meta does not show consumed. The rule reads the meta alone: a failed
  network transaction's meta records no operation changes, so none of its address credentials
  is kept, and neither is any of an executed recording without meta;
- two entries with the same address and nonce. The host consumes a nonce once, so at most one
  of them was checked, and the meta cannot say which.

A `SourceAccount` credential has no nonce. The operation's source account signed the
transaction that carries it, and that signature is its authorization, so it is always kept. Its
authorizer is the operation's own source account when the operation names one, otherwise the
(inner) transaction's source. The fee-bump fee payer is never the authorizer.

A simulation's entries are kept as returned. Record mode emits one for each address whose
`require_auth` the simulated call reached, unsigned and with a placeholder nonce. They describe
what the call would require, and no entry in them claims a signature.

A consumed nonce proves only that the network checked the entry. Under `rpc_reported` it is
still the endpoint's report, and under `self_supplied` the importer's.

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

A `recording/v2` artifact recorded before authorization entries were checked against the meta
no longer verifies if it lists an entry that is now a note, or attributes a source-account
credential to the transaction's source when the operation names its own. Verification reports
`E_EVIDENCE_INCOHERENT` for its `authorizations`. Record the transaction again, or reimport its
raw evidence.

Changing the schema changes recording hashes and downstream derived identities. Historical
published artifacts keep their original bytes and meaning. Current synthetic examples can be
regenerated from their source fixtures and reviewed as a complete derived chain.

## Mainnet fixture corpus

`crates/source-rpc/tests/captured-mainnet/` holds real mainnet transactions, captured on
protocol 29. Each case directory keeps the unedited `result` of every call `get_transaction`
makes: `getNetwork`, `getTransaction`, and `getLedgerEntries` for the referenced contract
instances. `manifest.json` names each case's transaction, ledger and coverage, and the ledger
windows the search scanned.
`crates/source-rpc/tests/mainnet_corpus.rs` replays them through `get_transaction` and `record`.
It compares every recorded authorizer, invocation tree and authorized argument with the
envelope's own XDR. Every address credential in the corpus has its nonce consumed in its
operation's meta, so every entry is recorded as authorization evidence.

| Case | What the recorder does with it |
|---|---|
| `sac-transfer-source-account` | fee-bumped on purpose: the source-account credential resolves to the inner transaction's source (the operation names none), never the fee payer; Stellar Asset Contract executable; one typed transfer |
| `classic-address-credential` | `Address` credential of a G-account that did not submit the transaction |
| `smart-account-credential` | account built on OpenZeppelin `stellar-accounts` authorizing a call that moves native XLM out of it under a spending-limit policy; its Wasm hash is observed |
| `nested-auth-tree` | a swap whose authorized root reaches a token transfer; every contract in the tree observed |
| `fee-bump-invocation` | relayer-paid invocation; the fee payer authorizes nothing; fee-bump inner result checked |
| `failed-invocation` | `E_TX_FAILED` by default; `allow_failed` records it as `executed_failed` |
| `classic-multi-operation` | `E_NO_SOROBAN_OP`, also for every explicit `operation_index` |
| `multi-authorizer` | every authorizer kept for synthesis to select, including an OpenZeppelin delegated signer whose entry authorizes the account's `__check_auth` |
| `auth-args-divergence` | `require_auth_for_args`: the authorized arguments are recorded, not the invoked ones |
| `credential-address-v2` | the protocol-27 `AddressV2` arm, with its nonce and expiration |

The same evidence imported through `source-bundle` is `self_supplied` with its transaction
result and `incomplete` without it.

Mainnet cannot supply the rest of what architecture §8 lists for this corpus:

- meta v3: mainnet has emitted meta v4 since protocol 23, for classic and Soroban transactions
  alike, so public RPC cannot supply v3 within its retention window. Older history has v3,
  but only an archive or indexer serves it. The recorder's synthetic fixtures cover v3;
- operation selection among several invocations: Stellar admits a smart-contract operation only
  as a transaction's single operation. Synthetic envelopes cover selection;
- `AddressWithDelegates`: none appeared in the windows the manifest records. A synthetic
  delegate tree covers the arm;
- `ledger_verified` and `trusted_indexer`: no acquisition path in this tree mints either label.

Public RPC keeps a transaction for about seven days, so a fixture cannot be fetched again
later. To refresh the corpus with new transactions of the same shapes:

```sh
python3 -I scripts/mainnet-recorder-fixture.py find --start <ledger> > picks.json
python3 -I scripts/mainnet-recorder-fixture.py capture picks.json
```

`find` scans `getTransactions` from each `--start` (repeatable) and the transactions behind
OpenZeppelin account events across the retention window. It uses Gateway's public mainnet RPC,
or `mainnet.sorobanrpc.com` when Gateway's does not answer; `--rpc` names another.
`capture` replaces the corpus only after every case is stored. Running it on the committed
`manifest.json` refreshes the same transactions while they are still retained. Both commands
only read: nothing is signed, simulated or submitted.

A refresh changes more than the anchors. `getLedgerEntries` returns current state, so the
observed ledgers move. Two endpoints can also return different meta bytes for the same
transaction: diagnostic events carry node-local timings, and the order of ledger changes in an
operation can differ. The authorizations and their fingerprints are unchanged, but recording
hashes are not. Mainnet now runs protocol 30 (reported on 25 November 2026), so a refresh must
also update `CAPTURED_PROTOCOL` in `mainnet_corpus.rs`.
