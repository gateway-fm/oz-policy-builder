# Native candidate account execution

`execution-runtime` is a separate, operator-selected native worker for the `account_wasm`
layer. It runs the pinned account Wasm and the exact supplied generated policy Wasm through
real Soroban authorization, with real Ed25519 delegate signatures and committed local state.
Its result always has `complete: false`: this mode does not invoke the target contract, import
captured network state, perform live enforcement, or authorize installation. The source network
and ledger fields bind provenance; the executed network and boundary ledgers are counterfactual.
The separate [captured-target mode](CAPTURED-TARGET-EXECUTION.md) runs a native SAC target call
against captured state.

The worker requires successful trusted `prepare_dry_run` artifact reproduction and registry
recognition before its result is used. It checks byte hashes and candidate identities itself;
it does not reproduce the generated source or authenticate the supplied registry snapshot.
The synthetic fixture script tests execution only and is not a preparation trust receipt.

## Supported scope and execution evidence

Initial support is one rule with one explicit delegated Ed25519 G signer, one generated policy,
and `any_of`, `all_of` or threshold-one authorization. The specification is at most 64 KiB,
with at most eight allowed calls, sixteen arguments per call and 256 derived boundary cases.
A call cap may be at most 512. Larger valid grants and other signer/policy compositions are
unsupported; there is no substitute signer or passing fallback.

Each boundary case starts from a fresh local installation at the exact candidate account and
policy addresses. A distinct deterministic bootstrap owner signs the setup invocation in the
offline network. This proves no ownership of the real wallet. The candidate's local rule ID is
1; the proposed chain ID is reported separately and remains unobserved. Counter boundary seeds
and validity-window ledgers are synthetic and explicit in each case result.

A denial agrees only when its expected account/policy error is attributed to the actual contract
and all local entries remain unchanged. Successful calls must advance any configured counter
by exactly one. Separate controls exercise signature-bit corruption, nonce/preimage binding,
payload and context-rule binding, and reuse of a consumed nonce. Cryptographic failures must
match the host's specific authorization error and diagnostic stage, with unchanged state.

For a bounded call cap, one continuous installation permits N calls and refuses N+1. With one
call remaining, a two-context authorization first spends that call, then refuses the second
context; both counter and nonce writes must roll back before a final single call succeeds.
This establishes local account authorization behavior, not the target's effects or network fees.

The runtime pins SDK 29.0.1 and its host 29.0.1 in its own lockfile, and rejects source protocol
versions other than 29. Generated contracts retain SDK 26.1.0 and the pinned account release.
Only canonical XDR crosses this boundary. A shared [ABI vector](examples/native-runtime-abi.json)
is checked against both the actual SDK-26 account/policy types and the runtime's SDK-29 wire
types; the source-built Wasm test additionally exercises the real account ABI.

## Machine protocol

Build with `cargo build --locked --manifest-path execution-runtime/Cargo.toml`. The operator
chooses the executable; requests cannot select a binary, endpoint, path or private key.
The worker accepts exactly no arguments (interactive execution) or exactly `--prepare`
(preparation only). `--captured` and `--prepare-captured` are the
[captured-target](CAPTURED-TARGET-EXECUTION.md) equivalents. All other argument combinations fail.

The first UTF-8 NDJSON line is a `NativeJob` of at most 16 MiB:

```text
{ schema: 1,
  request: DryRunInput,
  account_wasm_base64: string,
  ledger: { protocol_version: 29, sequence: u32, timestamp: decimal-u64-string,
            base_reserve: u32, min_temp_entry_ttl: u32,
            min_persistent_entry_ttl: u32, max_entry_ttl: u32 } }
```

`request` is the exact typed [preparation request](DRY-RUN-PREPARATION.md), including the fresh
run nonce and generated Wasm in `artifact.claimed_wasm_base64`. Unknown fields are rejected.
The worker derives the suite; callers cannot supply arbitrary cases or previous results.

A wallet first invokes its trusted local binary with the fixed `--prepare` argument and closes
stdin after the job. That mode validates and hashes the immutable job and emits exactly one
`PreparedFrame`; it neither executes Wasm nor requests signatures. The wallet retains this
trusted metadata. Interactive execution of the identical job begins with the same frame,
then emits sequential `sign_request` frames and one final `result`. Every repeated binding
must match the retained preparation frame. Repeats from the executing worker alone are not
an independent source of expected metadata.

`PreparedFrame` contains `binding` (run/job/suite/initialization hashes, source network/protocol/
ledger, account/delegate addresses), `execution_network_id`, account/policy code identities,
local/proposed rule IDs, boundary-case count and the allowed synthetic signature expiry ledger
set. Public Rust wire types are in `execution-runtime/src/{execution,protocol}.rs`.

Every later input or output line is at most 256 KiB; total output is at most 16 MiB. There are
at most 10,000 signature requests. The 120-second worker watchdog also bounds blocked input;
the wallet must independently enforce its deadline, bound stderr and kill the child process
group on cancellation. Each host invocation has a 200-million CPU-instruction and 128-MiB host
memory budget. These local limits are not claims of network transaction feasibility.

Exactly one signature request is outstanding. IDs are sequential canonical decimal strings
starting at `"1"`; a mismatched, repeated or out-of-order response fails. EOF, malformed input,
unknown fields, exceeded limits or child failure yield no usable passing report. The wallet
requires a zero child exit as well as a fully validated final report.

The wallet keeps a registered, controlled delegate key in backend memory and exposes only its
address and opaque capability ID to the UI. The worker receives only the address. An arbitrary
supplied delegate address without a matching capability is unavailable; an owner passkey does
not stand in for the delegate.

## Exact offline-domain encoding

Use the existing canonical-hashing XDR wrapper, with the **fixed ScVal sequence below**, not a JSON hash or a generic JSON-to-ScVal conversion:

```
ScVal::Vec(Some([
  ScVal::U32(2),
  ScVal::String("ozpb:v1:offline-execution"),
  ScVal::Vec(Some([
    ScVal::String(run_hash),
    ScVal::String(job_hash),
    ScVal::String(suite_hash),
    ScVal::String(state_hash),
    ScVal::String(source_network_id),
    ScVal::U32(source_protocol_version),
    ScVal::U32(source_ledger),
    ScVal::String(account_address),
    ScVal::String(delegate_address)
  ]))
]))
```

`execution_network_id` is lowercase hex SHA-256 of that XDR. Hash strings are canonical 64-character lowercase hex; addresses are canonical StrKeys. `job_hash` is the domain-separated canonical hash of the full typed immutable job under `ozpb:v1:native-execution-job`; the wallet obtains it from the fixed trusted local `--prepare` operation and checks every repeated binding. `run_hash` already binds the fresh run nonce, full spec, artifact claims and policy bindings. The runtime and wallet both reject execution-network equality with the source network and with known public/test/future network IDs. The source network is never rewritten inside captured ledger data.

## Signature exchange

Runner line:

```
{"type":"sign_request","request_id":"1","run_hash":"...","case_id":"case:0","delegate_address":"G...","execution_network_id":"...","nonce":"1001","expiration_ledger":123,"account_digest":"...","invocation_xdr":"...","preimage_xdr":"...","digest_hex":"..."}
```

Nonce is canonical signed-i64 decimal text; expiration is u32. Both XDR fields are canonical base64; digest fields are canonical lowercase hex. `preimage_xdr` is the protocol `HashIdPreimage::SorobanAuthorization` with the derived offline network, exact nonce/expiration and `invocation_xdr`. The root must be exactly the candidate account's `__check_auth` with one Bytes argument containing `account_digest` and no subinvocations. `digest_hex` is SHA-256 of the canonical preimage XDR. The wallet independently parses and reconstructs this object, checks all fields, run/case/registered delegate and expiration bounds, and signs only that offline digest. No live-domain signature is accepted here.

Wallet line:

```
{"type":"signature","request_id":"1","public_key_hex":"...","signature_hex":"..."}
```

The runtime checks the public key against the exact delegate, verifies the Ed25519 signature, and then executes the real account authorization. Keys never leave wallet backend memory. Negative cryptographic tests alter a verified signature or local invocation inside the runtime and label that mutation; they do not ask the wallet to sign an unrelated live payload.

The final `result` repeats run/job/suite/state/source-network/execution-network/account/policy bindings, exact host/protocol versions, local state provenance and initial-state hash, case results/error attribution/delta hashes, required coverage and supported scope. This report cannot become full four-layer completion by itself. The wallet rejects any missing/mismatched binding or unsupported/failed case and separately requires captured-target and live-enforcement evidence.

The signature expiry is the derived case ledger plus 64, checked for overflow. Boundary case IDs
are `case:<index>`; controls use `control:signature_bit`, `control:nonce_binding`,
`control:payload_binding`, `control:context_rule_binding` and `control:nonce_replay`.
Stateful checks use `sequence:<index>`, `sequence:partial_rollback` and `sequence:overflow`.
The rule-ID control obtains an offline signature over a digest containing a different rule-ID
vector, then invokes the original candidate rule: the account must reject the digest mismatch.
The partial-rollback control signs the actual two-context rule-ID vector. No control asks for
a signature on a live network or releases bootstrap-owner material to the wallet.

The [offline-domain vector](examples/native-domain-vector.json) includes canonical preimage
bytes and the independently encoded expected hash. `state_hash` commits to the typed descriptor
`{job_hash, local_rule_id: 1, bootstrap_owner, provenance:
"fresh_local_candidate_boundary_states"}`. The bootstrap seed is the canonical hash of the run
hash string under `ozpb:v1:local-bootstrap`; it is deliberately public, for synthetic setup only.
Actual per-case entry hashes are reported separately.

## Validation

`cargo test --manifest-path execution-runtime/Cargo.toml --locked` runs offline framing,
domain and ABI checks. `bash scripts/test-native-execution.sh` reproduces the public account
artifact and a signable generated policy, then requires every actual-Wasm/process test to run.
An operator may supply `OZPB_ACCOUNT_WASM` to reuse an artifact; the runtime still checks its exact
pinned hash. Source reproduction of the account requires the documented aarch64-apple-darwin
build host. The existing nightly source-build gate runs this worker suite as well.

Live-enforcement evidence remains missing, and captured-target evidence is the separate mode
above. This worker is an
incremental execution component; it does not expose the full public `dry_run` operation.
