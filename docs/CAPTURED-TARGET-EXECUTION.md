# Captured native target execution

The `captured_target` layer runs the candidate's exact native Stellar Asset Contract (SAC)
transfer through the pinned account Wasm and the generated policy Wasm, against target ledger
entries captured from an RPC endpoint. It extends the
[native execution worker](NATIVE-EXECUTION.md): the candidate installation is the same fresh
local state, the target state is byte-exact captured data, and the protocol-29 host executes
the real built-in SAC. It is an offline
counterfactual. It is not a historical replay, an owner-authority check, a fee, reserve or
resource check, or live-network acceptance, and its result is always `complete: false`.

## Supported scope

The native worker's scope applies (the selected rule only, with one delegated Ed25519 G signer
and exactly one generated policy). In addition the rule must have exactly one allowed call, `transfer(SELF, recipient,
amount)` on the source network's native SAC, with the amount fixed by `eq_i128`. The captured
call must be exactly the candidate's derived original call: the candidate account as sender, an
existing G recipient, and a positive amount below `i64::MAX`. Other targets, functions, argument
shapes, signer configurations and policy compositions are refused, never approximated.

Three cases run, each from identical initial state at the capture ledger `L`:

| Case ID | Call | Required outcome |
|---|---|---|
| `target:original:0` | the captured call | success |
| `target:argument-denial:0` | amount + 1 | generated-policy error 6 |
| `target:empty-signers:0` | the captured call, no authenticated signer | generated-policy error 1 |

When the rule has a call cap, the candidate counter is seeded at 0. That seed is synthetic and
reported. An uncapped rule's policy defines no counter, which is then neither seeded nor read.
Counter boundaries, validity windows and cryptographic controls remain the account-Wasm layer's
responsibility.

## Capture

`ozpb_source_rpc::capture_native_target` takes an unsigned envelope with no authorization
entries. A record-mode `simulateTransaction` discovers the authorization root and footprint;
recording mode records the authorization a call needs instead of enforcing it, so its success is
acquisition only, never evidence that a policy permits the call. Exactly one root, for the
account, equal to the call with no sub-invocations, is accepted. A restoration preamble is
refused rather than performed.

A record-mode footprint also names the account's own instance and code and the recorded
authorization's fresh nonce. The nonce key is new by construction and is not read. Instance
and code are read only to bind `account_code_hash`, the Wasm hash the account executed at `L`;
neither becomes a target entry, and a footprint touching other account storage is refused.
Every remaining key and the network's state-archival configuration are read in one bounded
`getLedgerEntries` call. Each must be returned, decode, match its key, be modified no later
than `L` and, for contract entries, live beyond `L`: any submission based on the capture lands
at `L + 1` or later, where an entry living only until `L` is archived. Entries are re-encoded
canonically, so a non-canonical encoding is normalised rather than refused. An omitted key is
refused because the endpoint does not distinguish absence from archival. `getLedgers` supplies
the header for exactly `L`; its canonical bytes must hash to the hash reported beside it and
state the sequence, protocol 29 and close time. That proves only that the header is
self-consistent: it is not chained to other ledgers or tied to the entries, and whoever builds
a job could recompute it. If the simulation and the entry read report different ledgers the
capture retries once, then fails.

The capture's provenance is `rpc_reported`: an endpoint's answer, not an inclusion proof. RPC
also returns each entry's outer `LedgerEntry` extension (`extXdr`, including any sponsor ID).
It is not captured; the runtime rebuilds it as V0 without claiming it was V0 on the network.
For the supported C-to-G native transfer, the SAC reads liabilities and sponsorship counts from
inside the captured `AccountEntry`; the omitted outer sponsor ID does not decide this call. The
fixture capture carries nontrivial liabilities and sponsorship counts for that reason.

[Recorded testnet responses](../crates/source-rpc/tests/captured-testnet/target-capture/) for
one transfer from the public Pollywallet sample account replay through the real capture code.
The only edit to them is dropping `getLedgers`' unused `metadataXdr`.

## Producing a capture

`ozpb capture-target` and the MCP tool `capture_target` run this capture through an
operator-configured RPC source and return the `TargetCapture` unchanged: it is the `capture` of
a `CapturedTargetJob`. The request names the source and its network and carries the unsigned
envelope; it never carries a URL.

```bash
cat > capture-request.json <<'JSON'
{"network_id": "<hex network ID>", "rpc_source": "testnet",
 "envelope_xdr_base64": "<unsigned envelope>"}
JSON
ozpb capture-target --request capture-request.json --rpc-sources rpc-sources.json > capture.json
```

The source map is the one the authority commands read: `--rpc-sources` or
`OZPB_RPC_SOURCES_FILE` for the CLI, `OZPB_RPC_SOURCES_JSON` for the MCP server, each
`{"<name>": {"rpc_url": …, "network_passphrase": …}}`. The named source must be for the
request's network. A hosted MCP server also requires the source's URL on `OZPB_RPC_ALLOWLIST`
and runs one read through an operator source at a time.

The envelope is confidential input (architecture §6.5). The CLI reads it from a file, so it
stays out of process arguments. It reaches the configured endpoint and, over MCP, the
conversation and the server carrying the request; prefer the CLI or a local stdio server. No
result or error echoes it: refusals of its shape are fixed descriptions, and endpoint errors keep
their code but lose the endpoint's text, because after simulation the endpoint holds the
envelope and could quote it in any later reply. The capture itself repeats the call (account,
recipient and amount), so it is as confidential as the envelope.

Only the shape above is captured. The refusals:

| Refusal | When | Code |
|---|---|---|
| larger than the XDR size bound | before any request | `E_RESOURCE_LIMIT` |
| not one unbroken, canonical base64 XDR envelope | before any request | `E_ENVELOPE_PARSE` |
| signed; carrying authorization entries; not one v1 `InvokeHostFunction` operation without a memo; or any call other than the native SAC's `transfer(contract account, G recipient, amount)` with `0 < amount < i64::MAX` | before any request | `E_UNSUPPORTED_ENVELOPE` |
| a source name that is not configured | before any request | `E_RPC` |
| a source configured for another network | before any request | `E_NETWORK_MISMATCH` |
| hosted server: the source's URL is not on `OZPB_RPC_ALLOWLIST` | before any request | `E_RPC` |
| hosted server: another read through an operator source is running | before any request | `E_RESOURCE_LIMIT` |
| the endpoint reports another network | during the capture | `E_NETWORK_MISMATCH` |
| any answer the capture above refuses: a failed, non-void or restoring simulation; an authorization root other than exactly the account's transfer; other account storage in the footprint; a missing, archived or expiring entry; an inconsistent header or archival configuration; ledgers that kept changing; or an unreachable or refusing endpoint | during the capture | `E_RPC` |
| MCP server, stdio or hosted: not finished within 300 s | during the capture | `E_RESOURCE_LIMIT` |

The CLI sets no overall deadline: each of its at most eight requests is bounded by the
transport's 30 s timeout. On an MCP server the 300 s deadline ends the wait, not the read; a
hosted server's slot stays held until the read itself stops.

Producing a capture does not run this layer. No CLI or MCP command runs it yet, and
`prepare_dry_run` still reports `captured_target` as unavailable.

## Preparation

`--prepare-captured` reads one `CapturedTargetJob` (`{schema: 1, native: NativeJob, capture:
TargetCapture}`), applies every native preparation check, then requires:

- the capture network and ledger to equal the job's, and the header's protocol, close time and
  base reserve and the archival configuration's TTL bounds to equal the job's ledger fields;
- `account_code_hash` to be the pinned account Wasm, which is what the candidate runs;
- the captured call, rule, recorded authorization root and footprint to have the supported shape;
- the footprint to be exactly the SAC instance (read-only) and the sender balance and recipient
  account (read-write), the SAC instance to be the built-in asset executable, and every entry to
  be canonical, modified no later than `L` and, for contract entries, live beyond `L`.

The candidate is then installed once over a source that refuses any target key; the hash of the
resulting candidate state is bound, and any overlap with captured keys is refused. The binding
reuses the native `run_hash` and commits `job_hash` (`ozpb:v1:captured-target-job`),
`suite_hash` over the three planned cases (`ozpb:v1:captured-target-cases`), and `state_hash`
over the capture hash (`ozpb:v1:target-capture`), candidate state hash, local rule ID and
bootstrap owner (`ozpb:v1:captured-initialization`), with `source_ledger = L`. The execution
network derived from that binding is therefore distinct from the native layer's.

The prepared frame adds `layer: "captured_target"`, the capture and candidate state hashes,
the target contract, `observed_ledger`, `case_ids`, `signing_case_ids` (in request order) and
the single signature expiry `L + 64`. The wallet retains it as trusted metadata, as for the
native worker.

## Execution

`--captured` emits the identical prepared frame, then one `sign_request` per signing case in
the native worker's [format](NATIVE-EXECUTION.md#signature-exchange), then one `result`. For each
case the candidate is reinstalled and must reproduce the prepared candidate state hash. Target
entries are served byte for byte by a strict snapshot source. Once the candidate is installed,
only captured keys and that case's exact new nonce keys (account nonce `100 + case index`,
delegate nonce `1000 + request number`) are answerable; a read of any other uncached key is a
host error and is logged, and the log survives the host's rollback of a failed call.

The account's authorization entry has the exact target call as its root, an `AuthPayload` naming
the delegate and local context rule 1, and expiry `L + 64`. The delegate signs only the
account's `__check_auth(account_digest)` over the offline network. The built-in SAC executes at
its captured source-network address.

The original agrees only if the transfer succeeds; the sender's SAC balance falls and the
recipient's native balance rises by exactly the amount; a configured counter advances by one;
data changes only on captured read-write keys and the counter; exactly the two expected nonce
keys appear; TTLs only grow, within `L + max_entry_ttl - 1`; nothing is removed; and no
undeclared read occurred. A denial agrees only if the call fails, the generated policy's
diagnostic error event carries the expected code and is attributed to the policy contract, and
the complete state, including balances, counter and nonces, is unchanged. The host returns only
a generic context error for every authorization failure, so attribution comes from the policy's
diagnostic event, never from the top-level error. A target refusal, such as an insufficient
captured balance, therefore fails the original instead of passing as a policy decision.

The report repeats the bindings and lists, per case, the captured keys read, created, written
and TTL-extended keys, undeclared reads, unexpected changes, balance deltas, counter values and
before/after hashes of the logical ledger (captured entries overlaid by host storage).

## Not established

Owner authority, installation, fees, reserves and network resource limits are outside this
layer. Source-network-dependent target behavior is not modeled: the execution network is a
per-run offline domain. Generic captured Wasm targets, other assets and multi-call sequences are
unsupported. `prepare_dry_run` still reports `captured_target` as unavailable, and a passing
report cannot authorize submission; only the separately approved live-enforcement path obtains
live authorization after owner consent.

## Validation

`cargo test --manifest-path execution-runtime/Cargo.toml --locked` runs the strict-source and
change-classification unit tests and argument refusal. `cargo test -p ozpb-source-rpc` replays
the recorded testnet capture and the mocked refusal cases, including endpoint replies that quote
the envelope. `cargo test -p ozpb-cli --test capture_target_cli` and
`cargo test -p ozpb-mcp-server --test mcp_stdio_capture` replay the same recorded responses over
a local HTTP endpoint through each shell's operator source configuration. `bash scripts/test-captured-target.sh`
generates four real policies and requires every actual-Wasm test to run and pass: the fixture
capture (a real SDK-29 SAC deployment built locally), the same with an uncapped rule, a capture
whose sender cannot cover the amount, a rule paying the delegate itself (refused as overlapping
candidate state), twenty preparation refusals including re-hashed headers that describe another
ledger, the recorded testnet capture replayed offline, and the full process protocol. The
nightly pinned-account gate runs it. Refresh the recorded responses deliberately with
`cargo test -p ozpb-source-rpc --test target_capture_conformance -- --ignored`.
