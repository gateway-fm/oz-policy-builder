# Preparing candidate-bound evidence

`ozpb prepare-dry-run` and MCP `prepare_dry_run` bind one candidate grant to its
deterministic reference cases and reproduced artifact. They return the four named evidence
layers and state exactly which have not executed. This is preparation for a layered dry run,
not the complete `dry_run` operation; `complete` is always `false`.

```sh
ozpb prepare-dry-run \
  --request dry-run-request.json \
  --registry-roots registry-roots.json \
  --registry-min-version 3 \
  --rpc-sources rpc-sources.json
```

The typed `DryRunInput` contains:

- `candidate`: the existing `CheckPolicyCallSurfaceInput`, including the exact spec, rule,
  policy bindings, signed registry, account, network and operator RPC-source name.
- `artifact`: `VerifyInput` for exactly the same spec and rule, with source, Wasm and
  BuildManifest claims.
- `candidate_context_rule_id`: the proposed chain ID, independently of the spec index.
  No live read has established that this is the next ID.
- `run_nonce`: a canonical lowercase 32-byte hex nonce distinguishing this run.

The shells resolve the source through operator configuration; the hosted shell also checks
its endpoint allowlist and reserves shared work capacity. Preparation does not contact that
source. Registry recognition, generated binding reproduction and artifact verification use
the configured build limits. Registry validity is checked again when preparation finishes.
No request field selects a command, builder, endpoint URL, signing key or execution report.

The result includes the complete-request hash, selected-rule suite hash, exact spec/binding/
registry/account/network identities and every bound policy's recognized or reproduced code
hash. These are candidate identities, not live code observations. A changed artifact claim,
nonce, rule ID or RPC-source name changes the run hash. The signed registry and operator
configuration must still be current when later execution starts.

The `reference` layer passes only when its selected-rule cases exist, agree with their
expectations, cover every required boundary class and model every composed policy. A reviewed
policy outside that model yields `unsupported`, even if every generated scope/count case
agrees. Source/Wasm reproduction is reported separately and cannot turn missing runtime
evidence into success.

`account_wasm`, `captured_target` and `live_enforcement` are explicitly `unavailable`.
Preparation runs no full account authorization, target-contract execution or live enforce
simulation. It commits no local or network state, signs nothing and submits nothing.
The absence of those layers cannot be overridden by supplying a caller-written report.

Completing those layers needs an actual execution backend, captured target dependencies and
wallet-owned authorization. An owner passkey is not a delegate signing capability. A wallet
must not substitute its owner key for an arbitrary delegate or present virtual authentication
as human approval. Live authorization must be approved in the wallet before it is exposed to
an RPC: authorization signatures can be replayed until their expiration, independently of an
unsigned fee-payer envelope. Installation preflight alone is not evidence of the candidate
policy's behavior.

The [canonical hashing specification](CANONICAL-HASHING.md) defines both new hash domains.
This preparation package adds no complete acceptance claim.

The separately configured [native execution worker](NATIVE-EXECUTION.md) can produce
local account-Wasm evidence after this preparation. It does not change this operation's
meaning or complete the captured-target and live-enforcement layers. The worker's separate
[captured-target mode](CAPTURED-TARGET-EXECUTION.md) does not either: this operation still
reports `captured_target` as unavailable. The [atomic live-enforcement helper](ATOMIC-LIVE-HELPER.md)
is a tested building block for the live layer only, limited to generated policies with a call
cap; `live_enforcement` stays `unavailable`.
