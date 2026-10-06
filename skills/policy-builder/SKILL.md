---
name: policy-builder
description: >-
  Help a user turn a recorded Stellar authorization into a scoped OpenZeppelin smart-account
  policy. Ask for the grant decisions, use the OZ Policy Builder MCP tools, review the generated
  Rust and labeled evidence, and stop before deployment or installation.
---

# Policy Builder

Use the `ozpb` MCP server for every policy artifact and verdict. You explain the tools' output
and ask for decisions; you do not invent a PolicySpec, edit generated Rust, or infer that an
offline result is safe to install. Discover the server's current tool schemas before calling it.

## Record the authorization

Ask for one of these inputs: a recent executed transaction hash, an unsigned transaction
envelope to simulate, a raw-XDR evidence document, or an existing `RecordingBundle`.
Use `record_transaction` for a hash and `record_simulation` for an envelope. Use
`import_recording` only for the raw-XDR document; its input requires
`network_passphrase`, `envelope_xdr_base64`, and `successful`, with optional result XDR,
result metadata, ledger, and timestamp. If the user already has a `RecordOutput.bundle` or
`RecordingBundle`, put that bundle directly in `SynthesizeInput.bundles`; do not import it
again. Synthesis verifies the bundle's internal consistency and lowers any claimed RPC
trust to `self_supplied`. Ask for the network and RPC source when a network tool needs them;
do not choose an endpoint or trust root on the user's behalf. A simulation is proposed
behavior, not an executed transaction. A raw-XDR import with result XDR can be labeled
`self_supplied` when the result agrees with the claimed outcome; without result XDR it is
`incomplete` and cannot drive synthesis. Treat a server refusal as a refusal and explain
what evidence is missing.

Show the recorded account, target contracts, functions, relevant arguments, observed code
identities, and evidence trust level. If a recording includes several independent calls, explain
that the resulting grants do not enforce their order as a workflow.

## Ask for the grant decisions

Before `synthesize_policy`, ask the user for:

- A grant name and, if the recording has several authorizers, the smart account to constrain.
- The delegate signer identities and predicate (any-of, all-of, or threshold). Never infer a
  delegate from the transaction authorizer.
- An expiration ledger or explicit acknowledgement that the grant has no expiration.
- A call cap or an explicit choice about unrestricted use.
- Whether to compose the reviewed spending-limit policy for a supported SEP-41 transfer;
  if so, ask for its amount cap and period in ledgers.
- Every requested widening beyond the recorded arguments, with its bound, reason, and blast
  radius. Exact recorded values are the default. Ask separately about recipient, amount,
  and unconstrained arguments when relevant; do not widen them together by guess. Function
  names remain exact. To allow another function, obtain a recording of that call; the
  `fn_name` in a widening identifies an observed call and cannot add a function.

`SynthesizeInput.decisions` is an untyped JSON field in the MCP schema. Construct it with
the complete `UserDecisions` encoding below. The values illustrate the shape only; replace
the address, ledger, name, and limits with the user's choices before calling the tool:

```json
{
  "grant_name": "example-grant",
  "delegate_signers": [{ "delegated": { "address": "<user-selected-strkey>" } }],
  "predicate": "any_of",
  "valid_until_ledger": 4260000,
  "no_expiry_acknowledged": false,
  "max_calls": 10,
  "widenings": [],
  "spending_limit": null
}
```

- `delegate_signers` is a nonempty array of `{"delegated":{"address":"<strkey>"}}`.
  External verifier signers are currently refused. Named signer sets remain strict.
- `predicate` is `"any_of"`, `"all_of"`, or `{"threshold":{"n":2}}`, where `n` is
  between 1 and the number of distinct delegates.
- `valid_until_ledger` is a ledger sequence or `null`. For `null`, set
  `no_expiry_acknowledged` to `true` only after the user explicitly accepts no expiry.
  `max_calls` is a positive integer or `null` for an explicitly uncapped grant.
- Each `widenings` entry identifies an observed contract, function, and zero-based argument
  index. Its bound is `{"le_i128":{"max":"100"}}`,
  `{"ge_i128":{"min":"100"}}`, or `"any_value"`; numeric bounds are canonical
  decimal i128 strings and apply only to i128 arguments. `blast_radius` is `"low"`,
  `"medium"`, or `"high"`; `"any_value"` requires `"high"`. A recipient or other
  non-i128 argument can only stay exact or become fully unconstrained.
- `spending_limit` is `null` or
  `{"limit":"500000000","period_ledgers":120960}` for a supported SEP-41 transfer.
  If non-null, also set the outer `SynthesizeInput.spending_limit_capability` to `"pinned"`.
  Never opt in to that policy without the user's decision.

For example, a user-approved numeric widening has this complete shape:

```json
{
  "contract": "<observed-contract-strkey>",
  "fn_name": "<observed-function>",
  "arg_index": 0,
  "bound": { "le_i128": { "max": "100" } },
  "intent": "<user's stated reason>",
  "blast_radius": "medium"
}
```

Put each `RecordOutput.bundle` into the outer `bundles` array, not the whole record output.
Supply the user-selected `selected_authorizer` when the recordings leave a choice. Do not
submit the illustrative values unchanged.

Use the tool's questions and `E_*` errors to resolve remaining decisions with the user. Keep
signer identities, spending limits, and policy composition visible in the proposed grant.

## Check and generate

1. Call `synthesize_policy` with the recording and the user's decisions. Show the resulting
   permissions and rationale before proceeding. If the tool refuses, resolve the named issue;
   never fill in a missing security decision yourself.
2. Call `reference_suite` on the validated spec. This is **layer-1 reference evidence**. Show
   the original permit case, the mutation denials, tested classes, missing classes,
   permit-only classes, and unmodeled reviewed policies. Stop on a disagreement or missing
   required class. Do not call this the full dry-run or claim contract or live coverage.
3. Call `generate_code` for each selected rule and make the complete generated Rust available
   for review. Explain the account, signer, target, tuple, lifetime, and call-cap checks the
   code contains. Do not edit the generated files by hand.
4. Call `verify` with the complete generated non-lock file set, the generated Wasm, and its
   BuildManifest. Report source reproduction, Wasm reproduction, offline behavior, modeling
   limits, and current-network preflight as separate dimensions. A `matches` result describes
   reproduction; it does not establish live readiness or policy coverage beyond what the
   report names.

## Hand off

Summarize exactly what the grant permits, what it does not constrain, the signer and expiry
choices, the evidence trust level, and the limits of the checks that ran. Generated code is a
review artifact, not an installed permission. The current MCP server does not provide a
complete live account authority check or a wallet installation flow. Tell the user that a
trusted live check, wallet review, and their own signature are required before installation.
Do not deploy, sign, submit, or ask for secret keys.
