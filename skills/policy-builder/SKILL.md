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
envelope to simulate, or a recording bundle. Call `record_transaction`, `record_simulation`, or
`import_recording` accordingly. Ask for the network and RPC source the tool needs; do not choose
an endpoint or trust root on the user's behalf. A simulation is proposed behavior, not an
executed transaction. An imported bundle is self-supplied evidence, even if it claims stronger
trust. Treat a server refusal as a refusal and explain what evidence is missing.

Show the recorded account, target contracts, functions, relevant arguments, observed code
identities, and evidence trust level. If a recording includes several independent calls, explain
that the resulting grants do not enforce their order as a workflow.

## Ask for the grant decisions

Before `synthesize_policy`, ask the user for:

- The delegate signer identities and predicate (any-of, all-of, or threshold). Never infer a
  delegate from the transaction authorizer.
- An expiration ledger or explicit acknowledgement that the grant has no expiration.
- A call cap or an explicit choice about unrestricted use.
- Every requested widening beyond the recorded arguments, with its bound, reason, and blast
  radius. Exact recorded values are the default. Ask separately about recipient, amount,
  function, and unconstrained arguments when relevant; do not widen them together by guess.

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
