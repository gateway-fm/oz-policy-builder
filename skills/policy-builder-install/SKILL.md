---
name: policy-builder-install
description: >-
  Hand off a grant the user has confirmed on the policy-builder skill's Confirm-before-deploy
  card: print the ozpb-grant-proposal/v1 artifact for the user's wallet to import, or the
  user-run deploy and unsigned-assembly path. Never deploys, signs or submits.
disable-model-invocation: true
---

# Hand off a confirmed grant

The user started this skill; you cannot start it yourself. It hands off a grant the user has
already confirmed. It never deploys, signs or submits anything, never asks for a secret key, and
does not decide that an installation is acceptable: the wallet that holds the owner key does.

## 1. Check the confirmation

Look back through this conversation. Continue only if all of these hold:

- the last `synthesize_policy` call succeeded, and its spec is the grant being handed off;
- after that call you showed the complete Confirm-before-deploy card for that spec (every
  label of the policy-builder skill's card, with every address and hash in full);
- after that card the user replied `confirm` (or "yes, I confirm");
- nothing changed after the confirmation: no new `synthesize_policy` call, decision, dry-run
  report or authority result.

Otherwise show the card again for the current spec, ask for `confirm`, and wait. Anything other
than an explicit confirmation is not one. An authority refusal on the card stops the handoff
whatever the user replies.

## 2. Choose the path

Use the wallet proposal only when every one of these holds for the confirmed spec:

- it came from `record_transaction` on a confirmed transaction of the user's wallet account,
  on testnet;
- one rule; one delegated `G…` signer; predicate `any_of`;
- an expiry ledger and a call cap of 1 to 10,000 calls (the wallet does not take unlimited
  calls or no expiry);
- every argument constraint is exact (`eq_*`): no widening, no adapter-derived constraint;
- the only policy is the generated scope policy (no spending limit);
- the target is the built-in Stellar Asset contract's `transfer` to a `G…` recipient;
- the grant name is lowercase letters, digits and hyphens, starting with a letter, at most 20
  characters.

No wallet imports `ozpb-grant-proposal/v1` yet: the proposal records the confirmed grant in
the form the wallet integration's planned import takes, and the user-run path in section 4 is
the way to an install draft today. Tell the user so. Also tell them what that import is
designed to require: the account must be the wallet's own account, running the account code the
wallet recognises; it records the transaction again by hash, which works only while RPC still
holds it (a few days); and the expiry must fall within about a day (17,280 ledgers) of the
ledger at import. The wallet decides; a refusal there is final, not something to work around.

For anything else, use the user-run path in section 4.

## 3. The wallet proposal

Print exactly one fenced `json` block in this shape:

```json
{
  "schema": "ozpb-grant-proposal/v1",
  "network_id": "<spec.network_id>",
  "transaction_hash": "<tx_hash of the record_transaction call>",
  "decisions": {
    "grant_name": "<decisions.grant_name>",
    "delegate": "<decisions.delegate_signers[0].delegated.address>",
    "valid_until_ledger": 0,
    "max_calls": 0,
    "unlimited_calls_acknowledged": false
  },
  "expected_grant": {
    "account": "<spec.smart_account.address>",
    "rules": [
      {
        "context": { "type": "<rule.context.type>", "contract": "<rule.context.contract>" },
        "calls": [{ "fn": "<call.fn>", "args": [{ "i": 0, "c": {} }] }],
        "authorization": {},
        "valid_until_ledger": 0,
        "max_calls": 0,
        "policy_kinds": ["<policy kind>"]
      }
    ]
  },
  "spec_hash": "<synthesize_policy spec_hash>"
}
```

Copy every value from the tool calls in this conversation, exactly; never retype one from
memory, shorten it, or fill one in:

- `network_id` and `spec_hash`: the confirmed `synthesize_policy` output.
- `transaction_hash`: the `tx_hash` passed to the `record_transaction` call whose bundle that
  synthesis used, in lowercase.
- `decisions`: the decisions passed to that `synthesize_policy` call. `delegate` is the one
  delegated address; `unlimited_calls_acknowledged` is `false` when the field was absent.
- `expected_grant`: the spec's grant projection. `account` is `smart_account.address`. For each
  rule, in order: `context` is the rule's `type` and `contract` only (no `target_code_hash`);
  `calls` is `allowed_calls` with each call's `fn` and each argument's `i` and `c` only (no
  `prov`, no `justified_by`); `authorization` is the rule's `authorization` unchanged;
  `valid_until_ledger` is `valid_until.ledger` or `null`; `max_calls` is the
  `call_count_per_installation` cap or `null`; `policy_kinds` is each policy's `kind`, in order.

No other field. Then tell the user, briefly, that nothing is installed, and how the planned
wallet import is designed to treat the proposal:

- as untrusted: it records the transaction again through its own RPC, synthesizes again with
  its own toolchain from its own decisions document, compares the grant projection, and
  refuses any difference, any widening and any spending limit. Spec hashes are shown but need
  not match, because two acquisitions can observe different context;
- it shows the delegate, expiry and cap for approval and owns deployment consent, the owner
  signature and submission.

## 4. The user-run path

For a grant the wallet does not take, print these steps for the user to run with their own keys
and tools. You run none of them.

1. Offer to write the confirmed `spec` to `spec.json` unchanged.
2. For each rule `i`: `ozpb generate --spec spec.json --rule <i> --out generated-r<i>`, then
   `ozpb verify` on that output (`docs/DEVELOPERS.md`). In `generated-r<i>/build-manifest.json`,
   `spec_hash` must equal the confirmed spec hash; note its `wasm_hash`.
3. Upload the verified Wasm with the user's own key:
   `stellar contract upload --wasm generated-r<i>/<the .wasm file> --source-account <your key name> --network testnet`.
   The hash it prints must equal `wasm_hash`.
4. Deploy by that hash, so the instance runs exactly the verified code (no constructor
   arguments):
   `stellar contract deploy --wasm-hash <wasm_hash> --source-account <your key name> --network testnet`.
5. A composed spending limit needs an instance of the reviewed policy whose code hash is the
   spec's `capability`, for example `stellar contract deploy --wasm-hash <capability> …` when
   that code is on the network. Its limit and period are set at installation.
6. When the user gives you the deployed addresses, build the binding set
   (`policy-binding-set/v1`: generated policies as `verified_generated_manifest` with their build
   manifest, a reviewed policy as `reviewed_registry`), call `check_policy_call_surface`, and show
   a new Confirm-before-deploy card with its authority list. Only after the user confirms that
   card, call `assemble_install_transaction` with the user's fee payer, fee ceiling and a validity
   window of at most 120 ledgers.
7. Read its `restoration` field first. `separate_transaction_reassemble_required` means the
   response holds only a restore transaction, not an installation: after the user's wallet has
   run that restoration, the authority check and assembly start again, with a new card. For
   `none` or `automatic_within_invocation`, the unsigned XDR is an installation draft for a
   wallet, not something to sign as is: it carries the owner's authorization unsigned, as
   recorded. A wallet must validate every field, recheck authority, build the owner
   authorization and enforce-simulate before signing (`docs/INSTALL-ASSEMBLY.md`);
   `stellar tx sign` alone does none of that. Say so, and stop.
