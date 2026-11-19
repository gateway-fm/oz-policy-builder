# Scoping decisions

A generated grant permits exactly the calls you recorded, for exactly the signers you name, until
you decide otherwise. This page lists every decision that changes that, what each one means for
safety, and how the agent skill asks for it. The mechanism is
[DEVELOPERS.md §2](DEVELOPERS.md#2-how-the-synthesizer-decides-scope); the design is
[architecture §4.3](architecture.md#43-synthesizer-cratessynthesizer) and
[§6.1](architecture.md#61-what-is-actually-guaranteed-authorization-minimal-vs-effect-minimal).
The decisions travel as one `UserDecisions` document (`crates/synthesizer/src/lib.rs`);
[`docs/examples/decisions.json`](examples/decisions.json) is a complete one.

## The default: exact

- Every recorded argument becomes a deep exact-equality constraint on the whole call: the same
  contract, function, argument count and values. An address equal to your account becomes `SELF`,
  so the policy is not tied to one account's address.
- Function names are always exact. To allow another function, record a call to it; a widening
  cannot add one.
- Several recorded calls become independent permissions. Their order and atomicity are not
  enforced, and the spec says so.
- Nothing widens by inference. The type of an argument never decides a direction: lowering a
  swap's minimum output makes it *less* safe, so no bound is ever guessed.

Exact means *authorization-minimal*: the narrowest grant over what the account's `__check_auth`
can see. It is not *effect-minimal*. A rule binds the target's address, not its code, so an
upgraded target can make the same permitted call do something else
([trust boundaries](TRUST-BOUNDARIES.md)).

## Decisions with no default

Synthesis refuses until each is answered. A missing one is an `E_NEEDS_DECISION` finding; a
contradictory pair (a cap *and* the unlimited acknowledgement, an expiry *and* the no-expiry
acknowledgement) is an `E_INVALID_DECISION` finding, reported under `E_SPEC_INVALID`. Every
finding is listed in the refusal's `details`.

| Decision | Fields | Safety meaning |
| --- | --- | --- |
| Who may act | `delegate_signers` (one or more `{"delegated": {"address": "G…"}}`), `predicate`: `any_of`, `all_of` or `{"threshold": {"n": N}}` | The policy checks it before it looks at the call. It is never inferred from the account that signed the recording. Named signer sets are strict: a signer added to the rule later does not widen the grant. External-verifier signers are refused. |
| How long | `valid_until_ledger`, or `no_expiry_acknowledged: true` | A ledger number, not a time. No expiry is a high-blast-radius choice and is shown as one. |
| How many calls | `max_calls`, or `unlimited_calls_acknowledged: true` | Counted per installation: reinstalling starts a new count. Unlimited is high blast radius. |
| Which account | `selected_authorizer`, in the synthesis request: over MCP only when a recording has several authorizers; on the CLI `--selected-authorizer` is always required | Must be a recognized smart account; an ordinary `G…` account is refused. |
| A name | `grant_name` | Names the context rule. |

## Widenings you may choose

A widening loosens one argument of one recorded call. Each names `contract`, `fn_name`,
`arg_index`, a `bound`, your `intent` in words and a `blast_radius` (`low`, `medium`, `high`), and
the spec carries it as `user_widened` provenance with that intent and rating.

| Bound | Accepts | Applies to |
| --- | --- | --- |
| `{"range_i128": {"min": "M", "max": "N"}}` — a range, the recommended form of "up to N" with M = 0 | every value from M to N, both included; the generated policy refuses everything else, negatives included | `i128` arguments |
| `{"le_i128": {"max": "N"}}` — a cap | every value ≤ N, negatives included; only with `"no_floor_acknowledged": true` beside it ([below](#open-question-negative-values-under-a-cap)) | `i128` arguments |
| `{"ge_i128": {"min": "N"}}` — a floor | every value ≥ N, such as a swap's minimum output | `i128` arguments |
| `"any_value"` | anything at that argument | any argument; requires `blast_radius: "high"` |

- An address or other non-`i128` argument stays exact or becomes `any_value`; a numeric bound on
  it is refused.
- A widening that matches no recorded argument it can apply to is refused, not ignored, and so
  is a numeric bound that excludes the recorded value: a widening loosens the recorded call and
  cannot refuse it.
- One argument carries one constraint: to bound both ends, use a range, not a cap and a floor. A
  decisions document that widens the same argument (contract, function and index) more than once
  is refused with an `E_INVALID_DECISION` finding naming it, rather than applying one bound and
  dropping the others.
- A range needs development registry version 7 or later, whose template entry declares
  `range_i128`; under an older snapshot synthesis refuses it (`E_UNSUPPORTED_PATTERN`, naming the
  kind).

## Composing the reviewed spending limit

`spending_limit: {"limit": "N", "period_ledgers": P}` adds OpenZeppelin's reviewed spending-limit
policy, recognized by its exact Wasm hash, to a supported SEP-41 `transfer` rule: the total
transferred within a rolling window of P ledgers stays at or below N, across calls. It is
configured, not generated. It also needs the capability named: `"pinned"` (or that policy's exact
Wasm hash) in `spending_limit_capability` over MCP, or `--spending-limit-capability` on the CLI.
Validation refuses a composition whose amount constraint admits no non-negative amount within the
limit. The [SEP-41 walkthrough](WALKTHROUGH-SEP41.md) composes one.

## Bounds an adapter derives

The one way a bound enters without your decision: a reviewed target adapter, bound in the signed
registry to the target's exact code hash, declares which direction is safe for an argument. The
Soroswap router adapter caps the input amount at the recorded value and keeps everything else
exact ([TARGET-ADAPTERS.md](TARGET-ADAPTERS.md)). The constraint carries `adapter_derived`
provenance and holds only while the target's code hash matches; an `any_value` from an adapter is
listed as high blast radius on the card like your own. Without a binding, synthesis stays exact.

## Open question: negative values under a cap

A cap (`le_i128`) admits every smaller value, negatives included: the generated check refuses only
values above the maximum, and an `i128` is signed. The generated scope policy does not refuse a
negative amount on its own and leaves it to the target contract to refuse. OpenZeppelin's v0.7.0
audit finding L-06 is about the same assumption in their spending-limit policy, which upstream
fixed in the policy.

So a cap you add is a question, not a default. Synthesis does not add a floor of zero, which would
infer a direction from the type. The way to close it is to state the floor: a range
(`range_i128`, say `0..=N`) is checked at both ends by the generated policy, needs no
acknowledgement, and is what the skill offers first. A cap without a floor stays available as an
explicit choice: it is refused with an `E_NEEDS_DECISION` finding until its widening carries
`"no_floor_acknowledged": true`, your statement that negative amounts pass the generated policy;
absent reads as `false`. The rationale repeats the acknowledgement for each cap and names what does
refuse a negative amount: the composed spending limit for a transfer amount it reads, otherwise
only the target. On a range, a floor or `any_value` the acknowledgement is refused as an
`E_INVALID_DECISION`. A cap an adapter derives for a maximum-input role carries no acknowledgement:
it is the adapter's reviewed claim about that target's code. It too sets no floor, and the
rationale says so in the same words.

What is established here: the evaluator's spending model never permits a negative amount, and a
spending-limit composition must admit a non-negative amount. What is not: that every target
refuses a negative amount, or that accepting one would be harmful for a given target. Exact grants
are unaffected, and so are ranged ones. What stays open for the security audit is the cap an
acknowledgement or an adapter leaves without a floor: whether relying on the target there is
acceptable ([AUDIT-SCOPE.md](AUDIT-SCOPE.md#prior-relevant-findings)).

## How the agent skill asks

The [`policy-builder` skill](../skills/policy-builder/SKILL.md) asks before it calls
`synthesize_policy`, and never fills in a security decision itself:

1. It asks for the grant name, the delegates and predicate, an expiry or an explicit "no expiry", a
   cap or an explicit "unlimited", whether to compose the spending limit, and every widening —
   recipient, amount and other arguments separately, never together by guess. When you cap an
   amount it offers "between 0 and X" (a range) first, and a cap with no floor only as the
   alternative you explicitly accept.
2. It restates the complete decisions — every delegate address in full, each widening as
   `Widen <contract>.<function> arg[<index>] to <bound>; blast radius: <…>; reason: <…>.`, a range
   as `>= min and <= max`, a cap accepted without a floor as `<= value, no floor` — and synthesizes
   only after a reply that just accepts them. A reply that accepts and adds anything is answered and restated.
3. On a refusal it asks about exactly the findings named in `details`.
4. The **Confirm before deploy** card lists under **High blast radius** every `any_value`
   argument, every widening you rated `high`, no expiry and no cap.

When the grant is meant for the wallet integration, the skill says so while asking, because the
wallet accepts one narrow grant shape, with no widening and no spending limit
([importing a proposal](POLLYWALLET-INTEGRATION.md#importing-an-agent-proposal),
[direct handoff](AGENT-WALLET-HANDOFF.md)).

With the CLI you write the decisions file yourself and pass it to `ozpb synthesize --decisions`;
the same refusals apply.
