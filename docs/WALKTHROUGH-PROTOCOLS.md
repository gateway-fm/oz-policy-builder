# Protocol walkthroughs: W3 Soroswap and W1 Blend

These harness modes take a real protocol call by a fresh pinned smart account through the same
record → synthesize → reference-suite → generate → verify chain as
[W2](WALKTHROUGH-SEP41.md), then install each synthesized rule separately and exercise it.
They are controlled testnet runs with throwaway keys or an exportable virtual passkey. They do
not establish a wallet's protected human approval.

**Status.** W3 is executable through `run.sh`. A controlled run on 20 October 2026 completed every
step below; an earlier run that day predates the two transfer-rule denials
([section 9 of the testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md#9-controlled-soroswap-swap-runs-20-october-2026)).
A run on 22 October 2026 repeated every W3 step with the [derived denials](#derived-denials) and
passed ([section 13](TESTNET-EVIDENCE-TRANCHE-2.md#13-controlled-soroswap-swap-run-with-derived-denials-22-october-2026)).
Those runs used widenings the harness wrote itself. W3 now takes the router's input bound and
open deadline from the registry's reviewed adapter, the floor and transfer cap from an operator
decisions file, and adds route, recipient and function controls. The adapter binding is a
development-registry assertion, and the router's Wasm was not reproduced from source
([target adapters](TARGET-ADAPTERS.md#the-testnet-router-binding-development-registry-version-4)). No live run has exercised that yet.
W1 is executable through `run.sh`: it opens the bounded USDC supply its claim is earned on and
withdraws it before the keys are discarded (see [W1](#w1-blend)). A controlled run on 21 October
2026 completed every W1 step after four stopped attempts
([section 10 of the testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md#10-controlled-blend-claim-run-21-october-2026)).
A run on 22 October 2026 repeated every W1 step with the [derived denials](#derived-denials) and
passed ([section 12](TESTNET-EVIDENCE-TRANCHE-2.md#12-controlled-blend-claim-run-with-derived-denials-22-october-2026)).

## W3 Soroswap

```bash
OZPB_HARNESS_WALKTHROUGH=soroswap \
OZPB_HARNESS_AUTHORITY_CHECK=cli \
OZPB_HARNESS_CONFIRM=operator \
OZPB_SOROSWAP_DECISIONS=testnet-harness/soroswap-decisions.json \
bash testnet-harness/run.sh
```

It needs the same authority-check configuration as W2
([harness README](../testnet-harness/README.md#the-wallet-decision-on-the-authority-check)).
`OZPB_HARNESS_CONFIRM=operator` is required: each rule gets its own authority check, and
operator mode approves them without a terminal prompt. `OZPB_SOROSWAP_DECISIONS` names the
operator's decisions file (below), a regular file; a relative path is read from the repository
root. Without it the run stops before setup.

### The recorded call and its decisions

`soroswap-preflight.mjs` first reads the operator's decisions file and journals it in the plan
(`operator_decisions`, with the file's SHA-256):

```json
{
  "schema": "ozpb-soroswap-operator-decisions/v1",
  "output_floor": { "min": "100000", "intent": "…" },
  "transfer_cap": { "max": "1000000", "intent": "…" },
  "adapter_deadline": "accept_any_value_high_blast_radius"
}
```

It refuses any other key, a floor below 2 (its control lowers it by one), a transfer cap below the
fixed input or above 10 000 000, a missing intent, and anything but that exact deadline
acceptance. The committed `testnet-harness/soroswap-decisions.json` holds the values of the
earlier runs.

It then re-reads the pinned router's code, its factory and the native-XLM →
`CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F` pair, the pair's tokens and
reserves, a live quote and the account's balance. It refuses a changed router or factory code,
a different pair, empty reserves, a quote below the floor, or too little balance for two swaps.
The expected identities are the constants in `testnet-harness/scripts/protocol-calls.mjs` and
`soroswap-preflight.mjs`; the pair's code is compared with this run's own preflight observation
before every later call.

The owner then calls `swap_exact_tokens_for_tokens` once through the account's owner rule
(ID 0) with these values. They are test decisions, not a price oracle or a slippage policy:

| Value | Decision |
| --- | --- |
| Input | 1 000 000 base units of native XLM (0.1 XLM), fixed by the harness. |
| Output floor | The operator's `output_floor.min`, an absolute amount of the output token, checked against the live quote. |
| Transfer cap | The operator's `transfer_cap.max`, at least the input. |
| Route | Exactly `[native, output token]`; recipient is the account itself. |
| Deadline | Preflight time plus one hour in the recorded call. The adapter then leaves it open. |
| Grant | 180 ledgers after the recorded ledger, one call per rule. |

The run requires a confirmed nonzero output and an equal balance increase before recording.

### Two independent rules

The account authorizes two contexts for the swap: the router call and the native-SAC
`transfer` from the account to the pair. Synthesis therefore produces two rules from one
complete spec. This document names them by role, because the account numbers rules itself
(its owner rule is ID 0, and each installed rule gets the next free ID):

- **Router rule** (spec index 0): input at most the recorded amount, output at least the
  operator's floor, the exact route and recipient, and **any deadline**.
- **Transfer rule** (spec index 1): at most the operator's transfer cap, from the account to the
  exact pair.

The router rule's input bound and open deadline are `adapter_derived`. Synthesis takes them
from `soroswap-router@1`, which the committed development registry (version 4) binds to the
router's exact code. That binding is a development-registry assertion, not governance, and the
router's Wasm was not reproduced from source ([target adapters](TARGET-ADAPTERS.md#the-testnet-router-binding-development-registry-version-4)).
The harness writes only the operator's two decisions into the synthesis inputs, as
`user_widened` with their intents: the output floor and the transfer cap. `protocol-synthesis.mjs`
refuses a synthesized spec whose router input bound or deadline did not come from that adapter
and that code hash, or whose router hash is not `adapter_required` with `refuse` on drift. The
Blend pool's hash stays an `evidence_only` observation; it has no adapter.

**The open deadline is high blast radius.** A delegate may name any deadline, including one that
never passes, so the router's own time check no longer limits when the swap executes; the rule's
expiry and each signature's own expiry ledger still do. Synthesis says so in its rationale, the
pipeline record flags it, and the operator's decisions file must accept it explicitly.

The rules are independent capabilities, not an atomic workflow. The transfer rule alone lets the
delegate move up to the operator's `transfer_cap` to the pair. **XLM sent to the pair that way is
lost to the account:** a direct transfer is not a swap, and the pair's surplus balance can be taken
by anyone. A cap equal to the recorded input is a `medium` blast-radius decision; a cap above it
grants transfer authority the swap never used, and synthesis records it as `high`.
The controls observe that authority only by simulation (`independent_token`), never by submitting
it, and then check that the transfer rule's own policy still bounds it. Rule IDs are signed in the
account's context order, router first. The harness's `protocolInputs` refuses a recorded call
whose rule order would not put the root invocation first, and `validateProtocolSynthesis`
refuses a synthesized spec whose rules come in any other order.

### Installation

`bundle-command.mjs install` uploads, deploys and installs each generated policy in turn. Every
authority request carries the bindings of all rules, so each rule's answer covers every bound
policy; each owner-signed `add_context_rule` must still equal that rule's approved intent. Each
transaction hash is journaled before submission; a pending or ambiguous step is never retried. An
interrupted bundle is recorded as `incomplete`, not as a partial success. Each rule's authority
answer (commitment, check and pre-sign recheck ledgers) and its install-time readback are kept
in the journal and exported. `bundle-command.mjs inspect` reads both rules back again.

### Derived denials

After `bundle-command.mjs inspect` and before any delegated call, `derived-denials.mjs` replays
the spec's own layer-1 suite against both installed rules
([harness README](../testnet-harness/README.md#derived-denials)). Each rule's recorded call must be
permitted in simulation: the router rule's swap with its transfer child signed for both rules,
and the transfer rule's direct transfer. Then every live-realizable deny case is replayed in
suite order. For the W3 spec that is ten cases, five per rule:

- input above the cap and output below the floor on the router rule (`#6`);
- the transfer rule's cap and a stranger recipient (`#6` from the transfer rule's own policy);
- for each rule, an empty signer set (`#1`), an unrecognized signer and the delegate plus an
  unrecognized signer (the account's `3016`).

The route mutation replaces a `Vec` with a bool, which the router's argument decoding rejects
before authorization. It stays offline with the other listed classes. So do the `to` mutation,
which moves the authorization off the account, and the suite's undeployed contract and absent
function, which have no live equivalent here. The adapter leaves the deadline open, so the suite
has no deadline denial; its cases for the deadline expect a permit and are not replayed. The
section 13 run predates the adapter and replayed the same ten denials against an exact deadline.

**Passing.** A W3 or W1 report passes when the recorded calls are permitted and at least five
derived denials from that spec's suite are refused by the predicted enforcer. That means the
confirmed delegated positive, plus the suite's originals permitted in simulation, plus denials
identified by the suite hash. All of these are enforcing simulations after installation, at their
reported ledgers; nothing is submitted. The hand-written controls below do not count toward the
five. **Status:** both passed live on 22 October 2026: W1 at exactly the minimum of five denials
([section 12 of the testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md#12-controlled-blend-claim-run-with-derived-denials-22-october-2026)),
W3 with ten ([section 13](TESTNET-EVIDENCE-TRANCHE-2.md#13-controlled-soroswap-swap-run-with-derived-denials-22-october-2026)).

### Required observations

All negative controls are enforcing simulations: nothing is submitted, even after an unexpected
permit. With both rules selected, the router rule's generated policy is the first enforcer
reached for tuple, signer and count failures; the transfer-rule controls select that rule alone.

Route, recipient and function controls are signed over a tree the harness builds, without
recording the call first, so they do not depend on whether the router could quote, fund or
accept it: a truncated route cannot be quoted, and a recording of a foreign-recipient swap would
name that recipient, not the account. A tampered route keeps the recorded transfer child, as a
delegate would sign the whole tree. The account decides each one when the router first asks `to`
to authorize, before it reads the route. The journal and the export mark these invocations
`signed_without_recording`; every other one is `recorded`.

| Control | Required evidence |
| --- | --- |
| Input above the adapter's bound | Router-rule policy refusal `#6`. |
| Output one below the operator's floor | Router-rule policy refusal `#6`. |
| Route reordered, extended, truncated | Router-rule policy refusal `#6` for each: `[output, native]`, `[native, output, native]`, `[native]`. |
| Foreign recipient | Refused before the account is asked: the host reports the recipient's missing authorization (`Unauthorized function call for address`) and no account authentication failure. The router asks `to`, and only `to`, to authorize and takes the input from it (`SOROSWAP_FOREIGN_RECIPIENT` in `protocol-invoke.mjs`, a contract address derived from a label). |
| Another router function | `swap_tokens_for_exact_tokens` by the account for the same route, signed for the router rule alone: `FunctionNotAllowed` (`#5`). |
| Any deadline | The largest `u64` deadline is **permitted** in simulation, signed for five ledgers only. This is the disclosed high-blast-radius authority, not a denial. |
| Wrong signer | The account's `UnauthorizedSigner` (`#3016`). |
| Empty signer set | Router-rule policy `ZeroSigners` (`#1`). |
| Direct transfer to the pair | The transfer rule alone permits it in simulation; this is the disclosed independent authority. |
| Direct transfer one above the operator's cap | Transfer-rule policy refusal `#6`. |
| Delegated swap | Confirmed transaction, nonzero output and matching balance increase. |
| Repeat swap | Router-rule policy `CallCountExceeded` (`#7`). |
| Direct transfer after the swap | Transfer-rule policy `CallCountExceeded` (`#7`): the swap's transfer context spent its one call. |
| Expired rule | After the ledger passes the grant expiry, the account's `UnvalidatedContext` (`#3002`); expiry is checked before any policy runs, so the spent count cannot mask it. |
| Removal | Owner-signed removal of each rule through the owner rule, event, absent readback and policy cleanup. |
| After removal | The account's `ContextRuleNotFound` (`#3000`). |

Before expiry, every observation must be at or below the expiry ledger; the expiry control must
be above it. An observation on the wrong side fails the run. Ledger waits are bounded, and
elapsed wall-clock time never stands in for a ledger.

On failure after installation, the wrapper runs `protocol-finish.mjs` before discarding keys.
It removes each rule whose installation was confirmed, with the same bounded child process and
termination handling as W2's failure cleanup. The child's output goes to a new private
`cleanup-child.log` in the run directory: transaction hashes and, on failure, the failing stage
and a message with the run's secrets redacted. A removal that was prepared or sent is never
resubmitted. Its hash is reconciled instead, after the network check. If it landed, it is
verified like any confirmed removal and marked `reconciled`. If it failed, or the endpoint has not
seen it although its latest ledger closed after the validity window and it retains the window's
start, it is kept by hash and one fresh removal may follow, never a third. Otherwise it stays pending and the cleanup
is `incomplete`. An attempt that prepared nothing may be retried. Removal readbacks count only
from an endpoint at or after the removal's ledger. Before signing any removal, the
network must be testnet and the account must still run the pinned code, whose rule IDs are never
reused; otherwise nothing is signed. A rule whose grant or policy readback no longer matches is
then still removed by the ID from its confirmed install. A rule whose installation was never
confirmed is reported as uncertain rather than inferred. An unreadable journal makes the final
cleanup `incomplete`, so the wrapper warns that grants may remain.

## W1 Blend

```bash
OZPB_HARNESS_WALKTHROUGH=blend \
OZPB_HARNESS_AUTHORITY_CHECK=cli \
OZPB_HARNESS_CONFIRM=operator \
bash testnet-harness/run.sh
```

It needs the same authority-check configuration as W3.

The pipeline, bundle installation and controls accept `blend_claim`: the exact
`claim(from = self, reserve_token_ids = [3], to = self)` on the Blend v2 pool
`CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW`. Reserve 1 of that pool is Circle's
testnet USDC (`CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA`), and ID 3 is its
bToken (supply) ID, `1 * 2 + 1`. The pool, its code, the claimed ID, the BLND token and the
backstop are pinned in `protocol-calls.mjs`. Its controls are a changed reserve list and a
foreign recipient (`NoTupleMatched`, `#6` from the generated policy), another pool function
(`FunctionNotAllowed`, `#5`: the policy checks the function name before any argument), the
signer controls, one
delegated claim after an explicit 1–120 ledger accrual wait, the count cap, expiry, removal and
the post-removal denial. The derived-denial step replays five cases of the W1 suite:

- a stranger `to` (`#6`);
- an empty signer set (`#1`);
- an unrecognized signer and the delegate plus an unrecognized signer (`3016`);
- the suite's absent function, realized as the pool's `submit` (`#5`), which the
  `pool_function` control already observed live.

That is exactly the minimum, and only two of the five reach the policy's argument or function
checks. The changed reserve list replaces a `Vec<u32>` with a bool, which the pool rejects before
authorization, so it stays offline. Blend's `claim` calls `from.require_auth()` before paying out,
so the stranger recipient is refused before the missing trustline matters. The foreign recipient is a contract address derived from a fixed label
(`BLEND_FOREIGN_RECIPIENT` in `protocol-invoke.mjs`): the pool pays the accrued BLND while the
call is recorded, and a classic account without a BLND trustline would fail that transfer before
the policy could refuse it. Like every negative control, it is only simulated.

### Read-only preflight

`blend-preflight.mjs` loads no key and sends nothing; every read is a separate RPC
observation. `--check` inspects the pool and the funding route without a run; `--run-dir`
also reads the run's account and payer and writes the plan. It refuses:

- a different pool code, BLND token or backstop, or a pool that is not active;
- a reserve list whose reserve 1 is not Circle USDC, a disabled reserve, a full supply cap or a
  reserve at its maximum utilization;
- a missing, zero or expired emission on ID 3, or one that expires within two hours (the run
  window);
- an expected owner claim under 10 BLND base units: 12 ledgers at an assumed 5 seconds each,
  at the current emission rate and supply with this position added;
- a backstop BLND allowance to the pool smaller than two such claims;
- a changed Soroswap router or factory code, another native-XLM → USDC pair, empty reserves or a
  quote for 200 XLM below the 10 USDC supply amount;
- an account that already has a Blend position, or a payer that cannot fund the swap.

These are fixed controlled-test values, not a yield, price or slippage model.

### Emission refresh

Blend emissions run in seven-day schedules. Before the preflight, `blend-position.mjs refresh`
reads the schedule on ID 3. If it has expired or would expire within the run window, the
harness calls the pool's permissionless `gulp_emissions` once, as the payer, and records the
transaction, the amount gulped and the new expiration. Otherwise it sends nothing and records
`not_needed`. A missing or zero schedule, a gulp the pool refuses, or a schedule still not live
afterwards stops the run with that reason. The preflight copies the refresh into the plan.
A read-only simulation of `gulp_emissions` on 21 October 2026 was refused (`#1200`,
`BadRequest`), so a run after the current schedule ends (26 October 2026, 04:23 UTC, refused by
the preflight from about 02:23) may not be able to refresh it.

### The position

A claim pays only on a position in an emitting reserve. `blend-position.mjs open` creates one
for this run's fresh account, journaling each transaction before it is sent:

1. The payer transfers 200 XLM to the account.
2. The owner swaps it through the pinned Soroswap router for at least 10 USDC, with the account
   as both payer and recipient (`swap_exact_tokens_for_tokens` and its native-XLM `transfer` to
   the pair, through rule 0).
3. The owner supplies exactly 10 USDC: `submit(self, self, self, [Supply USDC])` and its USDC
   `transfer` to the pool, through rule 0. It is a plain supply (request type 0), not
   collateral; nothing is borrowed, so no oracle price or health factor is involved.
4. The harness waits 12 ledgers so the owner's recorded claim is nonzero.

Each owner call is signed only after the recorded authorization equals the exact intended tree,
and the plan's amounts must equal the fixed values above. The swap output, the supply's balance
effect and the account's position (exactly one USDC supply) are checked before the claim.

`protocol-invoke.mjs` then makes the owner's claim, and every later step is the same as W3. A
claim that returns zero BLND, from the owner or the delegate, fails the run: the positive is
counted only with a nonzero return and an equal BLND balance increase.

### Withdrawal

After the controls, `blend-position.mjs close` withdraws the supply through rule 0 (a
`submit` withdrawing twice the supplied amount, which the pool caps at the account's whole
balance) and reads the account's positions back. Only an empty readback records `withdrawn`.
On failure, the wrapper runs the same close, bounded to 480 seconds, before the bundle cleanup
and before discarding the keys. It never signs when the network, the account code or the pool
code differs. A prepared withdrawal is never resubmitted; it is rebuilt, at most once, only
when the network rejected it, never queued it or applied it as failed. A position still open, a
withdrawal or supply whose outcome is unknown, or an unexpected position is recorded as
`incomplete` with its reason; the wrapper then exits nonzero and warns that a position may
remain open.

What the run leaves on its throwaway account is not recovered or recorded: the swap output
beyond the supplied 10 USDC (about 11 USDC at the 21 October quote), the withdrawn USDC and the
claimed BLND. Each run therefore takes about 21 USDC out of the testnet pair.

A zero-reward claim or a mocked pool is not a substitute for any of this.

## Evidence

The exported `evidence.json` adds two typed summaries for these modes: `walkthrough` (the owner
call, each invocation's status and attribution, the bundle journal including each rule's
authority answer, readback, pending submissions and removals, and the control steps) and
`protocol_pipeline`. The native setup's transfer target, recipient and amount are exported as
`null` for these runs: they only fund the account. A Soroswap journal without the
transfer-rule denials is labelled `router_rule_denials_only`, one with them but before the
adapter `transfer_rule_denials_included`, the adapter-bound set
`adapter_route_recipient_function_controls`, and a Blend journal `single_rule`. A W3 plan with
operator decisions is adapter-bound: its `protocol_pipeline` must name the adapter
(`soroswap-router@1`, the router's code hash, rule 0 and the registry root the run resolved and
installed under) and flag the open deadline in `high_blast_radius`, and W3 evidence without that
identity is refused. The pipeline also says who could sign the binding: `development_root` when
the configured roots include the public development key, exported as
`development_registry_assertion_not_governance`, whichever files the operator named; otherwise
`operator_root`. A plan without operator decisions predates the adapter (the 20 and 22 October
runs) and is exported with `adapter_status: pre_adapter`; an adapter on it, on a Blend claim, or
next to an older control set (which would claim the deadline was denied) is refused. The
operator's decisions are exported by value with the file's hash; their intents stay local. An
adapter-bound control journal is refused without its pipeline record.
A Blend walkthrough also exports `position`: the emission refresh, the funding, supply and
withdrawal transactions with their status and ledger, the withdrawal readback, and the
position's final status and reason. `withdrawn` is refused without a sent withdrawal and an
empty readback, and `no_position` after a supply that was sent. The run's own emission-refresh
record is exported as top-level `blend_emission_refresh` (status and transaction), so a gulp
sent before a later failure is not lost.
A removal made after a mismatched or unreadable pre-removal readback carries
`pre_removal_readback`. A `completed` control
journal is accepted only with every required step in order, its expected enforcers and codes,
the expiry boundary, exactly one matching invocation record per step (outcome, ledger and
attribution), a confirmed delegated positive and complete removal. `cleanup: removed` is refused
while any install or removal is pending, a confirmed install lacks a complete removal, or nothing
was removed; `no_installed_grants` is refused after a confirmed or pending install or a pending
removal. Per-rule Wasm, manifests and verification reports are hashed. Preflight readings, RPC
readbacks and host error text stay in the local run directory.

These are editable local RPC observations, not authenticated ledger proofs, and monitoring reads
are non-atomic.
