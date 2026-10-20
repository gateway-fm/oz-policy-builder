# Protocol walkthroughs: W3 Soroswap and W1 Blend

These harness modes take a real protocol call by a fresh pinned smart account through the same
record → synthesize → reference-suite → generate → verify chain as
[W2](WALKTHROUGH-SEP41.md), then install each synthesized rule separately and exercise it.
They are controlled testnet runs with throwaway keys or an exportable virtual passkey. They do
not establish a wallet's protected human approval.

**Status.** W3 is executable through `run.sh`. One controlled run on 20 October 2026 completed
every step below except the two transfer-rule denials, which were added afterwards
([section 9 of the testnet evidence](TESTNET-EVIDENCE-TRANCHE-2.md#9-controlled-soroswap-swap-run-20-october-2026)).
W1 has its pipeline, bundle installation and controls, but no setup for the Blend position its
claim needs; `run.sh` refuses it (see [W1](#w1-blend)), and no W1 run exists.

## W3 Soroswap

```bash
OZPB_HARNESS_WALKTHROUGH=soroswap \
OZPB_HARNESS_AUTHORITY_CHECK=cli \
OZPB_HARNESS_CONFIRM=operator \
bash testnet-harness/run.sh
```

It needs the same authority-check configuration as W2
([harness README](../testnet-harness/README.md#the-wallet-decision-on-the-authority-check)).
`OZPB_HARNESS_CONFIRM=operator` is required: each rule gets its own authority check, and
operator mode approves them without a terminal prompt.

### The recorded call and its decisions

`soroswap-preflight.mjs` re-reads the pinned router's code, its factory and the native-XLM →
`CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F` pair, the pair's tokens and
reserves, a live quote and the account's balance. It refuses a changed router or factory code,
a different pair, empty reserves, a quote below the floor, or too little balance for two swaps.
The expected identities are the constants in `testnet-harness/scripts/protocol-calls.mjs` and
`soroswap-preflight.mjs`; the pair's code is compared with this run's own preflight observation
before every later call.

The owner then calls `swap_exact_tokens_for_tokens` once through the account's owner rule (ID 0) with these fixed,
operator-chosen values. They are test decisions, not a price oracle or a slippage policy:

| Value | Decision |
| --- | --- |
| Input | 1 000 000 base units of native XLM (0.1 XLM). |
| Output floor | An absolute 100 000 base units of the output token, checked against the live quote. |
| Route | Exactly `[native, output token]`; recipient is the account itself. |
| Deadline | Preflight time plus one hour, recorded exactly. |
| Grant | 180 ledgers after the recorded ledger, one call per rule. |

The run requires a confirmed nonzero output and an equal balance increase before recording.

### Two independent rules

The account authorizes two contexts for the swap: the router call and the native-SAC
`transfer` from the account to the pair. Synthesis therefore produces two rules from one
complete spec. This document names them by role, because the account numbers rules itself
(its owner rule is ID 0, and each installed rule gets the next free ID):

- **Router rule** (spec index 0): input at most the recorded amount, output at least the floor,
  the exact route, recipient and deadline.
- **Transfer rule** (spec index 1): at most the recorded amount, from the account to the exact pair.

The widenings (input cap, output floor, transfer cap) are written into the synthesis inputs as
`user_widened` decisions by `protocol-synthesis.mjs` itself. They are fixed for this
walkthrough; a run does not ask for or record a separate acknowledgment of them. No reviewed
registry adapter is used: the committed development registry has no reviewed Soroswap binding,
and the harness does not invent one. The target code hashes in the spec are `evidence_only`
observations.

The rules are independent capabilities, not an atomic workflow. The transfer rule alone lets the
delegate move up to the input amount to the pair. **XLM sent to the pair that way is lost to the
account:** a direct transfer is not a swap, and the pair's surplus balance can be taken by anyone.
The controls observe that authority only by simulation (`independent_token`), never by submitting
it, and then check that the transfer rule's own policy still bounds it. Rule IDs are signed in the
account's context order, router first; the harness's `protocolInputs` refuses a spec whose rule
order would put the transfer rule first.

### Installation

`bundle-command.mjs install` uploads, deploys and installs each generated policy in turn. Every
authority request carries the bindings of all rules, so each rule's answer covers every bound
policy; each owner-signed `add_context_rule` must still equal that rule's approved intent. Each
transaction hash is journaled before submission; a pending or ambiguous step is never retried. An
interrupted bundle is recorded as `incomplete`, not as a partial success. Each rule's authority
answer (commitment, check and pre-sign recheck ledgers) and its install-time readback are kept
in the journal and exported. `bundle-command.mjs inspect` reads both rules back again.

### Required observations

All negative controls are enforcing simulations: nothing is submitted, even after an unexpected
permit. With both rules selected, the router rule's generated policy is the first enforcer
reached for tuple, signer and count failures; the transfer-rule controls select that rule alone.

| Control | Required evidence |
| --- | --- |
| Input above the cap | Router-rule policy refusal `#6`. |
| Output floor lowered | Router-rule policy refusal `#6`. |
| Different deadline | Router-rule policy refusal `#6`. |
| Wrong signer | The account's `UnauthorizedSigner` (`#3016`). |
| Empty signer set | Router-rule policy `ZeroSigners` (`#1`). |
| Direct transfer to the pair | The transfer rule alone permits it in simulation; this is the disclosed independent authority. |
| Direct transfer above the cap | Transfer-rule policy refusal `#6`. |
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
termination handling as W2's failure cleanup. A removal that was prepared or sent is never
resubmitted; an attempt that prepared nothing may be retried. A rule whose readback no longer
matches is still removed by the ID from its confirmed install, since the account never reuses
rule IDs. A rule whose installation was never confirmed is reported as uncertain rather than
inferred.

## W1 Blend

The pipeline, bundle installation and controls accept `blend_claim`: the exact
`claim(from = self, reserve_token_ids = [6], to = self)` on pool
`CCEBVDYM32YNYCVNRXQKDFFPISJJCV557CDZEIRBEE4NCV4KHPQ44HGF`, with its code pinned in
`protocol-calls.mjs`. Its controls are a changed reserve list, a foreign recipient and another
pool function (`#6` from the generated policy), the signer controls, one delegated claim after an
explicit 1–120 ledger accrual wait, the count cap, expiry, removal and the post-removal denial.

What is missing is the position. A claim pays only on a position in an emitting reserve, and the
harness does not yet open one: native-XLM collateral plus a small borrow of a reserve with an
active emission schedule, sized from live reserve, oracle and health data, with repayment and
withdrawal while the keys exist. `OZPB_HARNESS_WALKTHROUGH=blend` therefore refuses with that
reason. A zero-reward claim or a mocked pool is not a substitute.

## Evidence

The exported `evidence.json` adds two typed summaries for these modes: `walkthrough` (the owner
call, each invocation's status and attribution, the bundle journal including each rule's
authority answer, readback, pending submissions and removals, and the control steps) and
`protocol_pipeline`. The native setup's transfer target, recipient and amount are exported as
`null` for these runs: they only fund the account. A journal without the transfer-rule denials
is labelled `router_rule_denials_only`. A `completed` control
journal is accepted only with every required step in order, its expected enforcers and codes,
the expiry boundary, a delegated positive that matches a confirmed invocation and complete
removal. Per-rule Wasm, manifests and verification reports are hashed. Preflight readings, RPC
readbacks and host error text stay in the local run directory.

These are editable local RPC observations, not authenticated ledger proofs, and monitoring reads
are non-atomic.
