# Testnet and runtime evidence — Tranche 2

This record separates historical testnet observations from checks a reviewer can run on the
current revision. It does not establish completion of the Phase 2 outcome in
[architecture §10](architecture.md#10-delivery-plan). The first milestone's observations
remain in [TESTNET-EVIDENCE.md](TESTNET-EVIDENCE.md), sections 1–3.

The [testnet harness](../testnet-harness/README.md) is the executable source for the install
flow. Its run records are local observations, not authenticated ledger proofs. The
[scope map](SCOPE.md) names the remaining requirements. The 15 October observations predate later installer fixes; section 8 records a separate
20 October run against the reviewed subscription harness.

## 4. Pinned account, passkey owner, and generated policy

On 2026-10-15, the harness recorded an accepted testnet run with a passkey-owned account and
the optional authority-check flow. The account was
`CARMB4NCOKFT4NGSWANUIIVHVFPIT4IFQTGCCZQXSDKKWZDHPMLBLH43`; the generated policy was
`CCWIX4Z7WDOTMGLLE3DJ3ZMC57NZAEDNSFRRX72B5VFDMLX3KX6FQ7ZR`.
The earlier run and its limitations are also described in
[the harness change](https://github.com/gateway-fm/oz-policy-builder/pull/58).

| Step | Recorded observation | Limit |
| --- | --- | --- |
| Account and verifier | Setup read back the deployed account and WebAuthn verifier code hashes and compared them with the harness pins. | Recognition is tied to those builds; it does not cover arbitrary wallet accounts. |
| Recording | The owner authorized a transfer, whose transaction was imported from raw XDR. | Imported evidence is `self_supplied`; this was not the live RPC recorder followed by synthesis. |
| Spec and generation | A checked template described that exact transfer, with a separate delegate and a one-call cap; `ozpb generate` built it. | The spec was filled from the recording by the harness, not produced by `ozpb synthesize`. |
| Authority and wallet decision | The wallet accepted the intent, then required a matching commitment on the recheck at ledger 5213154, after the first observation at 5213153. | Trust was operator-supplied test configuration; `--confirm operator` provided no human approval prompt. |
| Installation | The passkey signed `add_context_rule`; the harness recorded successful installation. | The passkey was an exportable software credential in Chrome's virtual authenticator. |
| Delegate permit | The exact transfer was submitted successfully once. | This is one account, policy, and transfer, not the three required protocol walkthroughs. |
| Delegate denials | Wrong amount and recipient returned policy code 6; a second exact transfer returned code 7. | These were enforcing simulations, stopped before transaction submission. They have no failed on-chain transaction hashes. |
| Passkey negative control | A signature over the wrong challenge returned verifier code 3114. | This exercises the verifier path; it is not evidence of hardware-backed key custody. |

The recorded install transaction is
[`89c5c181f108682c4f19e1908f17f8926ceae3e16bfa04ba657107a380cc8da6`](https://stellar.expert/explorer/testnet/tx/89c5c181f108682c4f19e1908f17f8926ceae3e16bfa04ba657107a380cc8da6).
Testnet retention and resets can make a historical identifier unavailable; this document does
not claim a fresh network verification of it.

A separate run added an owner rule for an account the wallet did not trust. The recorded
wallet decision refused that authority. Its saved record contains no install transaction or
installed rule ID. The run used a one-off setup script to add that owner, so it is not a
fully reproduced refusal scenario in this tree. A missing install record alone cannot prove
that nothing was submitted. The older installer also did not persist the policy deployment
before refusal; the current installer does.

Both saved records can be read by the evidence exporter, which reports their provenance as
`unavailable`. They were created before checkout and CLI identity capture existed. The
earlier PR records the authority CLI revision used, but a new export must not fill that
metadata in as though it had been captured by the run. These runs do not test the later
manifest/spec consistency fixes, composed-rule refusal, or deployment-checkpoint changes;
those changes have their own offline regression tests.

The default harness creates the account itself and does not ask for an authority verdict.
The optional path requires an `ozpb` binary containing `check-policy-call-surface` and
`prepare-install-intent`; both commands are included in this checkout. Build the selected
binary from the revision being tested and configure its trust inputs as the harness README
describes. An external CLI digest identifies the selected binary; it does not attest to its
source revision.

## 5. Browser and wallet observations

The [browser harness record](../testnet-harness/browser/README.md) describes two headless
pollywallet runs on 2026-10-15. Its real page registered one resident credential per run and
showed a new wallet address. The committed
[screenshot](../testnet-harness/browser/media/pollywallet-wallet-created.png) is from the
second run. These observations establish wallet creation through that UI, not policy
installation into that wallet.

The account and verifier used by that deployment differ from the toolkit's pinned builds.
The separate pinned-account harness signs and installs with the same kind of passkey owner,
but does not use pollywallet's protected approval screen or backend. Browser registration,
off-chain assertion verification, pinned-account installation, and wallet-product integration
are distinct evidence claims. A successful first three does not establish the fourth.

## 6. Reference evaluation and MCP

The current CLI and MCP expose `reference-suite` / `reference_suite` for layer-1 evaluation
and `verify` for artifact reproduction. A reference result does not establish target
execution, live preflight, or successful installation. An older observation labeled
`dry_run` cannot be used as evidence for an operation that the current server does not expose.

Run the existing MCP verification integration tests with:

```bash
cargo test --locked -p ozpb-mcp-server --test mcp_stdio_verification
```

Those tests cover the named tools' schemas, reference responses and structured errors. They
do not deploy a hosted endpoint or complete a successful real-builder `verify` round trip.
The [Phase 2 verification guide](TRANCHE-2-VERIFICATION.md) describes the focused automated
gate included in this tree. The evidence exporter can run independently of that gate.

## 7. Capture and review a new run

The current wrapper uses `ozpb record` for the owner's confirmed transfer, then runs real
synthesis with explicit bounded test decisions, the reference suite, generation and
artifact verification before installation. It refuses incomplete reference coverage,
disagreements and any reproduction mismatch, including a zero-exit `verify` response with
`matches: false`. It preserves the RPC recording bytes and the full synthesis/reproduction
reports locally. This new executable path does not retrospectively change the historical
manual-template observations in section 4. Section 8 records the later subscription run.

The wrapper now also observes the installed grant's configuration, removes it through owner
authorization and requires a post-removal delegate denial from the account's missing-rule
check. It verifies the pinned removal event and records policy cleanup separately, because
the account's uninstall calls are best effort. Section 8 records these lifecycle observations;
they do not demonstrate a delivered wallet's protected revoke screen.

Use the harness README's prerequisites and its explicit testnet commands. Choose an empty
output directory. The harness spends testnet XLM, creates contracts, and uses throwaway keys.
For an authority run, configure the compatible CLI, signed snapshot, roots, RPC sources and
wallet confirmation mode as described there before starting.

`run.sh` writes `provenance.json` at startup and finalizes it on shell exit. It attempts an
evidence export after successful or failed steps, publishing complete `evidence.json` files
by atomic rename. A reporting error changes a zero exit to failure in the provenance too;
an original failure keeps its own code. Malformed records (including JSON `null`) are refused,
and an I/O error can prevent an output file. A hard kill can leave provenance unfinished.
To regenerate a summary without network access or keys:

```bash
node testnet-harness/scripts/evidence.mjs --run-dir /path/to/run --write
```

`--write` uses the same atomic publication as the wrapper: validation happens before the
previous report is replaced, and output symlinks cannot redirect the write to another file.

Review these fields before sharing the summary:

| Evidence | What to check |
| --- | --- |
| `provenance` | Checkout commit and dirty state, start/finish times, exit status, Node version, Cargo mode or the external CLI byte digest. These describe startup; they do not detect later edits or prove the external binary came from the checkout. |
| `run` | Expected testnet account, target, owner kind, delegate, policy hash, rule and expiry. No `run` means setup did not save one; it is not a successful empty run. |
| `run.transactions` | Recorded deploy and install transaction identifiers. An install record requires both its transaction and rule ID. Deployment can precede a refused wallet decision. |
| `run.authority` | `rechecked`, `refused`, or `not_recorded`. The last means no decision was recorded, not that an account is safe. Refusal text and operator identities are omitted from this summary. |
| `run.invocations` | Separate owner controls from delegate calls; inspect arguments, selected rule, result and error attribution. A null denial code is not an attributed policy refusal. Simulation denials have no transaction ID. |
| `pipeline` | A `recorded` completion record describes the new CLI chain. Check the distinct RPC acquisition and `self_supplied` synthesis identities; trust downgrade changes the recording hash. Artifact reproduction remains separate from current-network preflight. Older runs say `not_recorded`. |
| `lifecycle` | Check removal transaction, event, absent-rule and policy-cleanup observations separately. Configuration reads carry distinct RPC ledger numbers and are non-atomic; a match covers the recorded rule and code pins, not the whole authority surface. `post_revocation` invocation controls retain their actual result, including a failure to obtain the expected denial. |
| `derived_denials` | W1, W2 and W3 only. The exporter rebuilds the replay's plan from the retained run, spec and emitted suite, and refuses a journal that names other cases, offline reasons or expected enforcers. Check that `suite.spec_hash` is the pipeline's, that each original is `permitted` and each case's `observed` enforcer and code equal its `expected` ones, and read `offline` for what was not replayed and why. `live_stand_in` marks a case realized by a control's live equivalent (W1's pool `submit`, W2's control token). Labels say post-install, state-dependent, simulation-only, never submitted. |
| `artifacts` | Digests of available run, provenance, spec, recording, import bundle, manifest and Wasm bytes, and the emitted suite (`derived_cases`). Missing artifacts remain missing. JSON file digests are not canonical spec hashes. |

No field makes the summary an acceptance verdict. The exporter checks types and selected
consistency relationships, not the truth of a file supplied by another person. It does not
reproduce a build, fetch transactions, prove account-state freshness, or verify every
historical invocation against the current installed policy. Retain the raw artifacts locally
for deeper review. Do not publish the secrets file or a whole run directory: free-form logs,
raw errors and operator configuration are outside the export's allowlist. The summary still
exposes public account relationships and must be reviewed before publication.

### What a passing permit/deny report is

A walkthrough's permit/deny report passes when both of these hold:

- **The original call is permitted.** The delegated positive is confirmed, and the spec's suite
  original, replayed on the recorded call, is permitted in simulation.
- **At least five denials are refused.** They come from that spec's own layer-1 suite,
  identified by its suite hash and emitted from the installed spec, not from hand-written
  controls. Each is refused in an enforcing simulation against the installed rule by the
  enforcer its class predicts, attributed by contract id. The report names the expected and
  observed enforcer for every replayed case and lists every other case as offline (layer 1).

The scope is narrower than "the suite":

- The denials are simulations after installation, observed at their reported ledgers; nothing is
  submitted.
- Time, call-count, missing-state and strict-signer-set cases need ledger or installation state
  the live grant does not have, so they stay offline (layer 1).
- So do mutations the target rejects before the account is asked to authorize: arity, type
  confusion, or a value of another type.
- So does replacing the argument that asks the account to authorize, which moves the
  authorization off the account.
- The suite's undeployed contract address and absent function name are realized live only where
  a control has already shown a live equivalent.
- An unrecognized signer alone and the delegate plus an unrecognized signer stop at the same
  account check. Both count toward the five, so W1's five suite cases are four distinct checks.
- The report lists every offline case by class and reason. The
  [harness README](../testnet-harness/README.md#derived-denials) gives the selection rule.

## 8. Controlled SEP-41 subscription run, 20 October 2026

The [allowlisted run summary](evidence/testnet-subscription-2026-10-20.json) records a complete
W2 harness execution from 10:21:26 to 10:28:44 UTC, with a clean checkout at
`0fdb55c274d474ef641022502ccfbe25289f9cd3`. The external CLI digest is retained in its provenance;
that digest identifies executable bytes, not a source attestation. The owner was an exportable
virtual passkey, and confirmation used the explicit operator mode without a human prompt.

The selected account was `CDSWQ6MBK6UICYCSYWNTTLP3RQ27BQKCU435LBBHPXQ3XLXPB53OFCVC`.
Its grant composed an exact 1-XLM transfer to one controlled merchant, a two-call lifetime
cap, and the pinned spending policy with a deliberately short 24-ledger test window.

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | A confirmed owner transfer went through the real RPC recorder, synthesis, the 30-case reference suite, generation/build and matching source/Wasm/manifest reproduction. |
| Install | [Transaction 5fcaab10…d615](https://stellar.expert/explorer/testnet/tx/5fcaab10e09e28a0bad514683962cfd01827d0846ea3f3a2a744aeb123d3d615) installed rule 1 after the authority commitment recheck at ledger 5293646. Both policy configurations matched. |
| Tuple and signer controls | Larger amount, split charge, other merchant, funded other token, wrong signer and empty signer set all produced attributed enforcing-simulation denials before charging. |
| First charge and early repeat | [First charge](https://stellar.expert/explorer/testnet/tx/2538c174dfbbd730c4ccaa8cdf52fd9ed03156af8b22531836db3bbd55156ec9) confirmed at 5293653. The immediate repeat returned spending-policy code 3221 at 5293653, strictly before cutoff 5293677. |
| Next window and lifetime cap | [Second charge](https://stellar.expert/explorer/testnet/tx/4a33492fb9ad6d65a73e07e428a8470fb46c085a1f2e3c1d5d510a6f2252c347) confirmed at 5293681. After another full window, generated-policy code 7 was observed at 5293705. |
| Owner removal | [Removal transaction](https://stellar.expert/explorer/testnet/tx/b924cc544bc958077990718d8c10728f0cd8f4f88a98e748a31020486f3261e6) confirmed at 5293707. The pinned event matched, the rule read back absent, and both policies reported uninstalled. |
| Post-removal control | An enforcing simulation returned the account's missing-rule code 3000 at 5293707. No negative-control fee transaction was submitted. |

All 12 subscription control steps completed and the wrapper finalized with exit 0. The
reference evaluator still does not model the reviewed spending policy's rolling state;
the summary retains that exact gap. These remain editable local RPC observations, with
non-atomic reads and no ledger proof or protected wallet-approval claim.

A separate earlier failed attempt installed rule 1 on
`CDL6OEBK7K36WJCUPE3UC6AQF3CPNVNGU57SHYIN7SGVYXSEUEMDVEJL` and stopped during a negative
control before charging. No removal was confirmed before its throwaway keys were discarded;
its configured expiry is ledger 5310498. The completed run above does not revoke that earlier
grant. The current wrapper attempts bounded owner removal before discarding keys after a
failure, retaining pending or incomplete removal evidence without automatic resubmission.

## 9. Controlled Soroswap swap runs, 20 October 2026

Two complete [W3 harness executions](WALKTHROUGH-PROTOCOLS.md) ran that day. The second adds
the transfer rule's own denials; the first predates them.

### Earlier attempt

An attempt before both runs, on `CDAPJPE5Y4LL5CSSKAHSRWVRDFEQDGOD7AKHNQBF7T5HF55AGJZU5CYD`,
deployed both policies but installed neither: the harness wallet refused the first rule because
it expected only that rule's policy in an answer covering the whole bundle. The wrapper's cleanup
reported no installed grants. Both runs below include the installer fix.

### First run: router-rule denials only

The [allowlisted run summary](evidence/testnet-soroswap-2026-10-20.json) records a complete
[W3 harness execution](WALKTHROUGH-PROTOCOLS.md) from 12:00:08 to 12:16:14 UTC, with a clean
checkout at `610a196fc7543126a914c20ba583291178d90636`. The external CLI digest is retained in its
provenance. The owner was a throwaway ed25519 key, and both rules were approved in the explicit
operator mode without a human prompt.

The selected account was `CBSCLOU6CGH5DVIFL2K7KZHOPZNSQRKLI4ZIESVAMOG6S3D6XXZ27Z7E`. The grant
was two independent one-call rules from one spec, both valid until ledger 5294992: the router
rule (account rule ID 1) for the swap, and the transfer rule (ID 2) for the native-XLM transfer
to the exact pair. The account's owner rule is ID 0.

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/8e075309901d4508b6d12929cd3aa1b93c22b8279a81505029612796760175f7) of 0.1 XLM confirmed at 5294812 with 175656 output units and a matching balance increase. It went through the real RPC recorder, synthesis, the 63-case reference suite, and generation/build with matching source/Wasm/manifest reproduction for both rules. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/d20dabfd95bb1bfcb341749be65d450a7af4c62bfb8e55603b01cb61625e523c) was checked at 5294817, rechecked before signing at 5294818 and read back matched at 5294819. The [transfer rule](https://stellar.expert/explorer/testnet/tx/02bf33a1b07bf699778ff1703c676f638bc9af1054629d1763fe0cbf44a12b61) was checked and rechecked at 5294822 and read back matched at 5294824. Each answer covered both bound policies. |
| Swap controls | A larger input, a lower output floor and a different deadline each returned the router-rule policy's code 6. A wrong signer returned the account's 3016; an empty signer set returned the router-rule policy's code 1. |
| Independent transfer authority | A direct transfer to the pair under the transfer rule alone was permitted in simulation at 5294828, as disclosed. It was not submitted. |
| Delegated swap and count cap | [Delegated swap](https://stellar.expert/explorer/testnet/tx/868a99476333c25620f6f1e725a1c55d625eeef7b6386cacdd9ed07d193aa9c7) confirmed at 5294830 with 175656 output units. The repeat returned the router-rule policy's code 7 at 5294833. |
| Expiry | After the wait reached ledger 5294993, the account returned `UnvalidatedContext` (3002) at 5294995. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/ea7ac2b0a21688bc86dd78a5e531d9b53ef7ce0bed715b0c356aeadf869ed1d2) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/26970d5b278688bc82e9aa3ff667a19634234b010c36b89032a565d4c850e800) confirmed at 5294996 and 5294997. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5294997. No negative-control fee transaction was submitted. |

All 12 control steps of that run completed and the wrapper finalized with exit 0. The run
predates the two transfer-rule denials (a direct transfer above the cap, and one after the swap),
so no denial in it is attributed to the transfer rule's own policy; the summary labels its
control set `router_rule_denials_only`. The widenings were fixed by the harness's synthesis inputs,
with no per-run acknowledgment; no reviewed Soroswap adapter was involved. These remain editable
local RPC observations, with non-atomic reads and no ledger proof or protected wallet-approval
claim.

The committed summary was re-exported offline from the retained run directory after the exporter
gained per-rule authority and readback fields; the wrapper's own export at the time omitted them.
The run files, provenance and exit status are unchanged.

### Second run: full control set

The [allowlisted run summary](evidence/testnet-soroswap-transfer-controls-2026-10-20.json) records a
complete W3 harness execution from 13:08:57 to 13:25:34 UTC, with a clean checkout at
`fea559868fa957576993d6112439ec5fd5ac6d98` and control set `transfer_rule_denials_included`. The
owner was again a throwaway ed25519 key, and both rules were approved in the explicit operator
mode without a human prompt. The summary is the wrapper's own export.

The selected account was `CD5KAVYCDHMS4D6QQ2BCF5646J3KMYMAWUDXAGV6SBDFULKGLC4PFL3H`. Both rules
were valid until ledger 5295820: the router rule (account rule ID 1) and the transfer rule (ID 2).

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/05d8fa675d2578346154c4babaf5b24ee81ab95fd83d815f39687951284b3292) of 0.1 XLM confirmed at 5295640 with 175274 output units and a matching balance increase, then the real RPC recorder, synthesis, the 63-case reference suite and matching source/Wasm/manifest reproduction for both rules. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/133442ee26839673fa77a59dd1d976a0d0784ca119116be64cd295c4e7906229) was checked at 5295649, rechecked at 5295650 and read back matched at 5295651. The [transfer rule](https://stellar.expert/explorer/testnet/tx/05799950a7ee894e96f49aec0abadc75efde257c35fa45692d6c0eb82f7e1dea) was checked at 5295651, rechecked at 5295655 and read back matched at 5295656. |
| Router-rule and signer controls | A larger input, a lower output floor and a different deadline each returned the router-rule policy's code 6; an empty signer set its code 1. A wrong signer returned the account's 3016. |
| Transfer rule alone | A direct transfer to the pair was permitted in simulation at 5295661, as disclosed, and not submitted. A direct transfer one unit above the cap returned the transfer-rule policy's code 6 at 5295662. |
| Delegated swap and count caps | [Delegated swap](https://stellar.expert/explorer/testnet/tx/146cd502db654587d1d62d6f1434e74d79c9d95013d2762390885c7dc1cb1b7e) confirmed at 5295663 with 175274 output units. At 5295663 a repeat swap returned the router-rule policy's code 7, and a direct transfer returned the transfer-rule policy's code 7: the swap had spent both rules' one call. |
| Expiry | After the wait reached ledger 5295823 (target 5295821), the account returned `UnvalidatedContext` (3002) at 5295823. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/41caba90fbcb5c22a3bca6c445ba250d9e0aa39393d886fee78786744d504def) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/a7f56018934690ca6454641d4ebeb69f063241f9d2b8267bb0ff0ce80cc06987) confirmed at 5295825 and 5295829. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5295829. No negative-control fee transaction was submitted. |

All 14 control steps completed and the wrapper finalized with exit 0, deleting the throwaway keys.
The same limits apply as for the first run: fixed harness widenings, no reviewed adapter,
editable local RPC observations, non-atomic reads, no ledger proof and no protected
wallet-approval claim.

## 10. Controlled Blend claim run, 21 October 2026

The [allowlisted run summary](evidence/testnet-blend-claim-2026-10-21.json) records a complete
[W1 harness execution](WALKTHROUGH-PROTOCOLS.md#w1-blend) from 18:06:42 to 18:34:33 UTC, with a
clean checkout at `8772eddb83bbf16bcd59fc6b8114a3499c3fa884`. The CLI was an external binary
built from this branch's Rust sources, which are unchanged through that commit; its digest is
retained in the provenance. The owner was a throwaway
ed25519 key, and the single rule was approved in the explicit operator mode without a human
prompt. The summary is the wrapper's own export.

The selected account was `CDFLU7GBCURFJC6RA4XP2ZOZHUTJ6CETXBFSBGBNCWJUKKI56EE4GUDS`. The grant
was one one-call rule (account rule ID 1) for `claim(self, [3], self)` on the Blend v2 pool
`CAPBMXIQTICKWFPWFDJWMAKBXBPJZUKLNONQH3MLPLLBKQ643CYN5PRW`, valid until ledger 5316809. ID 3 is
the bToken (supply) ID of the pool's Circle testnet USDC reserve. The owner rule is ID 0.

Values marked *(journal)* come from the run's retained local `run.json`, not the published
summary; everything else in the table is in the summary.

| Observation | Recorded result |
| --- | --- |
| Emission and preflight | The refresh recorded `not_needed`, so no `gulp_emissions` was sent. *(journal)* The emission on ID 3 was live until 26 October 2026, 04:23:27 UTC; the read-only preflight passed at 5316491, with an expected owner claim of 210 BLND base units and a quote of 213647060 USDC base units for 200 XLM. |
| Position | The payer sent 200 XLM to the account, the owner swapped them on the pinned Soroswap router, then [supplied](https://stellar.expert/explorer/testnet/tx/48475f8d7ff5128e7a23292331f8bd1562e4742d2847c59592c8ae511c34a433) exactly 100000000 USDC base units (10 USDC, request type 0) at 5316494. *(journal)* The swap returned 213647060 USDC base units, and the readback showed one USDC supply position of 99888711 bTokens. |
| Owner recording and artifact chain | After a 12-ledger wait, the [owner claim](https://stellar.expert/explorer/testnet/tx/81954cb3585bd5b26a373d37fa0c9502e3464bc2436b49a74c8421c6099c4fbf) confirmed at 5316509 with 262 BLND base units and a matching balance increase. It went through the real RPC recorder, synthesis, the 25-case reference suite, and generation/build with matching source/Wasm/manifest reproduction. |
| Install | The [rule](https://stellar.expert/explorer/testnet/tx/c0c3c10cccb1f423efffcd1c6c1e32fd4af8b3a05946a7c5ef0f0b626f5ff6d7) was checked and rechecked at 5316515 and read back matched. *(journal)* It was installed at 5316517. |
| Claim controls | A different reserve token list and a foreign recipient each returned the generated policy's code 6 (`NoTupleMatched`); another pool function (`submit`) returned its code 5 (`FunctionNotAllowed`). A wrong signer returned the account's 3016; an empty signer set returned the policy's code 1. The foreign recipient is a contract address that holds nothing; nothing was sent to it. |
| Delegated claim and count cap | After the accrual wait, the [delegated claim](https://stellar.expert/explorer/testnet/tx/4e987cf5f5d3030afe9d044518c26c18edfdb5aa111a07b19419dfc84a3e504f) confirmed at 5316526 with 298 BLND base units and a matching balance increase. The repeat returned the policy's code 7 at 5316526. |
| Expiry | After the wait reached ledger 5316810 (the grant's last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5316811. |
| Owner removal | The [removal](https://stellar.expert/explorer/testnet/tx/ec505ff30a03aef18cf2c91a68f09b371b74641e074891a11d8e1d365c088a24) confirmed at 5316813. Its event matched, the rule read back absent, and the policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5316816. No negative-control fee transaction was submitted. |
| Withdrawal | The owner [withdrew](https://stellar.expert/explorer/testnet/tx/3e7caed05c8793f5411250ce6aebb0b952e33346447ea6bab38a6a2a323c78ce) the supply at 5316817, and the account's positions read back empty. *(journal)* 99999999 USDC base units were returned. |

All 12 control steps completed. They are 8 enforcing-simulation denials, 1 confirmed delegated
claim, 2 ledger waits (accrual and expiry) and the cleanup step. Five of the denials came from the
generated policy: #6 for the reserve list, #6 for the recipient, #5 for the other pool function, #1
for the empty signer set and #7 for the repeat. Three came from the account: 3016 for the wrong
signer, 3002 for the expired rule and 3000 after removal. The position was withdrawn, and the
wrapper finalized with exit 0, deleting the throwaway keys. The claimed BLND (560 base units), the swap's surplus USDC and
the withdrawn USDC stay on the throwaway account. No reviewed Blend adapter was involved: the
pool's code hash in the spec is an `evidence_only` observation. These remain editable local RPC
observations, with non-atomic reads and no ledger proof or protected wallet-approval claim.

### Earlier attempts

Four attempts that day, each on its own fresh account, stopped before completing; each led to a
harness fix or was a transient refusal. None left a Blend position or an installed grant, as
far as the checks below show.

1. `CCZPKB2CMQNPTVQ2NV4UKSWTZBNRKYSG6R7PUWTA75FDJ2WCNKA46ZIT`: after the funding swap, the
   supply transaction was refused before it was signed or sent, because its assembled fee
   exceeded the harness's one-XLM ceiling. A later read-only simulation reported a minimum
   resource fee of 1.0147 XLM for it. No position was opened and no rule was installed. Fixed by
   a named three-XLM ceiling for Blend calls.
2. `CC37QB7DXY33UIRUBP67G3GB3BI3WMAEU7H7LYLBDNP4Z6RHHR62FK5Y`: the owner claim returned 280 BLND
   base units, but the authority check refused the install (`E_INCOMPLETE_ACCOUNT_STATE: endpoint
   ledger or account instance changed during inspection`). The policy had been deployed but not
   installed. It was a fail-closed refusal, with no harness change. The wrapper withdrew the position (empty readback) and reported no
   installed grants.
3. `CA4DSK7ASGR5RCWS7BWKCNBITNTNJW4A66LZRGVNLLWL7O66VTBFCRIT`: the rule was installed. The
   foreign-recipient control then failed while recording, because the pool's BLND transfer to the
   payer, a classic account without a BLND trustline, failed with #13 before the policy ran. The
   wrapper withdrew the position and removed the grant, both verified. Fixed by a contract
   recipient.
4. `CBFH3ETF22KJXNZUXZFWJ5LUZ3VWVCHOVJ7LZ3H4HFV6SAXKR3ZBA6ES`: the rule was installed and two
   controls passed. The other-pool-function control was refused with the policy's code 5, where
   the harness expected 6, so it stopped as an unattributed denial. Fixed by expecting 5. The
   wrapper withdrew the position (empty readback), but its grant cleanup ended `incomplete`: the
   cleanup child prepared and sent the removal but did not record its confirmation, and its
   output was not retained then. Cleanup children now write `cleanup-child.log`, and a prepared
   removal is reconciled from its hash on the next cleanup instead of staying pending. A later read-only check found the removal transaction successful at
   ledger 5316457, rule 1 absent (3000), the policy reporting it uninstalled, and no Blend
   position. The keys had already been deleted, as designed; the rule would in any case have
   expired at ledger 5316739.

## 11. Controlled SEP-41 run with derived denials, 22 October 2026

The [allowlisted run summary](evidence/testnet-subscription-derived-2026-10-22.json) records a
complete W2 harness execution from 09:04:36 to 09:09:40 UTC. The checkout was clean at
`81ff8b82be007946ede4ae1d70a17b66c5fd2c73`, the commit that added the derived-denial step. The
external CLI's byte digest is retained in its provenance; it identifies the executable, not its
source. The owner was a throwaway ed25519 key, and confirmation used the explicit operator mode
without a human prompt. The keys were deleted when the run ended.

The selected account was `CDXYCLOXDIEB4COCDDQN5RM4LSHOELEJAEWSCYA7KUFOIANGQTXBQOHT`. Its grant
composed:

- an exact 1-XLM transfer to one controlled merchant;
- a two-call lifetime cap;
- a newly deployed instance of the pinned spending policy, with a deliberately short 12-ledger
  test window.

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | The confirmed owner transfer went through the real RPC recorder, synthesis, the 30-case reference suite, generation/build and matching source/Wasm/manifest reproduction. |
| Install | [Transaction 0c591b7d…8f10](https://stellar.expert/explorer/testnet/tx/0c591b7dace397eb217ca2e48f6d6225446df6cdcc1402aa95c42d046ace8f10) installed rule 1 after the authority commitment recheck at ledger 5327278. Both policy configurations matched. |
| Derived denials | The CLI emitted the installed spec's 30-case suite and the replay verified its suite hash. The recorded transfer (`case-0`) was permitted in simulation at 5327282. All 10 live-realizable deny cases were refused at 5327282–5327283 by the predicted enforcer; the live policy order put the spending policy first. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Tuple and signer controls | Larger amount, split charge, other merchant, funded other token, wrong signer and empty signer set all produced attributed enforcing-simulation denials before charging. |
| First charge and early repeat | [First charge](https://stellar.expert/explorer/testnet/tx/62220c9aa875a216c0e610750e735406c59470a66dd867d78cfcf6859313cb66) confirmed at 5327286. The immediate repeat returned spending-policy code 3221 at 5327289, before cutoff 5327298. |
| Next window and lifetime cap | [Second charge](https://stellar.expert/explorer/testnet/tx/b8f75fbad162ffce28eb8fbcd78552b67e88c9236c90ebe54eb9c0d46d3cfc69) confirmed at 5327301. After another full window, generated-policy code 7 was observed at 5327313. |
| Owner removal | [Removal transaction](https://stellar.expert/explorer/testnet/tx/c7c4308926e9f2f4b49ae7d0dc993d29a2432bc670e344e7fa70808de0146b36) confirmed at 5327318. The pinned event matched, the rule read back absent, and both policies reported uninstalled. |
| Post-removal control | An enforcing simulation returned the account's missing-rule code 3000 at 5327318. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-1` | another contract: the funded control token stands in for the suite's undeployed address | account `UnvalidatedContext` 3002 |
| `case-5`, `case-8`, `case-10` | stranger recipient; amount − 1; zero amount | generated policy `NoTupleMatched` #6 |
| `case-7`, `case-9`, `case-11` | amount + 1; amount × 10; i128 maximum | spending policy `SpendingLimitExceeded` 3221 |
| `case-15` | empty signer set | spending policy `NotAllowed` 3223 |
| `case-16`, `case-18` | unrecognized signer; delegate plus an unrecognized signer (one account check) | account `UnauthorizedSigner` 3016 |

This is W2's first passing report under [§7's definition](#what-a-passing-permitdeny-report-is):
the original was permitted, and ten derived denials were refused by their predicted enforcers
(`case-16` and `case-18` stop at the same account check). All 12 subscription control steps completed, and the wrapper finalized with
exit 0.

The reference evaluator still does not model the reviewed spending policy's rolling state; the
replay predicts that policy's refusals from its pinned source and its live, unexercised state.
These remain editable local RPC observations, with non-atomic reads and no ledger proof or
protected wallet-approval claim.

## 12. Controlled Blend claim run with derived denials, 22 October 2026

The [allowlisted run summary](evidence/testnet-blend-claim-derived-2026-10-22.json) records a
complete [W1 harness execution](WALKTHROUGH-PROTOCOLS.md#w1-blend) from 10:50:55 to 11:18:39 UTC.
The checkout was clean at `4feb59ea733dff70db6a8309d6078153ea735fc2`, and the external CLI was
built from it just before the run. Its byte digest is retained in the provenance; it identifies
the executable, not its source. The owner was a throwaway ed25519 key, and the single rule was
approved in the explicit operator mode without a human prompt. The keys were deleted when the run
ended. The summary is the wrapper's own export.

The selected account was `CABC2NCFR3KDIJY44QB3ONK67FAAX22JX2LYT7B4RJ3AMMT3HAX27ROW`. The grant
was one one-call rule (account rule ID 1) for `claim(self, [3], self)` on the same Blend v2 pool
as section 10, valid until ledger 5328859.

Values marked *(journal)* come from the run's retained local `run.json`, not the published
summary.

| Observation | Recorded result |
| --- | --- |
| Emission and preflight | The refresh recorded `not_needed`, so no `gulp_emissions` was sent. *(journal)* The emission on ID 3 was live until 26 October 2026, 04:23:27 UTC; the preflight passed at 5328541, with an expected owner claim of 210 BLND base units and a quote of 213603475 USDC base units for 200 XLM. |
| Position | The payer sent 200 XLM to the account, the owner swapped them on the pinned Soroswap router, then [supplied](https://stellar.expert/explorer/testnet/tx/b49f66b81a2abe391ffe22278e6ee1b33b87d639bb3a3541f08d6dc491331c1a) exactly 100000000 USDC base units at 5328544. *(journal)* The swap returned 213603475 USDC base units, and the supply showed 99888705 bTokens. |
| Owner recording and artifact chain | After the 12-ledger wait, the [owner claim](https://stellar.expert/explorer/testnet/tx/34428e7cf5a1bc6f97629d252e3e0f782f0fec14ae5b0d3d02b7454145115824) confirmed at 5328559 with 262 BLND base units and a matching balance increase. It went through the real RPC recorder, synthesis, the 25-case reference suite, and generation/build with matching source/Wasm/manifest reproduction. |
| Install | The [rule](https://stellar.expert/explorer/testnet/tx/eba348c235c510bef6f619f4132f0c4efb60b212bdd944f0c51b3278be58109b) was checked at 5328569, rechecked at 5328573, installed at 5328575 and read back matched at 5328575. |
| Derived denials | The CLI emitted the installed spec's 25-case suite and the replay verified its suite hash. The recorded claim (`case-0`) was permitted in simulation at 5328576. All five live-realizable deny cases were refused at 5328576 by the predicted enforcer. The 14 deny cases that stay offline are listed by class and reason, and the 5 other permit cases stay layer-1 only. Nothing was submitted. |
| Claim controls | A different reserve token list and a foreign recipient each returned the generated policy's code 6; the pool's `submit` returned its code 5. A wrong signer returned the account's 3016; an empty signer set returned the policy's code 1. All at 5328580–5328581. |
| Delegated claim and count cap | After the accrual wait, the [delegated claim](https://stellar.expert/explorer/testnet/tx/559d9c5cb053faaf1fe8b055453a6f54e2334b550a70ce634ebc9e4976c12650) confirmed at 5328585 with 455 BLND base units and a matching balance increase. The repeat returned the policy's code 7 at 5328585. |
| Expiry | After the wait reached ledger 5328860 (the grant's last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5328860. |
| Owner removal | The [removal](https://stellar.expert/explorer/testnet/tx/2e019c91a1919dd37e634b7ff55cb1b1726f40719c13a5b346f15feb14b2b603) confirmed at 5328861. Its event matched, the rule read back absent, and the policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5328861. |
| Withdrawal | The owner [withdrew](https://stellar.expert/explorer/testnet/tx/3e109c59d6e00d4ebc7e0aaae2139382ebe9c380428c1b961471fcdb4456db72) the supply at 5328866, and the account's positions read back empty. *(journal)* 99999999 USDC base units were returned. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-2` | another function: the suite's absent `claim_x`, realized as the pool's `submit` (`live_stand_in`) | generated policy `FunctionNotAllowed` #5 |
| `case-6` | stranger `to` | generated policy `NoTupleMatched` #6 |
| `case-10` | empty signer set | generated policy `ZeroSigners` #1 |
| `case-11`, `case-13` | unrecognized signer; delegate plus an unrecognized signer (one account check) | account `UnauthorizedSigner` 3016 |

Offline, not replayed: the undeployed contract (no live stand-in); the `from` mutation (it
replaces the authorizer); an `i128` in place of `from` or `to`, the changed reserve list and the
two arity cases (the pool rejects them before authorization); two strict-set mutations, three
call-count cases and the missing-state case (installation state); and the time boundary.

This is W1's first passing report under [§7's definition](#what-a-passing-permitdeny-report-is),
and it passes at exactly the minimum. The W1 suite has five live-realizable deny cases and all
five were replayed, so there is no margin: losing any one of them to an offline class would
refuse the run before anything is simulated. The five are four distinct live checks, because
`case-11` and `case-13` stop at the same account 3016 check. `case-2` is a stand-in: the suite's
function does not exist on the pool, so the pool's `submit`, which the `pool_function` control
also observes, carries it. Only `case-2` and `case-6` reach the policy's function or argument
checks. All 12 control steps completed, the
position was withdrawn, and the wrapper finalized with exit 0. The claimed BLND (717 base units),
the swap's surplus USDC and the withdrawn USDC stay on the throwaway account. No reviewed Blend
adapter was involved. These remain editable local RPC observations, with non-atomic reads and no
ledger proof or protected wallet-approval claim.

An earlier W1 run that day, from 09:32 to 10:00 UTC at the same commit with an earlier build of
the CLI, on `CDK2QVDV2TVFIVBAZQU4L7SLF7MR7WH3ZTQXDOT2MBI2VKSF655WFG7N`, also finalized with exit 0.
Its journal records the same five derived denials meeting their enforcers, a verified removal and
an empty withdrawal readback. Its summary is not committed; this record uses the later run, made with
a freshly built CLI.

## 13. Controlled Soroswap swap run with derived denials, 22 October 2026

The [allowlisted run summary](evidence/testnet-soroswap-derived-2026-10-22.json) records a
complete [W3 harness execution](WALKTHROUGH-PROTOCOLS.md#w3-soroswap) from 11:34:35 to 11:51:09
UTC. The checkout was clean at `2d16dfe1c9722a3c593d69a71c5de2f7a7016b2e`, the commit that lets a
policy upload name a 15-XLM fee ceiling. The external CLI was the section 12 binary, built from
`4feb59ea733dff70db6a8309d6078153ea735fc2`; no Rust source changed between the two commits. Its
byte digest is retained in the provenance; it identifies the executable, not its source. The owner
was a throwaway ed25519 key, and both rules were approved in the explicit operator mode without a
human prompt. The keys were deleted when the run ended. The summary is the wrapper's own export.

The selected account was `CAYI3PJNRFKCH44YCFLLTMURZURAV44KWMWG2ZD3NS3H7YLMP5HN54K6`. Both rules
were valid until ledger 5329248: the router rule (account rule ID 1) and the transfer rule (ID 2).

| Observation | Recorded result |
| --- | --- |
| Owner recording and artifact chain | [Owner swap](https://stellar.expert/explorer/testnet/tx/5ff1093ff365c824d1e6ff2d26cc6b52a86afae38116c5c52bb944d52c471ac6) of 0.1 XLM confirmed at 5329068 with 177477 output units and a matching balance increase, then the real RPC recorder, synthesis, the 63-case reference suite and matching source/Wasm/manifest reproduction for both rules. |
| Policy uploads | Read back from the network after the run (not part of the summary): the router-rule policy's upload carried a fee of 101,536,121 stroops (10.15 XLM), above the former ten-XLM ceiling and within the new 15-XLM one, and was charged 87,423,577. The transfer-rule policy's carried 99,478,611. |
| Install | The [router rule](https://stellar.expert/explorer/testnet/tx/49c3e2ba804e140042cda37a8d7a625fb61fec590478ed899f1c764af0f54e0d) was checked at 5329079, rechecked at 5329080, installed at 5329081 and read back matched at 5329081. The [transfer rule](https://stellar.expert/explorer/testnet/tx/ff7bd39b8634a50dedf35babdccddfe30841b744a2ed6d9edf4eda4515c5bc42) was checked at 5329084, rechecked at 5329085, installed at 5329086 and read back matched at 5329086. |
| Derived denials | The CLI emitted the installed spec's 63-case suite and the replay verified its suite hash. Both recorded calls (`case-0`, the swap, and `case-34`, the transfer) were permitted in simulation at 5329090. All ten live-realizable deny cases were refused at 5329090–5329091 by the predicted enforcer. The 32 deny cases that stay offline are listed by class and reason, and the 19 other permit cases stay layer-1 only. Nothing was submitted. |
| Router-rule and signer controls | A larger input, a lower output floor and a different deadline each returned the router-rule policy's code 6; an empty signer set its code 1. A wrong signer returned the account's 3016. All at 5329092–5329096. |
| Transfer rule alone | A direct transfer to the pair was permitted in simulation at 5329096, as disclosed, and not submitted. A direct transfer one unit above the cap returned the transfer-rule policy's code 6 at 5329096. |
| Delegated swap and count caps | [Delegated swap](https://stellar.expert/explorer/testnet/tx/33b4717212eab0b9d46d117e1b9b16c8fab37272c65a9d1733e249903ffc3d28) confirmed at 5329098 with 177477 output units. At 5329101 a repeat swap returned the router-rule policy's code 7, and a direct transfer the transfer-rule policy's code 7. |
| Expiry | After the wait reached ledger 5329249 (the grants' last valid ledger plus one), the account returned `UnvalidatedContext` (3002) at 5329249. |
| Owner removal | [Transfer-rule removal](https://stellar.expert/explorer/testnet/tx/cb91fafb2544bd0e58238257ecc6de6d6e04bb0a2d61bcf7e42a285c50fe0df2) and [router-rule removal](https://stellar.expert/explorer/testnet/tx/c16b10fd54019a80caad6c3e2e7bfeba144ab7ef99a6b5258dccbed68a5896ef) confirmed at 5329252 and 5329253. Each event matched, each rule read back absent, and each policy reported uninstalled. |
| Post-removal control | The account's missing-rule code 3000 at 5329256. |

The derived denials, by enforcer:

| Cases | Class | Enforcer and code |
| --- | --- | --- |
| `case-5`, `case-8` | router rule: input above the cap; output below the floor | router-rule policy `NoTupleMatched` #6 |
| `case-19` | router rule: empty signer set | router-rule policy `ZeroSigners` #1 |
| `case-39`, `case-43` | transfer rule: stranger recipient; amount above the cap | transfer-rule policy `NoTupleMatched` #6 |
| `case-48` | transfer rule: empty signer set | transfer-rule policy `ZeroSigners` #1 |
| `case-20`, `case-22`, `case-49`, `case-51` | each rule: unrecognized signer; delegate plus an unrecognized signer (one account check per rule) | account `UnauthorizedSigner` 3016 |

Offline, not replayed, for each rule: the undeployed contract and the absent function (no live
stand-in); the mutation of the argument that asks the account to authorize (the swap `to`, the
transfer `from`); type confusions, arity and, for the router, the route and deadline value
changes (rejected before authorization); strict-set, call-count and missing-state cases
(installation state); and the time boundary.

This is W3's first passing report under [§7's definition](#what-a-passing-permitdeny-report-is):
both recorded calls were permitted, the delegated swap was confirmed, and ten derived denials,
five per rule, were refused by their predicted enforcers. Each rule's two unrecognized-signer
cases stop at the same account check. All 14 control steps completed, and the wrapper finalized
with exit 0. The same limits apply as in section 9: fixed harness widenings, no reviewed adapter,
editable local RPC observations, non-atomic reads, no ledger proof and no protected
wallet-approval claim.

### Earlier attempts

Two W3 attempts earlier that day stopped before completing.

1. `CD4JERDBPZW3CDCXV2MI54XZVE4SHEQIK5XL6N2533TUZH2E2PFJFVSS`, from 10:00:57 UTC at
   `4feb59ea733dff70db6a8309d6078153ea735fc2` with an earlier build of the CLI. Both rules were
   installed (IDs 1 and 2, valid until ledger 5328121). Its journal records the derived-denial
   step completing, with both originals permitted and ten denials refused as predicted, and the
   controls through the delegated swap and both count caps. The process was then ended during
   the expiry wait, and the wrapper's exit handling did not complete: the provenance was never
   finalized, no summary was exported, and the journal records no removal or cleanup. The
   throwaway keys are no longer available, so **neither rule can be removed**. A read-only check
   at ledger 5329062 found both rules still present with `valid_until` 5328121, so the account's
   expiry check refuses them, and both policies reporting themselves installed with zero
   remaining calls. They remain on that throwaway account as expired, spent rules. This attempt
   is not counted as a report.
2. `CCARUZYNM7LL6NKB27URAVGZ4KVUZSODBPEPXWMY3KCH2HLNWOLCOOKR`, from 11:18:54 to 11:20:03 UTC at
   the same commit with the section 12 CLI. The harness refused to sign the router-rule policy's
   upload because its assembled fee exceeded the ten-XLM upload ceiling then in force; a
   read-only simulation a few ledgers later put it at 101,220,139 stroops. Nothing was uploaded,
   deployed or installed. The cleanup recorded `no_installed_grants`, a read-only check found only
   the owner rule, and the keys were deleted at exit. Fixed by the 15-XLM policy upload ceiling
   ([harness README](../testnet-harness/README.md#keys)).

## 14. Evidence still needed

The [SEP-41 subscription walkthrough](WALKTHROUGH-SEP41.md) and section 8 provide current live
harness observations for composed scope/count plus spending limits, ledger-bounded repeats and
separate cleanup checks; the known reference-model gap remains explicit. Section 9 adds two
two-rule Soroswap swap runs with expiry and per-rule removal; the second includes denials by the
transfer rule's own policy. Section 10 adds one Blend claim run on a supply position the harness
opened and withdrew.

Sections 11, 12 and 13 add a W2, a W1 and a W3 run with the derived-denial step; all three pass
under [§7's definition](#what-a-passing-permitdeny-report-is), W1 at exactly the minimum of five.
The section 8–10 runs predate that step. Two rules from an interrupted W3 attempt remain installed,
expired and spent, on a throwaway account (section 13).

Phase 2 still needs a delivered wallet's protected approval and revoke flow, reviewed Blend and
Soroswap adapters rather than `evidence_only` code observations and fixed harness widenings, the remaining harness layers with their actual evidence boundaries,
hosted-service deployment evidence, and the public demonstration/video. The controlled W1, W2
and W3 runs do not close those requirements. See [SCOPE.md](SCOPE.md) for the implementation map.
