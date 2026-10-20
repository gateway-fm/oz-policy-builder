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
| `artifacts` | Digests of available run, provenance, spec, recording, import bundle, manifest and Wasm bytes. Missing artifacts remain missing. JSON file digests are not canonical spec hashes. |

No field makes the summary an acceptance verdict. The exporter checks types and selected
consistency relationships, not the truth of a file supplied by another person. It does not
reproduce a build, fetch transactions, prove account-state freshness, or verify every
historical invocation against the current installed policy. Retain the raw artifacts locally
for deeper review. Do not publish the secrets file or a whole run directory: free-form logs,
raw errors and operator configuration are outside the export's allowlist. The summary still
exposes public account relationships and must be reviewed before publication.

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

## 9. Evidence still needed

The [SEP-41 subscription walkthrough](WALKTHROUGH-SEP41.md) and section 8 now provide current
live harness observations for composed scope/count plus spending limits, ledger-bounded
repeats and separate cleanup checks. The known reference-model gap remains explicit.

Phase 2 still needs a delivered wallet's protected approval and revoke flow, the Blend and
Soroswap walkthroughs, the remaining harness layers with their actual evidence boundaries,
hosted-service deployment evidence, and the public demonstration/video. The controlled W2
run does not close those requirements. See [SCOPE.md](SCOPE.md) for the implementation map.
