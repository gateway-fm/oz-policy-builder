# User guide

The path from a transaction you already made to a scoped grant on your smart account, and back:
record → decide → generate → reference check → review → install (running the remaining dry-run
layers) → use → monitor → revoke. Each step names its entry points: the agent skill in Claude
Code (which calls the MCP tools), the `ozpb` CLI, and the local wallet. Set up with the
[tester quickstart](TESTER-QUICKSTART.md); do everything on testnet first.

Nothing on this path signs, deploys or installs for you. The agent and the toolkit prepare and
check; you approve in the wallet ([trust boundaries](TRUST-BOUNDARIES.md)).

## 1. Record a transaction you already performed

The authorizer has to be a recognized OpenZeppelin smart account — the 0.7.3 example account the
wallet creates — not an ordinary `G…` account.

- **Skill:** run `/oz-policy-builder:policy-builder` and give it a transaction hash
  (`record_transaction`), an unsigned envelope (`record_simulation`) or a raw-XDR evidence document
  (`import_recording`). The hash must be recent: RPC retention keeps a transaction for a few days,
  and an expired one is `E_RETENTION_EXPIRED`.
- **CLI:** `ozpb record --tx-hash …`, `ozpb simulate --envelope-xdr …` or `ozpb import --bundle …`
  ([developer guide §1](DEVELOPERS.md#cli)).
- **Wallet:** create the account with a passkey, approve its fixed sample transfer, and record it
  ([review and consent](POLLYWALLET-INTEGRATION.md#review-and-consent)).

A grant you mean to install through the wallet must be recorded by hash from the wallet account's
confirmed transaction: the wallet records it again itself. A simulation is proposed behaviour, not
an executed transaction.

## 2. Answer the scoping questions

Who may act, until which ledger, how many calls, and whether to loosen any argument. Exact is the
default; every widening is your explicit decision with a stated blast radius. The skill asks and
restates them before synthesizing; with the CLI you write a decisions file. What each choice
means: [scoping decisions](SCOPING-DECISIONS.md).

## 3. Generate and verify the policy

- **Skill:** `synthesize_policy` → `generate_code` → `verify`. It shows the permissions with their
  rationale, makes the generated Rust available, and reports source and Wasm reproduction
  separately.
- **CLI:** `ozpb synthesize`, `ozpb generate`, `ozpb verify`, with the flags in the
  [developer guide](DEVELOPERS.md#cli).

The generated crate is readable Rust; do not edit it. `verify` and the wallet reproduce it from the
spec, so an edited crate no longer matches.

## 4. Check the reference evidence

Before anything is deployed, only the first of the four dry-run layers can run: `reference_suite`
or `ozpb reference-suite`, the independent evaluator permitting the recorded call and denying its
derived mutations. It is layer-1 evidence, not a dry run of the contract; the other three layers
need the policy deployed and bound, and run in step 6. A layer that has not run is reported as not
run or unavailable, never as passed.

## 5. Review the permission card

Before anything leaves the conversation the skill shows **Confirm before deploy**: what is
permitted, what is not constrained, every high-blast-radius choice, signer, expiry, cap, policies,
build and target code identities, the four layers and the authority list. Read the addresses in
full. Reply exactly `confirm` to hand off that card and nothing else; any change needs a new card.
The wallet shows its own review of the regenerated spec, files, Wasm hash and build manifest.

## 6. Install through the wallet

You sign; nothing is automatic.

1. In the wallet select **Connect Claude** and give Claude the one-time code. After you confirm the
   card, Claude Code asks you to approve `send_wallet_proposal`
   ([direct handoff](AGENT-WALLET-HANDOFF.md#use-it)). Without a connection, start
   `/oz-policy-builder:policy-builder-install` yourself and import its proposal.
2. **Review proposal from Claude.** The wallet records the transaction again, regenerates the grant
   and refuses any difference.
3. Confirm the policy's deployment (a testnet fee; no authority yet) and refresh the authority
   review. The remaining dry-run layers now run against the deployed policy
   ([report fields](DRY-RUN-PREPARATION.md#executed-layers-and-acceptance)):

   | Layer | What it shows | Where it runs |
   | --- | --- | --- |
   | `account_wasm` | The reference cases through the pinned account Wasm and your policy Wasm | `Run local execution checks`, or `ozpb dry-run` with the native worker and the delegate's key file |
   | `captured_target` | The call against target state captured from the network | the same |
   | `live_enforcement` | The policy deciding the real call on testnet, in a simulation never submitted | the wallet's live check, after you consent with the passkey |

   All four layers run only for the wallet's grant shape, one exact native XLM transfer.
4. **Prepare installation**, read its consent statement, and approve with the passkey
   ([installation](POLLYWALLET-INTEGRATION.md#installation)).

Outside the wallet, `ozpb check-policy-call-surface`, `ozpb prepare-install-intent` and
`ozpb assemble-install-transaction` (MCP: the same names with underscores) give the authority
answer, the exact `add_context_rule` arguments and an unsigned transaction. They are advisory: a
wallet must validate, recheck, enforce-simulate and have the owner sign
([INSTALL-ASSEMBLY.md](INSTALL-ASSEMBLY.md)).

## 7. Use the grant

The delegate signs calls inside the grant without the owner; this rule refuses anything outside
it. To predict one call against the installed rule, use `check_against_policy` or
`ozpb check-against-policy`: permit, deny or `unsupported` at one ledger, without checking
signatures ([LIVE-POLICY-CHECK.md](LIVE-POLICY-CHECK.md)). In the wallet,
`Pay with the automation key` makes the granted payment once and `Try the same payment again` shows
the cap refusing it ([using the grant](POLLYWALLET-INTEGRATION.md#using-the-grant)).

## 8. Monitor

- **The grant:** the wallet's `Check installed grant now` (CLI: `ozpb check-installed-grant`)
  compares the rule, the code and the modelled authority with what was installed. It reports
  `unchanged`, `inactive`, `drift` or `unavailable`, and only when you run it
  ([monitoring](POLLYWALLET-INTEGRATION.md#on-demand-installed-grant-monitoring)).
- **The registry:** `ozpb registry monitor` with the hashes your grant relies on tells you when one
  is revoked ([incident response](INCIDENT-RESPONSE.md#a-a-hash-you-rely-on-is-revoked-in-the-registry)).

## 9. Revoke

Expiry and the call cap stop a grant on their own; revocation removes its rule now. In the wallet,
`Prepare revocation` and approve with the passkey. The wallet revokes only grants its running
session installed ([revocation](POLLYWALLET-INTEGRATION.md#revocation)). What to do in an incident:
[incident response](INCIDENT-RESPONSE.md).

## On mainnet

The steps are the same; the wallet is what changes. In this tree the wallet backend and the testnet
harness act only on testnet and the MCP development launcher configures only a testnet source, so
installing on mainnet is part of the mainnet wallet integration. Recording a mainnet transaction
by hash works against a mainnet RPC endpoint, but synthesis needs a mainnet registry signed under
roots you pin: the development root is refused off testnet, and the
[mainnet registry](../registry/mainnet/README.md) stays an unsigned draft until its key ceremony
([registry governance](REGISTRY-GOVERNANCE.md)).
