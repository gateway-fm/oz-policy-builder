# Installing a generated policy on mainnet

The owner's runbook for one installation of a generated grant on Stellar mainnet through the
wallet integration ([Pollywallet integration](POLLYWALLET-INTEGRATION.md#mainnet-sessions)), from
the prerequisites to the removal. Every amount here is real XLM. Nothing in this repository
submits a mainnet transaction for you, and nothing here commits anyone to running one.

## Prerequisites

**Install from the 1.0.0 release.** It comes last in a fixed order: the audit and OpenZeppelin's
review of a frozen revision, the remediation of their findings, then the mainnet registry's key
ceremony, which can sign only once the audit's reference exists, and then the release, which
carries the signed mainnet head ([the order for 1.0.0](VERSIONING.md#the-order-for-100)). Until
then prerequisite 3 cannot be met. Take from that release the toolkit checkout the wallet is
applied from, the binaries, and the signed head, `roots.json` and checkpoint attached to it.

All of these must hold before the first mainnet write. The wallet checks each one and refuses,
with a reason the page explains, when it does not.

1. **Protocol 30 on mainnet.** Mainnet runs protocol 29 until its validators vote the upgrade (the
   vote is scheduled for 23 November 2026). The backend refuses to start against an endpoint that
   reports another protocol (`protocol_unsupported`).
2. **An RPC endpoint that returns diagnostic events.** stellar-rpc 30.0.1 returns them only with
   `--preflight-enable-debug`; the live check, the second use and removal's verification read them
   (`no_diagnostic_events`). `mainnet.sorobanrpc.com` returned them when probed on 19 November 2026.
   The readiness panel probes your endpoint.
3. **A production registry.** A signed mainnet snapshot, its root policy and the persisted
   checkpoint, from the [mainnet registry](../registry/mainnet/README.md) once its custodians have
   signed it ([registry governance](REGISTRY-GOVERNANCE.md)). The development root is refused on
   mainnet, by the wallet at startup and by the CLI (`E_REGISTRY_ROOT_POLICY`). Set
   `registryMinimumVersion` to the version of that registry you pinned (1 for its genesis; the
   development registry's 6 does not apply). Point `registryPublishedPath` at the published log so
   that monitoring can watch it.
4. **A funded fee payer.** A classic account you own, its secret seed in a file with mode `0600`
   (`feePayerKeyPath`), funded with its minimum reserve (1 XLM at the current 0.5 XLM base
   reserve) plus the fees below. The wallet never funds it (`payer_unfunded`).
5. **The delegate's key in a `0600` file, and its account funded.** On mainnet the grant's
   delegate is the agent's own key, named by its proposal. **Installation on mainnet requires that
   key** in a second file with mode `0600` (`delegateKeyPath`): three of the four check layers
   (account Wasm, captured target and live) sign as the delegate, so without the file they cannot
   run, the four-layer gate cannot pass and installation stays closed (`delegate_key_unavailable`).
   The live check's delegate signature is a real mainnet authorization: until its expiry, 12
   ledgers (about a minute) after the check is prepared, anyone holding it together with the owner's
   signature could submit the transfer it covers, which is why the wallet installs nothing until
   that ledger has passed (`signatures_still_valid`). The agent holds this key too: if it obtains
   your passkey signature from a live simulation request before that ledger, it could submit the
   installation itself and use the grant without the wallet. The consents say so; approve only a
   grant you would give that agent anyway. Fund the delegate's account with its minimum reserve
   (1 XLM).
6. **The atomic live helper, deployed by you.** The live check, and so installation, needs it on
   mainnet; the wallet never deploys it. Build `contracts/atomic-live-helper` with
   `stellar contract build --locked` from the release's tag, with the pinned build inputs (Rust
   1.91.1 and stellar-cli 27.0.0 at revision `5a7c5fe`, as `bash scripts/recorded-build-inputs.sh`
   prints them for `rust`, `stellar-cli` and `stellar-cli-revision`), on an aarch64-apple-darwin
   (Apple Silicon) host: the reviewed hash was recorded on that host, and reproducing it needs
   that host and those inputs ([testnet deployment](ATOMIC-LIVE-HELPER.md#testnet-deployment)). Check that the Wasm's SHA-256
   is the reviewed helper hash (`LIVE_HELPER_WASM` in `wallet/shared/live-consent.mjs`), then
   `stellar contract deploy --wasm ozpb_atomic_live_helper.wasm --network mainnet --source <your funded mainnet key>`
   and name the contract ID in `liveHelper`. The deployment uploads and instantiates the checked
   file, and the wallet refuses a helper whose code hash on the network is not the reviewed one.
   stellar-cli 27.0.0 is the build input only: no deployment with it to mainnet or to a
   protocol-30 network is recorded here, since the helper's testnet deployments went through the
   JavaScript SDK (`testnet-harness/scripts/deploy-live-helper.mjs`). Deploy with a stellar-cli
   release that supports the network's protocol; it need not be the one that built the file.
7. **The pinned account and verifier code.** Both the 0.7.3 account Wasm and the WebAuthn
   verifier Wasm were already stored on mainnet when read on 19 November 2026; the readiness
   panel checks them again and gives the upload command for either if it is missing
   (`pinned_code_missing`).
8. **A production build of the wallet page**, served by `vite preview` and built with
   `VITE_OZPB_NETWORK=mainnet`; the backend on port 4318 is reachable from nothing else.

## Every mainnet write, in order, with its simulated fee

Fees are in stroops (10,000,000 stroops = 1 XLM). "Resource fee" is the simulation's
`minResourceFee`. The wallet bids an inclusion fee of 1,000,000 stroops (0.1 XLM) on each
transaction it builds, and its caps count resource fee plus that bid; what the network actually
charges is usually lower, since the inclusion fee is charged at the going rate.

**Where each figure comes from.** Read-only simulations on 19 November 2026: on mainnet at ledger
65,558,679, **simulated on protocol 29; recheck after protocol 30**, and on testnet (protocol 30)
at ledger 5,811,160 for the steps mainnet cannot simulate before their own inputs exist (the account
constructor needs a deployed verifier instance; creating a contract needs its code stored; the
transfers and the rule changes need the account). Testnet is not a mainnet estimate: mainnet's
state-size rent makes new persistent data far dearer there (the same 7,331-byte helper upload
simulated at 96,811,199 on mainnet and 25,225 on testnet). The installation and removal figures
are the prepared fees of the [22 October 2026 testnet run](evidence/wallet-install-revoke-testnet-2026-10-22.json),
when testnet's own upload fees were of mainnet's order. Each step's fee is simulated again before
anything is signed and shown in its consent, and a step above its cap is refused before signing.

| # | Write | Paid by | Resource fee | Source | Most counted against the caps |
|---|---|---|---|---|---|
| 1 | Upload the live helper's code (7,331 bytes) | you, with `stellar` | 96,811,199 | mainnet, P29 | outside the wallet |
| 2 | Create the live helper | you, with `stellar` | 169,141 | testnet | outside the wallet |
| 3 | Create the passkey verifier instance | fee payer | 322,143 | mainnet, P29 | 1,322,143 |
| 4 | Create the smart account | fee payer | 321,783 | testnet | 1,321,783 |
| 5 | Sample transfer, 0.1 XLM from the account to the fee payer | fee payer | 147,927 | testnet, before the passkey's check | 1,147,927 |
| 6 | Upload the generated policy's code (22,949 bytes) | fee payer | 186,754,117 | mainnet, P29 | 187,754,117 |
| 7 | Create the policy | fee payer | 169,173 | testnet | 1,169,173 |
| 8 | Install the grant (`add_context_rule`) | fee payer | 1,472,660 | testnet, 22 October | 2,472,660 |
| 9 | One use of the grant, by the delegate (only with `delegateKeyPath`) | fee payer | 147,927 | testnet, as step 5 | 1,147,927 |
| 10 | Remove the grant (`remove_context_rule`) | fee payer | 1,009,430 | testnet, 22 October | 2,009,430 |

Nothing else writes: the live check and the second use are enforce-mode simulations, never
submitted, and readiness, review and monitoring only read.

**Total.** The fee payer's ceiling is about 19.83 XLM (steps 3–10), of which the policy
upload is 18.78 XLM. Your own helper deployment is about 9.70 XLM. Hold besides: the fee payer's
1 XLM reserve, the delegate account's 1 XLM reserve, 0.1 XLM in the smart account for the sample
(it returns to the fee payer, your own account) and the grant's amount for its one use. **About
31.63 XLM in all**, plus the grant's amount, at these figures; the inclusion bids alone are
0.8 XLM of the ceiling and are mostly not charged.

## The caps against these figures

| Cap | Default | Ceiling | Against the figures above |
|---|---|---|---|
| Per transaction (`maxFeeStroops`) | 1 XLM | 1 XLM | every step but the uploads fits, with installation and removal at about 0.25 XLM |
| Policy upload (`maxUploadFeeStroops`) | 12 XLM | 50 XLM | step 6, 18.78 XLM at protocol 29 prices, is refused (`fee_cap`) at the default; set it to at least 187,754,117 |
| Session (`sessionSpendCapStroops`) | 15 XLM | 50 XLM | the deployment preview needs the steps before it (3,791,853), the upload (187,754,117) and room for the policy's creation, an installation and a removal (30,000,000): set it to at least 221,545,970, about 22.2 XLM |

The defaults are deliberately low, so **set both caps yourself from the simulated figures**, in the
backend's configuration file, and restart the backend. The upload cap may not exceed the session
cap. The figures above were simulated on protocol 29: after the protocol 30 upgrade, read step 6
again before setting the caps. The deployment preview shows the upload's simulated cost before
anything is signed, and a refusal names the setting that refused it, the simulated cost and the
least value that lets the upload through. Leave a margin for the price to move between preview and
submission, and add whatever this work root's earlier sessions spent (the page shows it). A
removal is never stopped by the session cap, and every other step keeps room for one installation
and one removal (only for the removal once this session has installed the grant), so a grant you
install can always be taken back.

## Evidence to keep

Keep these together, for each installation:

- the **registry root** the grant was synthesized under (the spec's and the BuildManifest's
  `registry_snapshot`) and the checkpoint you pinned (`version`, `log_index`, `root`);
- the **BuildManifest** of the generated policy (its `wasm_hash`, `spec_hash` and
  `normalized_input_hash`), from the page's generated-artifact panel;
- the **DeploymentRecord** the deployment returns (`policyAddress`, `wasmHash`, `bindingSetHash`,
  the upload and creation transaction hashes): the deployed code hash must equal the manifest's;
- the **InstallationRecord** (transaction hash and ledger, rule ID, `policyCodeHash`, `specHash`,
  `bindingSetHash`, `authorityCommitment`, the verification run and its four layers, the live
  check's consent hash): it binds the installation to the deployment and, through the spec, to the
  registry root;
- the **removal result** (event verified, rule absent);
- the backend's **session journal** directory (`journal/` in the session directory under
  `workRoot`), which records the network first and every intended, submitted and confirmed
  transaction with its hash;
- the **monitor** observations you took, with their registry status.

The owner's passkey signatures are automation-free only if a person approved them; the records say
`human_approval_attested: false` because the wallet cannot tell.

## How to revoke

From the page, section 9: **Prepare revocation** for the grant this session installed, or, after a
restart, attach the account and use **Remove a grant an earlier session installed**, which lists
the account's rules as stored and removes the grant you choose with your passkey. Only a
grant-shaped rule (another contract's calls, limited by at least one policy) is offered; your
owner rule and any recovery, guardian or admin rule are not. After a restart the removal needs only
the fee payer's account to exist and to be able to spend that removal's own fee, less than the
per-transaction cap (`payer_unfunded` otherwise), not a new deployment. Either way the
removal is verified by the account's `context_rule_removed` event and the rule reading back absent.
If the registry later revokes the account or the owner verifier, revoking the grant does not help:
follow [revocation and emergency removal](REGISTRY-GOVERNANCE.md#revocation-and-emergency-removal).

## If anything refuses

Nothing is signed or sent when a step refuses; the page names the reason
([when the wallet refuses](POLLYWALLET-INTEGRATION.md#when-the-wallet-refuses)). In particular:

- `protocol_unsupported`, `network_mismatch`: the endpoint, not the grant. Fix the configuration.
- `no_diagnostic_events`: use an endpoint that returns them.
- `payer_unfunded`, `account_unfunded`, `delegate_unfunded`: fund that account from your own wallet.
- `pinned_code_missing`, or a live layer naming the helper: upload or deploy it yourself, as above.
- `fee_cap`, `spend_cap`: the step would pass a cap. For the policy upload the page names the
  setting (`maxUploadFeeStroops` or `sessionSpendCapStroops`), the simulated cost and the least
  value that lets it through; check that figure against the table above before raising the
  setting, within its ceiling.
- `registry_root_refused`: the registry trust files are not the production ones.
- `signatures_still_valid`, `account_changed`: wait for the ledger shown, or find out what changed
  before installing anything.
- An uncertain submission blocks every later write in the session: read the intended hash in the
  journal and look it up before starting another session.
