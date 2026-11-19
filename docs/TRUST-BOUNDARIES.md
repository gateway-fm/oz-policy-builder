# Trust boundaries

What you can rely on when you use a generated grant, what you cannot, and where each check
happens. A one-page summary of [architecture §6](architecture.md#6-trust-security-and-privacy-model)
and [SECURITY.md](../SECURITY.md#what-this-milestone-does-and-does-not-claim); the audit's version,
with the tests behind each claim, is [AUDIT-SCOPE.md](AUDIT-SCOPE.md#trust-boundaries-and-what-is-claimed).
Audit status is stated in [SECURITY.md](../SECURITY.md).

## What is guaranteed

- **Nothing happens without you.** The toolkit library, the MCP server and the Claude session
  never sign, submit, deploy or install; the CLI's `ozpb dry-run` signs only requests for an
  offline execution network. Deploying a policy needs your explicit consent; installing it needs your own account
  signature over the exact transaction you reviewed. The testnet harness and the demo script
  submit transactions on testnet with disposable keys; the wallet backend does so with disposable
  keys on testnet and, in a [mainnet session](POLLYWALLET-INTEGRATION.md#mainnet-sessions), with
  the operator's own fee-payer key. Each acts only when you run it.
- **Exactly what you approved.** The grant permits the recorded calls, deep-equal, plus only the
  widenings you decided or a registry-bound adapter derived, each tagged with where it came from
  ([scoping decisions](SCOPING-DECISIONS.md)).
- **Signers first.** The generated policy refuses a call whose authenticated signers do not satisfy
  the grant's predicate, before it looks at the call; no signers always deny, and a named signer
  set is strict.
- **Unknown means refused.** Unrecognized account, policy or verifier code, a missing registry and
  an unverifiable snapshot are errors, never guesses.
- **Reproducible output.** The same spec and the same pinned build inputs give byte-identical source
  and Wasm, so anyone can rebuild what you install (on comparable hosts; see below).

## What is not guaranteed

- **Not effect-minimal.** A rule binds the target's address, not its code: an upgraded target can
  make a permitted call do something else. Effect claims hold only through a reviewed adapter, and
  only while the target's code hash matches.
- **Not "safe to install".** The authority check lists who can change your account or reset the
  grant and refuses known-bad shapes, but it is an observation of one RPC endpoint at one ledger.
  Your wallet, which holds the owner key, recomputes it and decides. A rule added later is caught
  only by a fresh check.
- **Account recognition is generation compatibility only.** It does not say a grant is safe on a
  particular live account.
- **Caps are per installation**, and a cap (`<=`) on a signed integer admits negative values
  ([open question](SCOPING-DECISIONS.md#open-question-negative-values-under-a-cap)).
- **A partial dry run** outside the one native-asset transfer shape the four layers support
  ([SCOPE.md](SCOPE.md#implementation-boundaries)).
- **Builds are attested by reproduction only.** A real build is labelled `local-unattested`; the
  pinned account Wasm reproduces byte-for-byte only on Apple Silicon.
- **A consistently lying RPC endpoint is not detected.**
- **The wallet removes grant-shaped rules only.** With the owner's passkey it removes a grant its
  running backend installed or, after a restart, one an earlier session installed, read from the
  account as stored. It refuses the owner rule, a rule naming the owner's passkey and a
  `Default`-context or policy-less rule; those need the account's own management
  ([an earlier session's grant](POLLYWALLET-INTEGRATION.md#removing-an-earlier-sessions-grant),
  [how to revoke](INCIDENT-RESPONSE.md#how-to-revoke-a-grant)). A restarted backend does not read
  the earlier session's replay obligations, so wait as
  [after a restart](POLLYWALLET-INTEGRATION.md#after-a-restart) says before installing again.

## Who holds which key

| Key | Held by | Can | Cannot |
| --- | --- | --- | --- |
| Account owner (a passkey in the wallet; an ed25519 key in harness runs) | You, through the wallet | Install and revoke grants; anything the owner rule allows | — |
| Delegate (automation) key | Testnet wallet: a key the backend generates and holds in memory. Mainnet wallet: the agent's own key, which the backend reads from the operator's 0600 file (`delegateKeyPath`) and holds in memory; installation requires it, and whoever can read that file holds the agent's key. `ozpb dry-run`: your 0600 file, signing only offline-domain requests | Sign calls the grant permits | Change the account or reset the grant — the authority check refuses a grant whose delegate could, at the ledger it reads |
| Fee payer | The wallet backend. Testnet: a disposable key it generates, in memory. Mainnet: the operator's key, read from a 0600 file (`feePayerKeyPath`) and held in memory | Pay fees and submit, within the configured fee caps on mainnet | Authorize anything on your account: the backend refuses an envelope whose authorization entries name it |
| Registry custodian keys | Custodians, m-of-n, on separate devices | Sign registry snapshot roots | Touch any account |
| Development registry root | Anyone: it is published | Sign testnet development snapshots | Be accepted for any network but testnet |
| None: the Claude session, the MCP server (local or hosted) and the toolkit library | No account, owner, delegate or fee-payer key (on mainnet the delegate is the agent's own key, held as the delegate row says, never by these) | Prepare unsigned XDR at most | Sign, submit, deploy or install |
| Wallet pairing code | The agent session | Deliver a draft the wallet regenerates | Start any wallet action |

Custody details: [registry keys](REGISTRY-GOVERNANCE.md#roles),
[the delegate key file](NATIVE-EXECUTION.md#running-the-layers-from-the-cli),
[the wallet's keys](POLLYWALLET-INTEGRATION.md#start-the-local-backend) and
[on mainnet](POLLYWALLET-INTEGRATION.md#mainnet-sessions),
[the handoff](AGENT-WALLET-HANDOFF.md#authority-and-data-boundaries).

## What the registry signature covers

The custodians sign the canonical hash of the whole snapshot, so a valid threshold signature covers
every entry (capabilities keyed by exact Wasm hash, with review references), the network, the
version and its place in the chain, the validity interval and every revocation.

It does **not** cover:

- that deployed code implements what an entry declares — a review reference is the custodians'
  assertion, not a proof;
- generated policies, which have no entry: they are recognized by rebuilding them;
- installed grants: revoking an entry makes the toolkit refuse it, but does not remove a rule from
  any account ([incident response](INCIDENT-RESPONSE.md));
- newer versions a published copy withholds: only each version's expiry bounds a frozen log;
- any network but testnet when the signer is the development root: every command refuses that
  root off testnet. The mainnet registry is an unsigned draft until its key ceremony
  ([`registry/mainnet/`](../registry/mainnet/README.md)).

The procedure is [Registry governance](REGISTRY-GOVERNANCE.md).

## What `rpc_reported` means

Evidence fetched live from the configured RPC endpoint, trusted exactly as far as that endpoint is.
It is *reported*, not proven: no ledger-inclusion proof exists in this toolkit. A recording that
crosses a serialization boundary — over MCP, from a file, as an import — is downgraded to
`self_supplied` before synthesis, so a caller cannot claim `rpc_reported` for evidence it supplies.
`incomplete` evidence cannot drive synthesis. The authority check's answer is likewise one
endpoint's report at one ledger. See [RECORDING-EVIDENCE.md](RECORDING-EVIDENCE.md).

## Where trust is checked

| Step | Loads the registry under your pinned roots and floor |
| --- | --- |
| `synthesize_policy` / `ozpb synthesize` | Yes, and stamps the snapshot root into the spec |
| `generate_code`, `verify` / `ozpb generate`, `ozpb verify` | **No.** They carry the spec's root into the BuildManifest unchecked: a manifest's `registry_snapshot` says which snapshot the spec claims, not that anyone verified it |
| `check_policy_call_surface`, `prepare_install_intent`, `assemble_install_transaction` | Yes, before reading the account through an operator-named RPC source |
| `check_against_policy`, `prepare_dry_run` | Yes |
| The wallet, before you sign | Recomputes authority against its own RPC and roots, regenerates any proposal, validates the unsigned transaction and enforce-simulates it |

A spec synthesized under your pinned roots is the path to a root the toolkit has checked, and the
install-time checks load it again ([where trust is checked](REGISTRY-GOVERNANCE.md#where-trust-is-checked),
[SCOPE.md item 7](SCOPE.md#implementation-boundaries)).
