# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Advisories → Report a
vulnerability** on this repository. That opens a channel visible only to the maintainers, so
no address has to be guessed and nothing lands in a public issue first. Please do not open a
public issue for a security report. If that option is not visible to you, open an issue that
says only that you have a security report and asks for a private channel — no details — and,
during the grant period, we will open one.

Useful in a report, roughly in order: the commit you looked at, the input that reaches the
defect (a `PolicySpec`, a recording bundle, a registry snapshot, an RPC response), what the
code does with it, and what a caller gains. A generated policy that permits more than its
spec describes, a validator that accepts a spec codegen cannot render safely, an evidence
label a caller can raise, or a registry snapshot that widens a capability are all in scope
and all interesting.

There is no bounty.

## After a report

During the grant period — through Tranche 3, after which there is no committed maintenance
([architecture §10, Maintenance](docs/architecture.md#10-delivery-plan)) — the maintainers handle a
report in these steps, on a best-effort basis and with no promised response times:

1. **Acknowledge** it in the private advisory and say whether we can reproduce it.
2. **Assess** it with you: whether it is in scope, what a caller gains, and which releases and
   fielded artifacts it reaches — generated policies, registry entries, the wallet integration.
3. **Fix** it privately, in the advisory's temporary private fork, with a test that fails before
   the fix, and release it in the latest release line ([Supported versions](#supported-versions)).
4. **Revoke** whatever the defect makes untrustworthy that has a registry entry — a template
   family, a reviewed policy, an account or verifier build, a target adapter — in a signed
   registry successor ([revocation](docs/REGISTRY-GOVERNANCE.md#revocation-and-emergency-removal)).
5. **Disclose** in coordination with you: publish the GitHub security advisory, saying what users
   must do, and an entry in the release notes (`docs/release-notes/`). You are credited there if
   you want to be.

A defect in an upstream component — OpenZeppelin `stellar-contracts`, the Soroban SDK or host,
`stellar-cli` — goes to its maintainers through their own channel and is handled here as an
[upstream advisory](#upstream-advisories). What users and operators do when a policy, account or
registry entry they rely on is affected, during the grant and after it, is
[incident response](docs/INCIDENT-RESPONSE.md).

## What this milestone does and does not claim

Read this before reporting: several properties a security reader would expect are
deliberately **not** claimed here, and are documented as boundaries rather than gaps. From
`README.md` and `docs/architecture.md`:

- Recognizing an account's code hash establishes *generation compatibility only*. Nothing
  here says a generated policy is safe to install on a particular live account.
- Recordings that cross the synthesis boundary as JSON are downgraded to `self_supplied`. A
  caller cannot mint the stronger `rpc_reported` label, and self-supplied evidence is not
  presented as RPC attestation.
- A spec cannot name an external-verifier signer for a new rule, because nothing at
  authorization time binds a verifier address to the executable a registry recognizes. The
  authority check accepts an existing external owner only through the code observed at its
  verifier address at the read ledger, and only for reviewed immutable, stateless verifiers.
- The reference evaluator models the generated scope policy. It returns `indeterminate`, never
  a whole-composition `permit`, when an attached reviewed policy is not modelled.
- The local build runner bounds environment, inputs, outputs and time, and on a hosted
  (`--http`) server the number of builds running at once. It is not a multi-tenant sandbox
  and is not offered as one.
- The library and the MCP server never sign, submit, or deploy, and hold no account, owner or
  fee-payer keys. The demo script, the testnet harness and the local wallet backend do on
  testnet, with disposable keys they generate, the wallet's automation delegate included. In a
  mainnet session, and in a testnet session the operator configures with its own fee payer key
  to rehearse one, the local wallet backend generates no signing key and holds two the operator
  supplies, each read at startup from a 0600 file the operator owns and kept in process memory:
  - The operator's fee payer key (`feePayerKeyPath`), used only as the source and fee payer of
    the backend's transactions, within per-transaction and session fee caps; it is never
    printed, returned or journaled, and never a signer on an account.
  - The agent's own key (`delegateKeyPath`), the delegate the grant names. Installing a grant
    requires it: the account-Wasm, captured-target and live checks, three of the four layers
    installation requires, sign as the delegate. The live check's delegate signature is a real
    authorization on the session's network until its expiry, 12 ledgers after the check is prepared; with the
    owner's signature it is a submittable transfer, so installation waits until that ledger has
    passed. Without the file the wallet holds no delegate key and installation stays closed
    (`delegate_key_unavailable`). Whoever can read that file, or the backend's memory, holds the
    agent's key.

  The wallet's owner signs with the user's own passkey.
- `ozpb dry-run` holds the spec delegate's key, read only from a
  0600 file owned by the caller, never from an argument or the environment, and cleared on a
  best-effort basis when the run ends (a moved value can leave a stack copy). It signs only the
  native worker's requests whose preimage names the run's offline execution network, which it
  derives itself and which can never equal the source, public, test or future network; it never
  submits, deploys or installs. A delegate key is still a live credential on its own network, so
  use a throwaway delegate for dry runs.
- That signing guard stops a confused or buggy worker, not a hostile one. The native worker
  runs unsandboxed as the caller's user and can read anything the caller can, including the key
  file, whose path is on the command line. Run only a worker binary you built or otherwise
  trust; the CLI refuses one that is writable by its group or others, or owned by neither the
  caller nor root. File mode and owner are the only checks on the key file: an extended ACL
  (macOS or POSIX) that grants someone else access to a 0600 file is not detected.
- `ozpb registry keygen` and `ozpb registry sign --key-file` handle a registry custodian's key:
  generated into a new 0600 file, read back under the same file checks as the delegate key, never
  printed, and used only to sign a registry snapshot root; neither command reads a network. A
  custodian key is a production root, so keep it on a machine or device used for nothing else, or
  on a hardware key whose signature `sign` accepts instead of a key file. The procedure, including
  rotation and compromised keys, is [`docs/REGISTRY-GOVERNANCE.md`](docs/REGISTRY-GOVERNANCE.md).
- No independent third-party audit has been performed. The evidence that has actually been
  run is in `docs/TESTNET-EVIDENCE.md` and, for the second milestone's controlled testnet
  harness runs, `docs/TESTNET-EVIDENCE-TRANCHE-2.md`; those runs are local RPC observations,
  not ledger proofs or wallet approval. `docs/SCOPE.md` says what deliberately has not been
  run; test counts are not treated as assurance. The scope prepared for an external audit —
  in-scope components, threat model, and the known limits not to re-report — is
  `docs/AUDIT-SCOPE.md`; OpenZeppelin's review of the generated code starts from
  `docs/OZ-REVIEW-PACKAGE.md`.

A report that one of the above is true is a report we already agree with. A report that one of
them is *false* — that a claimed fail-closed path can be made to open — is the one we want.

## Upstream advisories

[GHSA-jpg9-m7w4-c7wc](https://github.com/OpenZeppelin/stellar-contracts/security/advisories/GHSA-jpg9-m7w4-c7wc):
in OpenZeppelin `stellar-accounts` before 0.7.3, anyone can authorize a smart account without
keys when a `Delegated` signer is the contract requesting its authorization, or when delegation
loops back. The recognized account is now OpenZeppelin's example built at v0.7.3, and
development registry version 6 revokes the earlier v0.7.2 build. The revocation binds only where
version 6 is the floor: versions 1 to 5 still recognize the old build, and a caller can supply
its own signed snapshot, so operators must set `OZPB_REGISTRY_MIN_VERSION=6` (the CLI's
`--registry-min-version 6`, the wallet's `registryMinimumVersion: 6`) or persist a version-6
checkpoint. The shipped configurations and documented commands do. This floor is the
development registry's: a mainnet operator pins the production registry, whose own chain starts at
version 1 and whose genesis already revokes the 0.7.2 build, and sets that registry's floor. Accounts created on testnet
from the old code, including by the harness, the demo and the wallet, are then refused and are
not upgraded in place: recreate them from the current code. Execution and the wallet accept only
the pinned code whatever the floor. Details are in
[`docs/SOROBAN-DEPENDENCIES.md`](docs/SOROBAN-DEPENDENCIES.md#account-073-ghsa-jpg9-m7w4-c7wc).

When a fixed upstream release cannot be adopted yet, as for RUSTSEC-2026-0387, the exposure is
accepted explicitly, with a reviewed scope and an expiry
([`docs/SECURITY-EXCEPTIONS.md`](docs/SECURITY-EXCEPTIONS.md)). The
[incident-response guide](docs/INCIDENT-RESPONSE.md#d-an-upstream-advisory) walks through the
advisory above as a worked example.

## Supported versions

The first two milestones are delivered in this repository, and later ones land in it too. During
the grant period the latest release line is supported: fixes go on `main` and into its next
release. There are no maintained release branches and no backports to earlier releases. After the
grant period no version is supported; the code stays open source for anyone to run, fork or
maintain.
