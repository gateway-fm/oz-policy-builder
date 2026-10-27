# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: **Security → Advisories → Report a
vulnerability** on this repository. That opens a channel visible only to the maintainers, so
no address has to be guessed and nothing lands in a public issue first. Please do not open a
public issue for a security report. If that option is not visible to you, open an issue that
says only that you have a security report and asks for a private channel — no details, and we
will open one.

Useful in a report, roughly in order: the commit you looked at, the input that reaches the
defect (a `PolicySpec`, a recording bundle, a registry snapshot, an RPC response), what the
code does with it, and what a caller gains. A generated policy that permits more than its
spec describes, a validator that accepts a spec codegen cannot render safely, an evidence
label a caller can raise, or a registry snapshot that widens a capability are all in scope
and all interesting.

We will acknowledge a report and tell you what we think of it. There is no bounty.

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
  fee-payer keys. The demo script, the testnet harness and the local wallet backend do, on
  testnet only, with disposable keys they generate; the wallet's owner signs with the user's
  own passkey.
- `ozpb dry-run` is the one CLI command that holds a key: the spec delegate's, read only from a
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
- No independent third-party audit has been performed. The evidence that has actually been
  run is in `docs/TESTNET-EVIDENCE.md` and, for the second milestone's controlled testnet
  harness runs, `docs/TESTNET-EVIDENCE-TRANCHE-2.md`; those runs are local RPC observations,
  not ledger proofs or wallet approval. `docs/SCOPE.md` says what deliberately has not been
  run; test counts are not treated as assurance.

A report that one of the above is true is a report we already agree with. A report that one of
them is *false* — that a claimed fail-closed path can be made to open — is the one we want.

## Supported versions

One milestone is implemented so far, and later ones land in this same repository. Fixes go on
`main`; there are no maintained release branches, and no backports.
