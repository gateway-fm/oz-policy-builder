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
- External-verifier signers are rejected outright, because nothing at authorization time
  binds a verifier address to the executable a registry recognizes.
- The reference evaluator models the generated scope policy. It returns `indeterminate`, never
  a whole-composition `permit`, when an attached reviewed policy is not modelled.
- The local build runner bounds environment, inputs, outputs, concurrency and time. It is not
  a multi-tenant sandbox and is not offered as one.
- Nothing in this toolkit signs, submits, or deploys, and it holds no keys.
- No independent third-party audit has been performed. The evidence that has actually been
  run is listed in `docs/SCOPE.md` and `docs/TESTNET-EVIDENCE.md`; test counts are not treated
  as assurance.

A report that one of the above is true is a report we already agree with. A report that one of
them is *false* — that a claimed fail-closed path can be made to open — is the one we want.

## Supported versions

One milestone is implemented so far, and later ones land in this same repository. Fixes go on
`main`; there are no maintained release branches, and no backports.
