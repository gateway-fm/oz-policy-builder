# Tranche 3 verification guide

This guide maps each contracted item of the third milestone to what this tree implements and to
what remains, naming whom each remaining step rests on. It claims nothing the tree does not
hold: no mainnet installation, audit report or OpenZeppelin sign-off is recorded here.
[MAINNET-GATES.md](MAINNET-GATES.md) states, for each acceptance gate before any mainnet use,
whether its tests close it and every deviation that keeps a gate narrowed or open. This guide
records the owner's acceptance of those deviations, and of the five it states itself, each against
the revision it was accepted for.

## Contracted outcome and milestone boundary

[Issue #4](https://github.com/gateway-fm/oz-policy-builder/issues/4) records the Tranche 3
requirements: a production versioned endpoint, documentation and a full test suite;
security-audit remediation through the SCF Soroban Security Audit Bank; documented OpenZeppelin
technical-reviewer sign-off on generated-code quality before mainnet; and one mainnet wallet
integration. Its verifiable outcome is a mainnet install of a generated policy, and a published
audit report with its remediation. The proposal's payment schedule adds professional user
testing at the mainnet launch. [Architecture Phase 3](architecture.md#10-delivery-plan) gives
the technical design and the acceptance gates before any mainnet use.

The order ([the order for 1.0.0](VERSIONING.md#the-order-for-100)): OpenZeppelin's review and
the audit start together on one freeze commit; after OpenZeppelin's documented sign-off and the
owner's acceptance below, the mainnet registry is signed and a `1.0.0-rc.N` release candidate
carries it; the one mainnet installation is made from that candidate; the audit's report and
remediation lead to a registry successor whose template-pack reference adds the report, and to
1.0.0, which carries it; the installation is repeated from 1.0.0 only if a remediated finding
changes the installed policy's code or the shape of the grant. The milestone is submitted
with both outcomes: the installation's evidence and the published audit report with its
remediation.

| Contracted item | What this tree implements | What remains, and on whom |
| --- | --- | --- |
| Production versioned endpoint | A release operators run themselves; Gateway operates no service. [VERSIONING.md](VERSIONING.md) says what 1.0.0 keeps stable and gives the release gate. The tree's own MCP wire contract is committed as [`wire-contract.json`](wire-contract.json): CI fails when the built server serves another, and an `api-types` test pins the `E_*` codes to it ([keeping the snapshot current](VERSIONING.md#keeping-the-snapshot-current)). `release-binaries.yml` builds `ozpb`, `ozpb-mcp-server` and the native worker for three platforms, with `SHA256SUMS`, the MCP wire contract and build-provenance attestations; `publish-image.yml` publishes the images. [Self-hosting](SELF-HOSTING.md#production-release) says how to verify, configure (mainnet included) and upgrade them. The HTTP endpoint's tests are [G12](MAINNET-GATES.md#g12-hosted-processing). | No release candidate or 1.0.0 release exists: the workspace version is 0.1.0. Both are the owner's, in [the order for 1.0.0](VERSIONING.md#the-order-for-100): `1.0.0-rc.N` for the mainnet installation, then 1.0.0 after the audit's remediation. G12 is open: log redaction is checked in the shipped configuration, not observed in what a running endpoint retains. |
| Documentation | By reader in the [documentation index](README.md): usage ([user guide](USER-GUIDE.md), [tester quickstart](TESTER-QUICKSTART.md), [MCP server](MCP-WALKTHROUGH.md)), the [scoping-decision rationale](SCOPING-DECISIONS.md), [trust boundaries](TRUST-BOUNDARIES.md), the [extension guide](EXTENDING.md) for primitives, adapters and wallets, [registry governance](REGISTRY-GOVERNANCE.md), the [disclosure policy](../SECURITY.md), [incident and revocation guidance](INCIDENT-RESPONSE.md) and the owner's [mainnet runbook](MAINNET-INSTALL.md). | Nothing is recorded yet for the audit or the mainnet installation; the [remediation log](AUDIT-REMEDIATION.md) and the runbook's [evidence to keep](MAINNET-INSTALL.md#evidence-to-keep) say what each will hold. |
| Full test suite | CI on every pull request (`.github/workflows/ci.yml`); the Wasm and pinned-account gates nightly, on demand and on path changes (`nightly-live.yml`); mutation testing of the eight pure cores, on the lines a pull request changes and weekly in full (`mutation.yml`); the [mainnet gate map](MAINNET-GATES.md), whose named tests CI runs by full name (`scripts/check-mainnet-gates.sh`); the recorder's mainnet corpus (`crates/source-rpc/tests/mainnet_corpus.rs`); the wire-contract check against the built server (`scripts/release-artifacts.py check-wire-contract`) and the wallet's typed install surface held to it (`wallet/tests/install-wire.test.mjs`); and the release gate (`scripts/verify-phase2.sh`). [AUDIT-SCOPE](AUDIT-SCOPE.md#building-and-running-the-gates) lists every command. | The gate map's open gates (G2, G9, G10, G12) and narrowed ones (G6, G7, G11), each with what would close it, and its review gate, G14. Architecture §8's mainnet walkthroughs are narrowed to one installation ([below](#deviations-for-the-owners-acceptance)). Accepting a deviation is the owner's; closing an open gate is the project's. |
| Security-audit remediation through the SCF Audit Bank | The audit's entry point, [AUDIT-SCOPE.md](AUDIT-SCOPE.md): components in two tiers with line counts, trust boundaries, threat model, invariants with their tests, known limits and every gate. Already triaged: Aikido's static-analysis items ([SAST-TRIAGE.md](SAST-TRIAGE.md)) and the temporarily accepted advisory ([SECURITY-EXCEPTIONS.md](SECURITY-EXCEPTIONS.md)). [AUDIT-REMEDIATION.md](AUDIT-REMEDIATION.md) is the remediation log. | The audit itself: no report has been received and the log is empty. Applying to the Audit Bank and naming the freeze commit are the owner's; the report is the auditor's; remediation, each fix with its regression test, is the project's. The audit runs on the freeze commit alongside OpenZeppelin's review; its report and remediation precede 1.0.0, not the mainnet installation ([deviation 6](#deviations-for-the-owners-acceptance)), and a mainnet registry successor adds the report to the template pack's review reference. |
| Documented OpenZeppelin sign-off on generated-code quality, before mainnet | The [review package](OZ-REVIEW-PACKAGE.md): what to read, how a generated policy uses `stellar-accounts`, the version pairing, where each of the five review gates stands, the upstream items, and a [review record](OZ-REVIEW-PACKAGE.md#review-record) for the sign-off. | OpenZeppelin's review and documented sign-off, theirs to give; the review record is empty. The sign-off row comes before the mainnet registry's key ceremony, whose template-pack review reference cites it, and before the release candidate the installation is made from. The generated-code changes the package lists as made, the emitter's single-guard fix among them, are in this tree, and none is planned beyond the upstream items ([what will still change](OZ-REVIEW-PACKAGE.md#what-will-still-change-before-the-audited-revision)). |
| One mainnet wallet integration | The Pollywallet integration's [mainnet sessions](POLLYWALLET-INTEGRATION.md#mainnet-sessions): a production build of the page, the operator's fee payer and the agent's delegate key from 0600 files, per-transaction, upload and session fee caps, production registry trust only, readiness checks, and removal of a grant an earlier session installed; an operator-funded testnet profile runs the same funding and custody model on testnet ([rehearse on testnet](MAINNET-INSTALL.md#rehearse-on-testnet)). It installs [the shipped grant shape](MAINNET-GATES.md#the-grant-shape-this-tranche-ships) after all four check layers pass. | A signed production registry, from the custodians' key ceremony. The owner's helper deployment, funding and passkey ([runbook](MAINNET-INSTALL.md)). On the agent side the direct handoff reaches only a testnet wallet ([MCP on mainnet](MCP-WALKTHROUGH.md#6-on-mainnet)). |
| Professional user testing at the mainnet launch (the proposal's payment schedule) | The [tester quickstart](TESTER-QUICKSTART.md): the whole flow locally on testnet, and what a tester reports. | What the testing involves is SCF's to say, and asking is the owner's. Nothing in this tree records it. |
| **Outcome:** a mainnet install of a generated policy | The path in the row above, the [evidence to keep](MAINNET-INSTALL.md#evidence-to-keep) for it, and [publishing the installed policy](MAINNET-INSTALL.md#publishing-the-installed-policy) so that a reviewer can check its code against the chain with `ozpb verify-published`. | Not done: no mainnet installation is recorded in this tree. It is the owner's, with a person's passkey, from the `1.0.0-rc.N` release candidate, and again from 1.0.0 only if a remediated audit finding changes the installed policy's code or the shape of the grant. |
| **Outcome:** a published audit report and its remediation | [AUDIT-REMEDIATION.md](AUDIT-REMEDIATION.md), with an empty report and findings table. | Not done: no report exists. Publication follows the audit; the milestone is submitted with it and the installation's evidence together. |

### Against the Phase 3 design

The design items the rows above do not already cover:

| Design item | Where it stands |
| --- | --- |
| Security audit across the full authorization-to-install path ([§6.4](architecture.md#64-audit-scope-committed)) | Scoped in [AUDIT-SCOPE.md](AUDIT-SCOPE.md); [G14](MAINNET-GATES.md#g14-security-review) is its review gate. Not performed. |
| Source and manifests published keyed by Wasm hash | Implemented as tooling ([publishing](PUBLISHING.md)): `ozpb publish-artifact` writes the generated crate, spec, BuildManifest and Wasm with a `SHA256SUMS` index to `<wasm hash>/<manifest hash>/`, refusing files the manifest does not describe, and `ozpb verify-published` checks such a build and reproduces it through `verify`. Hosting a build is its publisher's; the project publishes none of its own, and the release workflow attaches no generated policy. A reproduction is still a rerun of an unattested manifest ([G9](MAINNET-GATES.md#g9-artifact-chain-and-buildmanifest)). |
| Registry governance: transparency log, monitoring, revocation procedure | Implemented and documented ([registry governance](REGISTRY-GOVERNANCE.md)). The mainnet log is an unsigned draft until its key ceremony, and revoking an account build or an owner verifier has documented owner procedures but no tooled or exercised path ([G10](MAINNET-GATES.md#g10-registry-governance)). |

## Deviations for the owner's acceptance

A narrowed or open gate is not accepted by being listed, and neither is anything below. The
deviations to accept or refuse are:

1. **Each narrowed or open gate's deviation**, as the [gate map's summary](MAINNET-GATES.md#summary)
   states it.
2. **Architecture §8's mainnet walkthroughs narrowed to one installation.**
   [§8](architecture.md#8-testing-strategy) plans the walkthroughs "against mainnet manually at
   release gates". The mainnet run this milestone contemplates is the single native-XLM
   installation of [the shipped grant shape](MAINNET-GATES.md#the-grant-shape-this-tranche-ships),
   through the wallet, repeated from 1.0.0 only as deviation 6 says. The Blend, SEP-41 and
   Soroswap walkthroughs stay on testnet: the harness that runs them is bound to testnet, there
   is no Blend adapter, and the mainnet registry draft carries no target-adapter binding, since
   the Soroswap binding is a testnet-only development-registry assertion
   ([mainnet registry](../registry/mainnet/README.md)). This narrows §8; the one installation is
   not a relabelling of the three walkthroughs as run on mainnet.
3. **The wallet host holds the agent's delegate key on mainnet.**
   [§6.2](architecture.md#62-custody-and-signing-boundary) says no component handles secret keys.
   A mainnet installation requires the agent's delegate secret in a 0600 file on the wallet host,
   because three of the four check layers sign as the delegate, and the wallet backend also holds
   the operator's fee-payer key ([SECURITY.md](../SECURITY.md#what-this-milestone-does-and-does-not-claim)).
4. **The wallet's install types are hand-written and drift-tested, not generated.**
   [§4.11](architecture.md#411-engineering-architecture--workspace-boundaries-and-idioms) planned
   the wallet's MCP payload types as generated from the `api-types` JSON Schemas. The two
   wallet-facing install tools' request and response types are hand-written declarations
   (`wallet/shared/install-wire.d.mts`), so no generator dependency is added, held to the published
   schemas in [`wire-contract.json`](wire-contract.json) by `wallet/tests/install-wire.test.mjs`,
   which fails on any difference in a field's name, whether it is required, or its type. The other
   tools' payloads are not declared in TypeScript, except where the install tools carry them (the
   authority check's request and answer).
5. **The native worker ships on a release candidate.** The offline worker that runs the account-Wasm
   check layer builds against `soroban-sdk` 30.0.0-rc.1. The stable SDK 30.0.0 requires a newer
   host, which changes the dependency inventory of a temporary advisory risk acceptance; moving
   needs that acceptance reassessed first
   ([release notes](release-notes/v1.0.0.md#the-native-worker-ships-on-a-release-candidate),
   [security exceptions](SECURITY-EXCEPTIONS.md)).
6. **The mainnet installation precedes the audit's report and remediation.**
   [Architecture §10](architecture.md#10-delivery-plan) lists the security review of the
   authorization-to-install path among the acceptance gates before any mainnet use
   ([G14](MAINNET-GATES.md#g14-security-review)). The milestone asks for
   OpenZeppelin's sign-off "before mainnet" and for the published audit report and remediation
   as an outcome. The one installation of deviation 2 is made from a release candidate once
   OpenZeppelin's sign-off and these acceptance rows are recorded, while the audit may still be
   running; G14 closes with the audit's report and remediation, before 1.0.0. OpenZeppelin's
   sign-off covers the generated code only, so recording, synthesis, the authority check and the
   wallet's install path are used on mainnet before any audit finding about them is known. If a
   remediated finding changes the installed policy's code or the shape of the grant, the
   installation is repeated from 1.0.0 ([the order for 1.0.0](VERSIONING.md#the-order-for-100)).

## Acceptance recorded here

One row per accepted deviation, against the revision it was accepted for. An empty table means
no acceptance is recorded.

| Deviation | Revision | Accepted by | Date | Note |
| --- | --- | --- | --- | --- |

## Running the checks

[AUDIT-SCOPE.md](AUDIT-SCOPE.md#building-and-running-the-gates) gives every gate with its
prerequisites; the [Tranche 2 guide](TRANCHE-2-VERIFICATION.md#run-the-automated-checks) says what
the release gate and the focused evidence checks establish. Record `git rev-parse HEAD` and
`git status --short` with the results: a passing run is evidence for that revision only.
