# Tranche 3 verification guide

This guide maps each contracted item of the third milestone to what this tree implements and to
what remains, naming whom each remaining step rests on. It claims nothing the tree does not
hold: no mainnet installation, audit report or OpenZeppelin sign-off is recorded here.
[MAINNET-GATES.md](MAINNET-GATES.md) states, for each acceptance gate before any mainnet use,
whether its tests close it and every deviation that keeps a gate narrowed or open. This guide
records the owner's acceptance of those deviations, and of the two it states itself, each against
the revision it was accepted for.

## Contracted outcome and milestone boundary

[Issue #4](https://github.com/gateway-fm/oz-policy-builder/issues/4) records the Tranche 3
requirements: a production versioned endpoint, documentation and a full test suite;
security-audit remediation through the SCF Soroban Security Audit Bank; documented OpenZeppelin
technical-reviewer sign-off on generated-code quality before mainnet; and one mainnet wallet
integration. Its verifiable outcome is a mainnet install of a generated policy, and a published
audit report with its remediation. [Architecture Phase 3](architecture.md#10-delivery-plan) gives
the technical design and the acceptance gates before any mainnet use.

| Contracted item | What this tree implements | What remains, and on whom |
| --- | --- | --- |
| Production versioned endpoint | A release operators run themselves; Gateway operates no service. [VERSIONING.md](VERSIONING.md) says what 1.0.0 keeps stable and gives the release gate. `release-binaries.yml` builds `ozpb`, `ozpb-mcp-server` and the native worker for three platforms, with `SHA256SUMS`, the MCP wire contract and build-provenance attestations; `publish-image.yml` publishes the images. [Self-hosting](SELF-HOSTING.md#production-release) says how to verify, configure (mainnet included) and upgrade them. The HTTP endpoint's tests are [G12](MAINNET-GATES.md#g12-hosted-processing). | No 1.0.0 release exists: the workspace version is 0.1.0. The release is the owner's, after the steps in [the order for 1.0.0](VERSIONING.md#the-order-for-100). G12 is open: log redaction has no automated test. |
| Documentation | By reader in the [documentation index](README.md): usage ([user guide](USER-GUIDE.md), [tester quickstart](TESTER-QUICKSTART.md), [MCP server](MCP-WALKTHROUGH.md)), the [scoping-decision rationale](SCOPING-DECISIONS.md), [trust boundaries](TRUST-BOUNDARIES.md), the [extension guide](EXTENDING.md) for primitives, adapters and wallets, [registry governance](REGISTRY-GOVERNANCE.md), the [disclosure policy](../SECURITY.md), [incident and revocation guidance](INCIDENT-RESPONSE.md) and the owner's [mainnet runbook](MAINNET-INSTALL.md). | Nothing is recorded yet for the audit or the mainnet installation; the [remediation log](AUDIT-REMEDIATION.md) and the runbook's [evidence to keep](MAINNET-INSTALL.md#evidence-to-keep) say what each will hold. |
| Full test suite | CI on every pull request (`.github/workflows/ci.yml`); the Wasm and pinned-account gates nightly, on demand and on path changes (`nightly-live.yml`); mutation testing of the eight pure cores, on the lines a pull request changes and weekly in full (`mutation.yml`); the [mainnet gate map](MAINNET-GATES.md), whose named tests CI runs by full name (`scripts/check-mainnet-gates.sh`); the recorder's mainnet corpus (`crates/source-rpc/tests/mainnet_corpus.rs`); and the release gate (`scripts/verify-phase2.sh`). [AUDIT-SCOPE](AUDIT-SCOPE.md#building-and-running-the-gates) lists every command. | The gate map's open gates (G2, G9, G10, G12) and narrowed ones (G6, G7, G11), each with what would close it, and its review gate, G14. Architecture §8's mainnet walkthroughs are narrowed to one installation ([below](#deviations-for-the-owners-acceptance)). Accepting a deviation is the owner's; closing an open gate is the project's. |
| Security-audit remediation through the SCF Audit Bank | The audit's entry point, [AUDIT-SCOPE.md](AUDIT-SCOPE.md): components in two tiers with line counts, trust boundaries, threat model, invariants with their tests, known limits and every gate. Already triaged: Aikido's static-analysis items ([SAST-TRIAGE.md](SAST-TRIAGE.md)) and the temporarily accepted advisory ([SECURITY-EXCEPTIONS.md](SECURITY-EXCEPTIONS.md)). [AUDIT-REMEDIATION.md](AUDIT-REMEDIATION.md) is the remediation log. | The audit itself: no report has been received and the log is empty. Applying to the Audit Bank and naming the freeze commit are the owner's; the report is the auditor's; remediation, each fix with its regression test, is the project's. |
| Documented OpenZeppelin sign-off on generated-code quality, before mainnet | The [review package](OZ-REVIEW-PACKAGE.md): what to read, how a generated policy uses `stellar-accounts`, the version pairing, where each of the five review gates stands, the upstream items, and a [review record](OZ-REVIEW-PACKAGE.md#review-record) for the sign-off. | OpenZeppelin's review and documented sign-off, theirs to give; the review record is empty. The emitter change the package lists under [what will still change](OZ-REVIEW-PACKAGE.md#what-will-still-change-before-the-audited-revision) alters generated code before the audited revision. |
| One mainnet wallet integration | The Pollywallet integration's [mainnet sessions](POLLYWALLET-INTEGRATION.md#mainnet-sessions): a production build of the page, the operator's fee payer and the agent's delegate key from 0600 files, per-transaction, upload and session fee caps, production registry trust only, readiness checks, and removal of a grant an earlier session installed. It installs [the shipped grant shape](MAINNET-GATES.md#the-grant-shape-this-tranche-ships) after all four check layers pass. | Protocol 30 on mainnet, which its validators decide. A signed production registry, from the custodians' key ceremony. The owner's helper deployment, funding and passkey ([runbook](MAINNET-INSTALL.md)). On the agent side the direct handoff reaches only a testnet wallet ([MCP on mainnet](MCP-WALKTHROUGH.md#6-on-mainnet)). |
| **Outcome:** a mainnet install of a generated policy | The path in the row above, and the [evidence to keep](MAINNET-INSTALL.md#evidence-to-keep) for it. | Not done: no mainnet installation is recorded in this tree. It is the owner's, with a person's passkey, from the 1.0.0 release. |
| **Outcome:** a published audit report and its remediation | [AUDIT-REMEDIATION.md](AUDIT-REMEDIATION.md), with an empty report and findings table. | Not done: no report exists. Publication follows the audit. |

### Against the Phase 3 design

The design items the rows above do not already cover:

| Design item | Where it stands |
| --- | --- |
| Security audit across the full authorization-to-install path ([§6.4](architecture.md#64-audit-scope-committed)) | Scoped in [AUDIT-SCOPE.md](AUDIT-SCOPE.md); [G14](MAINNET-GATES.md#g14-security-review) is its review gate. Not performed. |
| Source and manifests published keyed by Wasm hash | Not delivered: nothing publishes them ([§6.3](architecture.md#63-reproducibility-and-artifact-provenance), scope note). The runbook has the owner keep a grant's BuildManifest with its installation's evidence, and `ozpb verify` reproduces source and Wasm from the spec; a manifest is its producer's unattested statement ([G9](MAINNET-GATES.md#g9-artifact-chain-and-buildmanifest)). |
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
   through the wallet. The Blend, SEP-41 and Soroswap walkthroughs stay on testnet: the harness
   that runs them is bound to testnet, there is no Blend adapter, and the mainnet registry draft
   carries no target-adapter binding, since the Soroswap binding is a testnet-only
   development-registry assertion ([mainnet registry](../registry/mainnet/README.md)). This
   narrows §8; the one installation is not a relabelling of the three walkthroughs as run on
   mainnet.
3. **The wallet host holds the agent's delegate key on mainnet.**
   [§6.2](architecture.md#62-custody-and-signing-boundary) says no component handles secret keys.
   A mainnet installation requires the agent's delegate secret in a 0600 file on the wallet host,
   because three of the four check layers sign as the delegate, and the wallet backend also holds
   the operator's fee-payer key ([SECURITY.md](../SECURITY.md#what-this-milestone-does-and-does-not-claim)).

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
