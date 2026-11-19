# Documentation

Find your role, then start at the first document listed for it. Each document appears once, under
the reader it is mainly written for.

## Users: you run the agent and own the account

- [USER-GUIDE.md](USER-GUIDE.md) — the path from a recorded transaction to an installed, used and revoked grant.
- [TESTER-QUICKSTART.md](TESTER-QUICKSTART.md) — run the whole flow locally on testnet, and what to report.
- [SCOPING-DECISIONS.md](SCOPING-DECISIONS.md) — every decision that shapes a grant and what it means for safety.
- [TRUST-BOUNDARIES.md](TRUST-BOUNDARIES.md) — what is guaranteed, who holds which key, where trust is checked.
- [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md) — what to do when something a grant relies on is revoked or compromised.
- [MCP-WALKTHROUGH.md](MCP-WALKTHROUGH.md) — the MCP server and Claude skill, and what each tool needs.
- [WALKTHROUGH-SEP41.md](WALKTHROUGH-SEP41.md) — W2: a SEP-41 subscription with the reviewed spending limit.
- [WALKTHROUGH-PROTOCOLS.md](WALKTHROUGH-PROTOCOLS.md) — W3: a bounded Soroswap swap, and W1: a Blend claim.

## Wallet integrators

- [POLLYWALLET-INTEGRATION.md](POLLYWALLET-INTEGRATION.md) — the reference integration: consent, checks, passkey install, use, revoke.
- [AGENT-WALLET-HANDOFF.md](AGENT-WALLET-HANDOFF.md) — direct local delivery of a confirmed proposal from Claude to the wallet.
- [INSTALL-ASSEMBLY.md](INSTALL-ASSEMBLY.md) — the unsigned install transaction and what a wallet must check before signing.
- [LIVE-POLICY-CHECK.md](LIVE-POLICY-CHECK.md) — predicting one call against an installed rule.
- [DRY-RUN-PREPARATION.md](DRY-RUN-PREPARATION.md) — the four dry-run layers and the report's acceptance fields.
- [NATIVE-EXECUTION.md](NATIVE-EXECUTION.md) — the account-Wasm layer's native worker and `ozpb dry-run`.
- [CAPTURED-TARGET-EXECUTION.md](CAPTURED-TARGET-EXECUTION.md) — the captured-target layer.
- [ATOMIC-LIVE-HELPER.md](ATOMIC-LIVE-HELPER.md) — the live-enforcement helper contract and its testnet deployment.
- [ACCOUNT-METHOD-INVENTORY.md](ACCOUNT-METHOD-INVENTORY.md) — the reviewed method inventory of the pinned account.

## Self-hosters and operators

- [SELF-HOSTING.md](SELF-HOSTING.md) — run the MCP endpoint yourself for trusted clients.
- [ISOLATED-BUILDS.md](ISOLATED-BUILDS.md) — disposable build workers on a separate host.
- [SOROBAN-DEPENDENCIES.md](SOROBAN-DEPENDENCIES.md) — which SDK, accounts and protocol versions each part pins, and why.
- [PROTOCOL-30-VALIDATION.md](PROTOCOL-30-VALIDATION.md) — protocol 30 compatibility observations.

## Registry custodians

- [REGISTRY-GOVERNANCE.md](REGISTRY-GOVERNANCE.md) — keys, signing, publishing, monitoring, revocation, rotation.
- [../registry/mainnet/README.md](../registry/mainnet/README.md) — the unsigned mainnet genesis draft.

## Security auditors

- [AUDIT-SCOPE.md](AUDIT-SCOPE.md) — the entry point: components, threat model, known limits, gates.
- [MAINNET-GATES.md](MAINNET-GATES.md) — each acceptance gate before mainnet use, its status and the tests CI runs for it.
- [../SECURITY.md](../SECURITY.md) — disclosure policy, and what is deliberately not claimed.
- [architecture.md](architecture.md) — the full technical architecture and delivery plan.
- [SCOPE.md](SCOPE.md) — what is implemented, and the limits each part keeps.
- [CANONICAL-HASHING.md](CANONICAL-HASHING.md) — the hash specification an independent implementation follows.
- [RECORDING-EVIDENCE.md](RECORDING-EVIDENCE.md) — the recording format and what a recording hash does and does not prove.
- [SECURITY-EXCEPTIONS.md](SECURITY-EXCEPTIONS.md) — advisories accepted temporarily, with their expiry.
- [TESTNET-EVIDENCE.md](TESTNET-EVIDENCE.md) — first-milestone testnet evidence.
- [TESTNET-EVIDENCE-TRANCHE-2.md](TESTNET-EVIDENCE-TRANCHE-2.md) — second-milestone runs, and how to capture a new one.

## OpenZeppelin reviewers

- [OZ-REVIEW-PACKAGE.md](OZ-REVIEW-PACKAGE.md) — the entry point for reviewing the generated code.
- [ECOSYSTEM-CONFORMANCE.md](ECOSYSTEM-CONFORMANCE.md) — the platform's and OpenZeppelin's conventions, and where we diverge.
- [TARGET-ADAPTERS.md](TARGET-ADAPTERS.md) — the reviewed target-adapter design and its one binding.

## Stellar Community Fund reviewers

- [TRANCHE-1-VERIFICATION.md](TRANCHE-1-VERIFICATION.md) — reproduce the first milestone.
- [TRANCHE-2-VERIFICATION.md](TRANCHE-2-VERIFICATION.md) — the second milestone's checks and evidence crosswalk.
- [TRANCHE-3-VERIFICATION.md](TRANCHE-3-VERIFICATION.md) — the third milestone's verification record (accepted deviations are recorded there).

## Contributors

- [DEVELOPERS.md](DEVELOPERS.md) — the CLI, how synthesis decides scope, and the invariants CI enforces.
- [EXTENDING.md](EXTENDING.md) — adding a constraint kind, a target adapter or a wallet integration.
- [CHANGE-REVIEW-PLAN.md](CHANGE-REVIEW-PLAN.md) — how changes to evidence, authority and installation are reviewed.
- [../CONTRIBUTING.md](../CONTRIBUTING.md) — DCO, gates, commit messages and documentation rules.
- [release-notes/](release-notes/) — breaking changes, security fixes and additions per release.

[`examples/`](examples/) holds runnable inputs, and [`evidence/`](evidence/) the published run
summaries the evidence records cite.
