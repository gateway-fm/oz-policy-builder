# Testnet & runtime evidence — Tranche 2

> **Scope: Tranche 2.** This file records the evidence for the second milestone: the full
> smart-account install with on-chain permit/deny (§4), the browser/passkey UX driven
> headless (§5), and the `dry_run` tool over MCP stdio (§6). Screenshots for these runs are in
> `docs/media/`, which `testnet-harness/browser/README.md` also cites.
> The first milestone's evidence is in `docs/TESTNET-EVIDENCE.md`, which holds §1–§3.
>
> The runs below happened, on live testnet, with the addresses and transaction hashes given.
> Keeping them out of a first-milestone delivery is a statement about which milestone contracts
> them, not about their standing as evidence.

Verifiable evidence gathered by running the toolkit against **live Stellar testnet**
(Protocol 27). Reproducible with the commands noted; testnet identities are throwaway
(Friendbot-funded, no real value) and are kept out of the repo.

Section numbers continue from `docs/TESTNET-EVIDENCE.md`, so a citation such as "§4" names the
same section of the evidence whichever file holds it, and re-partitioning the set renumbers
nothing.

## 4. Full OZ smart-account install + on-chain permit/deny (the RFP's Phase-2 outcome)

The complete **record → generate → deploy → install → permit/deny** loop, executed on real
testnet with a policy this toolkit generated — using an ed25519 session signer (no passkey/
browser). Reproducible harness: `testnet-harness/`.

- **OZ smart account** deployed + initialized, admin rule = `External(verifier, ed25519)`:
  `CBSMG5UBESWKZK4CIFNCXMPOSQ4VS3C2FSE6HQMRGDE4HJT574MPKQ4M`
- **ed25519 verifier** (OZ example): `CAPZOJAAQ354OXCYVDO5I3ZH2PK3SRUVGSKA7TCUTCUFGXOIZ664X4B7`
- **Generated native-SAC policy** (`transfer(from=SELF, to=G, amount==10_000_000)`, strict
  External signer): `CBVNZA3LETWWWKHJ3V7W73SXQVUWZDN7IUTIGISCJTE7QXYVCLPAWNBC`
- **Install** via `add_context_rule`, authorized by a **hand-built `AuthPayload`** carrying
  `ed25519_sign(sha256(signature_payload ‖ xdr(context_rule_ids)))` — the custom-account
  signing `smart-account-kit` wraps, done directly here. The account's `__check_auth` ran,
  the verifier checked the signature, and `install()` executed on-chain:
  install tx `34a91aa99108fcd00e6ba027be4cf0196977c893f5668098c8d996f36af7a86f`.
- **PERMIT** (on-chain SUCCESS): the account transferred exactly 10,000,000 to the allowed
  recipient through the installed rule — real XLM moved, gated by the policy's `enforce`:
  tx `f7db6fed7695424f446d996ba570573de20e82cd61cfddeb722b8314f3767684`.
- **DENY** (reverted by the policy): a transfer of 10,000,001 (one over the exact amount) and
  a transfer to a different recipient both reverted with `Error(Auth, InvalidAction)` — the
  policy's `enforce` panicked (`NoTupleMatched`).

> **Which build the two upstream addresses refer to — not the pinned hashes.** This run
> predates the pinned upstream wasm hashes (`crates/domain/src/lib.rs`, module
> `pinned_upstream`, added 2026-08-12 in `3e63582`). Both upstream contracts above were
> deployed from wasm **built locally**, not from a pinned hash: the account from the harness's
> own copy of OpenZeppelin's `examples/multisig-smart-account/account` — a minimal adaptation
> with the `Upgradeable` extension removed, kept then at `testnet-harness/oz-account/` and
> added together with this evidence in `8ad21e6` — and the verifier from their
> `ed25519-verifier` example, at a toolchain nobody recorded. So the code hash of the account
> above (`CBSMG5UB…`) is **not**
> `a12747ff6c139dc14fc2fd30d200d6bbb5da7b5d59812c047ce1f9cad226b289`, the value now pinned as
> `OZ_SMART_ACCOUNT_WASM`: it was built from different source. The verifier's source was
> upstream's, but a pinned hash reproduces only with the pinned compiler (provenance table on
> `pinned_upstream`), so the verifier above (`CAPZOJ…`) cannot be assumed to carry
> `60e8798db610bdaf3370d39ebda56ee1dc2c15ce1c3a9e28b528bfa24a06b477` either. Neither instance
> had its code hash recorded at deploy time, and the addresses do not yield one afterwards.
>
> The permit/deny result stands on its own: what executed was OpenZeppelin's
> `stellar-accounts` 0.7.2 `__check_auth` → policy path, built from their source, driving a
> policy this toolkit generated. What the divergence does mean is that these two instances
> would **not** resolve through the toolkit as it stands today — `synthesize` looks the
> authorizer's observed code hash up in the signed registry snapshot
> (`Registry::resolve_account`) and an External signer's verifier hash likewise
> (`resolve_verifier`), and both fail closed on anything the snapshot does not pin. So nothing
> in the current flow builds either contract locally: `scripts/demo-tranche1.sh`
> deploys the account with `stellar contract deploy --wasm-hash a12747ff…` and then asserts
> that the code hash the network reports back equals the pin, which doubles as a live check of
> the pin itself. `testnet-harness/` now takes the same path, and its local copy of the account
> is removed; it remains in history at `8ad21e6` for anyone reproducing this particular run
> byte-for-byte.

This is the same permit/deny behaviour the differential suite proves against the compiled
contract locally, now confirmed on live testnet through the full custom-account
authorization path.

A real bug this surfaced: the generated `Cargo.toml` lacked the `[profile.release]` with
`overflow-checks` that standalone `stellar contract build` requires (it built before only
inside a workspace that supplied it). Fixed in codegen; goldens regenerated.

## 5. pollywallet + headless passkey (browser UX), via Playwright

Driven with a Playwright CDP **virtual WebAuthn authenticator** in headless Chromium — no
hardware, no display. Harness: `testnet-harness/browser/`.

- **Self-contained passkey proof**: headless Chromium creates a **secp256r1 (ES256, alg −7
  — Stellar's passkey curve)** credential and signs a 32-byte install-shaped challenge
  (71-byte signature; resident key stored on the authenticator); a `.webm` is recorded.
- **pollywallet's REAL UI, headless**: cloned `kalepail/pollywallet`, `pnpm install`, unit
  suite 53/54 (the 1 failure is an expired live-testnet fixture). Booted its dev server
  locally (after stripping the Workers-AI binding that forces remote mode) and drove its
  actual **"Create Smart Wallet"** button — pollywallet's own `@simplewebauthn/browser`
  passkey registration completed under the virtual authenticator (1 resident credential;
  `docs/media/pollywallet-passkey-headless.png`).
- The pollywallet flow then failed at its **server-side deploy** (the OpenZeppelin Channels
  relayer backend — needs relayer config/keys), a backend dependency, not a browser/passkey
  limit. pollywallet's heavy dev deps — Workers AI (AI codegen) and a Docker Rust compile
  **sandbox** — are exactly the non-deterministic pieces this toolkit *replaces*; an
  integration drops them and points signing at Channels (configured) or direct RPC.

So the browser + passkey UX is drivable headless end to end; the only gap to a full
pollywallet install run is relayer configuration.

## 6. MCP server `dry_run` over stdio

Recorded when this evidence was first written, and kept here rather than with the first
milestone's MCP evidence (§3) because `dry_run` is a tool a later milestone contracts
(`architecture.md` §4.6). It is the original observation, moved — not re-run for this record.

- An `initialize` → `notifications/initialized` → `tools/call dry_run` session returns
  `structuredContent` with the evidence report (24 cases, `all_agree: true`) — a real
  request/response round-trip, not just `tools/list`.

## What still genuinely requires a human / external party

Residuals of §4–§6 specifically. The residuals that apply to the delivery as a whole — a
hosted public endpoint, and OpenZeppelin technical-reviewer sign-off — are recorded once, in
`docs/TESTNET-EVIDENCE.md`, rather than restated per milestone.

- (A polished narrated **demo video** is a human artifact, though the Playwright harness
  above already records `.webm` runs of the real flows.)
