# Testnet & runtime evidence — Tranche 1

> **Scope: Tranche 1.** This file records the evidence for the first milestone only: the
> recorder against live RPC (§1), the generated policy deployed on testnet (§2), and the MCP
> server exercised over both transports (§3). Evidence for a later milestone, where there is
> any, is kept in a file of its own; nothing below depends on those files.
>
> Section numbers run continuously across the set, which is why this file ends at §3. New
> evidence belongs in the file for the milestone that contracts it, not appended here.

Verifiable evidence gathered by running the toolkit against **live Stellar testnet**
(Protocol 27) and exercising the MCP server over both transports. Reproducible with the
commands noted; testnet identities are throwaway (Friendbot-funded, no real value) and are
kept out of the repo.

## 1. Recorder validated against live Gateway public RPC

A real native-SAC `transfer` was submitted on testnet and then recorded by `ozpb record`
via **Gateway's public testnet RPC** (`rpc.testnet.stellar.gateway.fm`, the endpoint named
in the proposal).

- Transaction: `0eb48bcb9e7c76cdb45ec3e280b504a1beaa659138797e4a8fc897e9d80438c9`
  ([stellar.expert](https://stellar.expert/explorer/testnet/tx/0eb48bcb9e7c76cdb45ec3e280b504a1beaa659138797e4a8fc897e9d80438c9))
- The recorder decoded, from real Protocol-27 XDR: the network id (testnet), the
  `transfer(from, to, i128)` authorization call, the credential kind, and the SEP-41
  transfer token movement — matching the on-chain event exactly.

This upgrades the recorder from fixture-tested to **live-protocol-tested**, and confirms
Gateway's RPC serves the reads the toolkit depends on (`getTransaction`, `getNetwork`,
`getLatestLedger`).

> **This claim went stale the next day and was wrong for three weeks.** The commit after it
> (`68bd40a`, 2026-07-22) added a `getLedgerEntries` call to observe target executables, and
> decoded its `xdr` field as a whole `LedgerEntry` when the RPC returns `LedgerEntryData`.
> Every offline test passed — the mocks encoded the same wrong assumption — while `ozpb record`
> failed against every real endpoint. Found on 2026-08-12 by attempting this demo again, fixed,
> and anchored: `crates/source-rpc/tests/captured-testnet/` holds verbatim responses for all
> four RPC methods, replayed through the real entry points in `rpc_conformance.rs`.
>
> Two process lessons, both now acted on. A hand-written mock validates parsing but not the
> assumption underneath it, so anything shaped by an external system needs at least one
> captured real response. And a transaction hash cannot be replayed later — RPC retention drops
> it — so the live path must be re-exercised on a schedule, not evidenced once.

```
ozpb record --tx-hash <hash> \
  --rpc-url https://rpc.testnet.stellar.gateway.fm \
  --network "Test SDF Network ; September 2015"
```

## 2. Generated policy deployed on testnet

The generated W2 subscription policy (compiled to wasm via `stellar contract build`) was
**deployed as a real contract instance** on testnet:

- Policy contract: `CCFRJAPI5DUYR2FPOH5NCZGU3QYH3QFZMB7FMR67EJEJ32LA4YTD4G6L`
  ([lab](https://lab.stellar.org/r/testnet/contract/CCFRJAPI5DUYR2FPOH5NCZGU3QYH3QFZMB7FMR67EJEJ32LA4YTD4G6L))
- Deploy tx: `5487a04c6a8e6f455d72cd9919a7ad2004dfa3f49df0a5daebcdc7bc2d285b71`

This upgrades the generated artifact from "compiles to wasm" to "deployable on-chain
contract."

## 3. MCP server exercised end-to-end (both transports)

Exercised through `import_recording`, a tool this milestone contracts, so the round-trip
reproduces in a tree containing only what this milestone delivers. Re-run 2026-08-14 against
`target/debug/ozpb-mcp-server` built from this tree, with the committed fixture
`docs/examples/import-bundle.json` as the tool's arguments.

- **stdio, full `tools/call`:** an `initialize` → `notifications/initialized` →
  `tools/call import_recording` session. `initialize` returns protocol version `2025-06-18`,
  `capabilities.tools`, and the server info (`rmcp` 2.2.0) with the server's instructions
  string. The `tools/call` returns `structuredContent` carrying the decoded
  `RecordingBundle`: one authorization — authorizer address, an `address` credential with its
  `nonce` and `signature_expiration_ledger`, and the authorization `fingerprint` — the
  `transfer(from, to, i128)` call with its three arguments, one `transfer` token movement,
  `canonicalization_version: 2`, `schema: recording/v1`, `execution: executed_success`,
  `trust: self_supplied`, and a `recording_hash`. A real request/response round-trip, not
  just `tools/list`; the process exits 0.
- **streamable HTTP:** `ozpb-mcp-server --http 127.0.0.1:<port>` serves the identical
  handler at `/v1/mcp`; a curl `initialize` returns `200` with `content-type:
  text/event-stream`, an `mcp-session-id` header, and the SSE-framed server info identical to
  the stdio handshake's. The same request without a bearer token is refused with `401`. What
  this evidences is that the two transports answer the same handshake with the same server —
  a loopback run, on this machine. Serving the toolkit as a hosted endpoint is a later
  milestone's subject and nothing here speaks to it.

The two hashes this run produced — the `recording_hash` and the authorization `fingerprint` —
are deliberately not quoted. Re-running the command reproduces them, but no committed artifact
carries either value, and a hash quoted in prose that nothing in the tree produces is the
precise failure `scripts/check-quoted-hashes.py` exists to catch.

## What still genuinely requires a human / external party

Residuals of §1–§3, and the two that apply to the delivery as a whole and are therefore
recorded once here rather than restated per milestone. A residual belonging to a later
milestone's evidence is recorded with that evidence.

- **A hosted public endpoint** — contracted in a later milestone, and named here only to mark
  the boundary of §3: what is evidenced above is a server answering on loopback, not a
  deployed service. It is not an outstanding item of this milestone.
- **OpenZeppelin technical-reviewer sign-off** — an external human review.
