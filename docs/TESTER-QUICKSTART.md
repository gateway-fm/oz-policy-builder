# Tester quickstart

Run the whole flow yourself on Stellar testnet: a smart account with your passkey, a payment,
Claude turning it into a one-call grant, the grant installed, used once, refused the second time,
and revoked. Everything runs on your own machine; there is no hosted service to sign up for, and
nothing costs real money. What each step means is in the [user guide](USER-GUIDE.md).

Allow for the one-time setup: the first builds take several minutes. The flow itself took about
twenty minutes in the [recorded run](TESTNET-EVIDENCE-TRANCHE-2.md#25-wallet-run-by-a-person-with-claudes-proposal-11-november-2026).

## Prerequisites

- **Rust** through `rustup`. The checkout pins Rust 1.91.1 and the `wasm32v1-none` target in
  `rust-toolchain.toml`; `rustup show` in the checkout reports whether they are installed.
- **`stellar` CLI 27.0.0** on `PATH`; `generate_code` builds with it
  ([pinned revision](TRANCHE-1-VERIFICATION.md#1-run-the-release-gate)).
- **Node 22.12 or later**, **pnpm**, and **Chrome** (passkey creation needs `localhost`).
- **Claude Code**.

## One-time setup

```bash
git clone https://github.com/gateway-fm/oz-policy-builder.git
cd oz-policy-builder
cargo build --locked -p ozpb-cli                                  # target/debug/ozpb
cargo build --locked --manifest-path execution-runtime/Cargo.toml # the native worker
npm --prefix wallet ci --ignore-scripts --no-audit --no-fund
```

The native worker lands in `execution-runtime/target/debug/ozpb-execution-runtime` unless you set
`CARGO_TARGET_DIR`.

**The wallet.** Apply the integration to a clean Pollywallet checkout at the pinned revision and
build it, exactly as in [Apply to the supported upstream revision](POLLYWALLET-INTEGRATION.md#apply-to-the-supported-upstream-revision).

**The backend configuration.** Create a directory with mode `0700` for session state, then an
`operator.json` with absolute paths that are not symlinks
([fields](POLLYWALLET-INTEGRATION.md#start-the-local-backend)):

```json
{
  "executable": "/absolute/path/oz-policy-builder/target/debug/ozpb",
  "workRoot": "/absolute/path/wallet-state",
  "rpcUrl": "https://rpc.testnet.stellar.gateway.fm",
  "registrySnapshotPath": "/absolute/path/oz-policy-builder/docs/examples/registry.signed.json",
  "registryRootsPath": "/absolute/path/oz-policy-builder/docs/examples/registry-roots.json",
  "registryMinimumVersion": 6,
  "nativeExecutable": "/absolute/path/oz-policy-builder/execution-runtime/target/debug/ozpb-execution-runtime",
  "liveHelper": "<contract ID>"
}
```

- `liveHelper` is the contract ID under
  [Current helper deployment](ATOMIC-LIVE-HELPER.md#current-helper-deployment-account-073). The
  backend checks its code before every use.
- The RPC must answer in about a second a request: the wallet's reads have to finish within 12
  ledgers, and a slow endpoint is refused as `rpc_too_slow`.
- The registry files are the committed development pair: testnet only, and signed with a key
  anyone can use. That is fine for testing and wrong for anything else.

## The flow

**1. Start the wallet.** In the toolkit checkout:

```bash
node wallet/server/main.mjs --config /absolute/path/operator.json
```

It prints a one-time session URL on `http://localhost:3000`. In the Pollywallet checkout run
`pnpm dev`, then open that URL in Chrome. Keep the URL private and the page open until you finish.

**2. Make a payment.** Create a passkey and approve the account's deployment, then prepare the
sample transfer (0.1 testnet XLM) and approve it with the passkey. Note the confirmed transaction
hash the page shows.

**3. Connect Claude.** Select **Connect Claude** and note the one-time code (valid five minutes;
the connection lasts thirty).

**4. Ask Claude.** In a second terminal, in the toolkit checkout:

```bash
MCP_TIMEOUT=900000 claude --plugin-dir .
```

The first start builds the server; wait until `/mcp` lists `ozpb` as connected. Run
`/oz-policy-builder:policy-builder` and ask, for example: *"Connect my wallet with code `<code>`.
Then make a grant that lets the wallet's automation key repeat transaction `<hash>` once, within
the next two hours."* Answer its questions, check the restated decisions, read the **Confirm before
deploy** card, reply `confirm`, and approve the `send_wallet_proposal` call when Claude Code asks.

**5. Review and install.** In the wallet: **Review proposal from Claude**, confirm the policy's
deployment, refresh the authority review, `Run local execution checks`, then the live check with the
passkey. When the page offers installation (it waits for the live check's signatures to expire),
**Prepare installation** and approve with the passkey.

**6. Monitor, use, revoke.** `Check installed grant now` should report `unchanged`.
`Pay with the automation key` makes the payment with no passkey; `Try the same payment again` must
be refused by the call cap, code 7. Finish with `Prepare revocation` and the passkey, then
**Disconnect Claude**.

Agent only, without the wallet: [MCP walkthrough §1](MCP-WALKTHROUGH.md#1-use-the-server-and-skill-with-claude-code).

## What to report

Open an issue on the repository with:

- the commit you ran (`git rev-parse HEAD`) and your OS;
- the step, what you expected and what happened;
- the error code (`E_…`) or the wallet's refusal reason
  ([table](POLLYWALLET-INTEGRATION.md#when-the-wallet-refuses)), and any testnet transaction hashes;
- anything the card, a question or a refusal said that you could not act on — that is a finding too.

Issues are public: never paste the session URL, a pairing code, a secret key (`S…`), a signed
envelope or signed authorization entries, and review logs before you paste them. A security
problem goes through the private channel in [SECURITY.md](../SECURITY.md) instead.
