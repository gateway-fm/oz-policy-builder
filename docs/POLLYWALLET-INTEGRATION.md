# Pollywallet Policy Builder integration

The integration adds a Policy Builder route to a pinned Pollywallet checkout. Pollywallet
owns the passkey interaction; the local wallet backend owns its RPC connection, registry
roots, retained artifacts and disposable testnet fee payer. MCP output cannot select a
command, RPC endpoint, file path or signing identity.

Pollywallet is the wallet named in the public architecture. Its pinned upstream default
account differs from the account recognized by this toolkit. The integration therefore
creates or attaches a recognized account explicitly. It does not relabel an unknown account,
migrate an existing wallet, or broaden account/verifier recognition.

This integration supports recognized account creation, a fixed owner-authorized sample
transfer from that new account, confirmed-transaction recording, artifact generation and
reproduction, artifact deployment, live authority review and, when the operator configures
the [native worker](NATIVE-EXECUTION.md), local account-Wasm execution of the reviewed grant.
Policy installation, revocation and replacement remain disabled: the captured-target and
behavioral live-enforcement layers are not yet connected. The signing validators below are
tested foundations, not a completed installation or wallet acceptance claim.

## Apply to the supported upstream revision

Use a dedicated clean checkout of
[`kalepail/pollywallet`](https://github.com/kalepail/pollywallet/tree/853b102983699726f918b68d8e42edbba74e65b9):

```sh
git clone https://github.com/kalepail/pollywallet.git /absolute/path/pollywallet
git -C /absolute/path/pollywallet checkout --detach 853b102983699726f918b68d8e42edbba74e65b9
python3 scripts/apply-pollywallet.py --revision HEAD /absolute/path/pollywallet
```

Run the apply command from a committed toolkit checkout containing this integration. It reads
only that immutable Git tree, refuses a different or dirty upstream revision, refuses source
symlinks and unlisted patch paths, and retains license attribution. Untracked toolkit files
and working-copy edits do not become integration inputs.

Install the two existing lockfiles separately:

```sh
cd /absolute/path/pollywallet
pnpm install --frozen-lockfile --ignore-scripts
npm --prefix src/policy-builder ci --ignore-scripts --no-audit --no-fund
pnpm build
pnpm exec vitest run src/lib/__tests__/policy-builder-bridge.test.ts
```

The upstream wallet keeps SDK 16.2.0. The nested validator package pins SDK 17.2.1.
Only serialized XDR crosses that boundary. Do not deduplicate the Stellar SDK packages or
silently replace the upstream dependency lock. The browser uses the upstream `buffer`
polyfill, so URL-safe base64 is encoded explicitly rather than relying on Node-only encodings.
The package-scoped `#wallet-stellar-sdk` import and explicit Vite alias keep the development
optimizer from reusing the upstream SDK 16 bundle for SDK 17 validators.

The Vite development server binds to `127.0.0.1:3000`, with a same-origin proxy for
`/api/policy-builder` to the local backend on `127.0.0.1:4317`. Open the UI through
`http://localhost:3000`: Chrome requires the `localhost` domain for WebAuthn registration
and rejects the numeric IP as a relying-party domain.
Open the backend's session launch URL. Its bearer credential is read once from the fragment,
removed from browser history, and held only in memory. A page reload requires a fresh launch
URL; the credential is not stored in local storage or sent in a query string.

This route is a local operator workflow. Building it does not deploy a Cloudflare service,
call the upstream shared relayer, publish an image, or establish a hosted endpoint.
The overlay disables upstream AI and sandbox service bindings, container startup, remote
bindings and the development inspector. Those unrelated upstream cloud features are
unavailable in this dedicated checkout. In particular, ordinary `pnpm dev` must not require
Cloudflare credentials or launch the upstream compiler container.

## Start the local backend

Build the toolkit CLI and prepare a signed registry snapshot and its trusted roots as
described in the registry documentation. Use Node 22.12 or newer and install the wallet
lockfile with `npm --prefix wallet ci --ignore-scripts --no-audit --no-fund`.
Create an operator-owned directory with mode `0700` for retained session state, then write
an operator JSON file using absolute canonical paths:

```json
{
  "executable": "/absolute/path/oz-policy-builder/target/debug/ozpb",
  "workRoot": "/absolute/path/wallet-state",
  "rpcUrl": "https://soroban-testnet.stellar.org",
  "registrySnapshotPath": "/absolute/path/registry.signed.json",
  "registryRootsPath": "/absolute/path/registry-roots.json",
  "registryMinimumVersion": 1,
  "buildJobs": 2,
  "buildTimeoutSecs": 600
}
```

Set the minimum registry version to the operator's accepted rollback floor. Optional
`stellarBinary`, `cargoHome`, `rustupHome`, and `buildCacheDir` fields select existing local
toolchain paths; the cache directory also requires mode `0700`. Optional `nativeExecutable`
names the operator-built `ozpb-execution-runtime` binary; without it the account-Wasm check is
unavailable. The CLI and optional Stellar and native binaries must be executable regular files. Configuration, registry and executable paths cannot
be symlinks or writable by other users. Arbitrary environment overrides are refused, builds
run offline, and HTTP requests cannot select these settings.

From the toolkit checkout:

```sh
node wallet/server/main.mjs --config /absolute/path/operator.json
```

In the applied Pollywallet checkout, run `pnpm dev`, then open the one-time session URL
printed by the backend. The equivalent backend entrypoint in that checkout is
`node src/policy-builder/server/main.mjs --config /absolute/path/operator.json`.
Startup does not fund an account, execute the CLI or submit a transaction. The backend
listens only on `127.0.0.1:4317`; the approved browser origin is exactly
`http://localhost:3000`; the numeric-IP browser origin is refused.

Each backend launch creates a separate private session directory and an in-memory disposable
testnet fee payer. Retain the session journal: an intended transaction hash is recorded before
submission, and an uncertain result blocks subsequent writes in that session. Inspect that
hash before starting another attempt. The fee payer key is not saved, printed or returned
to the browser. Fresh account confirmation separately discloses a fixed one-testnet-XLM
sample balance (`sampleFundingStroops: "10000000"`) and at most three testnet XLM in fees
across its three transactions (`maxTotalFeeStroops: 30000000`).
On SIGINT or SIGTERM the listener stops accepting new requests; an already admitted request
can finish and write its receipt before shutdown. Keep the journal when interrupting a session.

## Review and consent

1. Create a passkey using Pollywallet's existing authenticator helper, then separately review
   and confirm recognized account deployment. Alternatively attach the public locator of an
   existing recognized account. Retain that locator to reconnect; it contains no private key.
2. For an account created in this session, prepare the fixed sample transfer, review its
   sender, recipient and fee, then separately approve it with the owner passkey. It transfers
   exactly 0.1 testnet XLM back to the local fee payer, which pays at most one testnet XLM in
   transaction fees. Recording remains a separate action after confirmation. An attached
   wallet must supply its own confirmed authorized transaction. Select the restricted
   delegate, grant name, expiry and call limit; the backend retains the resulting
   specification and generated artifact under opaque identifiers.
3. Inspect the immutable specification, generated files, Wasm hash, build manifest and
   verification limits. Deployment confirmation concerns that exact artifact and the testnet
   fee ceiling; it does not grant account authority.
4. Refresh the live authority and exact installation grant. The browser independently checks
   the recognized owner rule, full credential identifier, policy address and retained bindings.
   The selected owner rule comes from that evidence; rule zero is not assumed.
5. Optionally run the account-Wasm check described below. It signs nothing with the owner
   passkey and does not change the installation gate's other required layers.
6. Only when the required verification report is complete does the route enable owner signing.
   It checks the fresh unsigned envelope against the immutable display before asking Pollywallet
   for a passkey signature. It then independently checks the signed XDR, origin, challenge,
   user verification, full signer identity and exact owner rule before submission.

Account and policy deployment confirmations are distinct from owner authorization. A cancelled
or refused signing attempt consumes the prepared review. Sample preparation is available only
for the exact wallet created in this backend session and checks its retained full owner-zero
getter, including the fresh constructor's empty `policy_ids` and `signer_ids: [0]`.
A new preparation invalidates the old action; its 120-second token can expire sooner
under the ledger freshness checks. Cancellation before submission permits another preparation.
After any sample submission attempt, the client disables further attempts, including when a
response is lost. Backend enforcement, fresh code/owner/sequence checks and the journal still
apply before the fee payer signs or sends anything. The confirmed hash is offered for a
separate recording action.

Sample authorization preserves either direct `Address` or `AddressV2` credentials exactly.
For `AddressV2`, the SDK constructs the address-bound preimage described in Stellar's
[authorization migration guide](https://stellar.github.io/js-stellar-sdk/migration/protocol-27-soroban-auth/).
The browser and backend reject a changed credential discriminator and do not downgrade V2
to the legacy payload. Source-account credentials and delegation wrappers are unsupported
for this owner-passkey flow.

## Account-Wasm execution

With `nativeExecutable` configured, the route can create a local automation delegate. The
backend generates an Ed25519 key in process memory and returns only its public address and an
opaque capability ID; at most eight exist per backend, and they disappear when it stops. Use
that address as the grant's restricted delegate. The owner passkey never stands in for it, and
a grant naming any other delegate address cannot run this check.

`Run account-Wasm check` uses only state the backend retained for the reviewed deployment:

1. `ozpb prepare-dry-run` binds the exact artifact claims, binding set, signed registry, the
   next context rule ID from the reviewed authority evidence and a fresh run nonce. Its run
   hash, suite hash and per-case reference expectations become the independent expectations.
   Without a bounded next-ID enumeration in that evidence, the layer stays `unavailable`.
2. The operator RPC supplies one coherent protocol-29 ledger header, the archival TTL limits
   and the pinned account Wasm bytes, within twelve ledgers of each other.
3. The worker runs once with `--prepare`; the wallet checks that frame against step 1 and the
   offline signing domain, then runs the identical job interactively. Every repeated frame
   must equal the retained one. The wallet signs only the offline-domain `__check_auth`
   digests of IDs in the derived case, control and sequence inventory, each at most once,
   in the runner's exact request-ID and nonce order. The order of the IDs themselves is not
   enforced.
4. The final report is accepted only after the wallet recomputes agreement for every case
   from the CLI's expectations and the reported observations, checks all five cryptographic
   controls and the stateful call-cap sequence, and requires a zero worker exit that leaves no
   process in the worker's group; any refusal kills that group.

A passing result marks only the `account_wasm` layer. It is local execution in fresh synthetic
state: no target contract, captured network state or live enforcement runs, and it proves no
ownership of the real wallet. Every other outcome carries no evidence:

- `unsupported`: the grant is outside the worker's scope, for example a call cap above 512;
  nothing runs.
- `unavailable`: the next rule ID was not established, or CLI preparation or the operator
  RPC read did not complete; the worker does not run.
- `failed`: the preparation evidence, the worker or its report was refused.

A new review starts again without account-Wasm evidence. A hung worker is stopped by its
120-second deadline in each of its two runs; the backend serves no other request meanwhile.

`bash scripts/test-wallet-native-execution.sh` runs this sequence against the actual CLI and
worker with the runtime test's public delegate seed. Like the testnet harness, it needs
`OZPB_REGISTRY_SNAPSHOT_ROOT` set to the root of `docs/examples/registry.signed.json`;
`OZPB_ACCOUNT_WASM` may reuse a pinned account artifact.

## Report layers

The four report layers are `reference`, `account_wasm`, `captured_target` and
`live_enforcement`. The UI distinguishes the first three local checks from full acceptance.
Missing, unsupported, failed, duplicated or mismatched evidence keeps acceptance closed.
An installation preflight is not counted as behavioral live-enforcement evidence. Backend
capabilities keep installation signing and lifecycle actions unavailable until their required checks exist.

Authentication with a virtual authenticator is automation evidence. The signature result
explicitly reports `human_approval_attested: false`; it does not establish a human acceptance
decision. This local design also does not protect against an agent or process with arbitrary
control of the operator's OS account or browser profile.

## Verification

The [20 October 2026 sample run](evidence/pollywallet-sample-2026-10-20.json) created and
funded a pinned testnet account, approved the fixed 0.1 XLM transfer using `AddressV2`,
confirmed it at ledger 5294119, and recorded the transaction through the CLI. It used the
actual browser integration with a virtual authenticator. This is sample-flow evidence;
the run did not install a generated grant or complete four-layer/lifecycle acceptance.

Toolkit tests exercise session authentication, one-shot state, transport limits, exact XDR
and signature checks, and the client controller's refusal paths. The apply-script tests cover
immutable inputs, dirty/different upstream checkouts, symlinks, missing lock metadata, and
binary/rename patches that omit ordinary text headers.

The upstream bridge test uses the actual Pollywallet SDK 16 passkey helper and nested SDK 17
validator with a generated test key. It checks the full credential, a nonzero installation
owner rule, and the exact fixed sample-transfer envelope with owner rule zero, using both
legacy and V2 credentials. It marks the
result as automated authentication.

With the applied checkout's development server running, the browser regression uses the
existing Playwright lockfile and a temporary virtual authenticator:

```sh
npm --prefix testnet-harness/browser ci --ignore-scripts --no-audit --no-fund
OZPB_BROWSER_CHANNEL=chrome node scripts/test-pollywallet-browser.mjs /absolute/path/pollywallet
```

Run this from the toolkit checkout. It calls the actual upstream registration and signing
helpers at the supported `localhost` origin, independently verifies installation and
sample-transfer signatures, and submits no transaction. It removes its temporary browser
module afterward. Omit
`OZPB_BROWSER_CHANNEL` to use the installed Playwright Chromium instead of local Chrome.

At the pinned upstream revision, `pnpm exec tsc --noEmit` already reports five errors in
`src/hooks/useWallet.ts` and `src/lib/tx-analyzer.ts`. The unchanged upstream checkout produces
the same diagnostics. Generate the route tree with `pnpm build` before comparing type checks;
this integration does not edit the generated route tree or suppress those upstream errors.
