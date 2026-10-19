# Browser harness: headless passkeys (Tranche 2)

A passkey wallet's UI is driven headless, with no display and no authenticator hardware. Chrome's
DevTools Protocol provides a virtual CTAP2 authenticator, created in `authenticator.mjs`. It
approves every request as if a verified user had touched it. A CI job, or a job recording a demo,
would use the same technique.

```
cd testnet-harness/browser
npm ci
npm test                                     # offline: the assertion verifier, passkey.mjs's DEBUG guard
OZPB_BROWSER_CHANNEL=chrome node webauthn.mjs
```

`OZPB_BROWSER_CHANNEL=chrome` uses an installed Google Chrome. Without it, run
`npx playwright install chromium` once to get Playwright's own build. Output goes to `out/`,
which is gitignored. To open the page by hand, run `node server.mjs`. It serves on
`OZPB_PASSKEY_PORT`, default 5177. `webauthn.mjs` itself takes any free port.

## `webauthn.mjs`: create, sign, verify

`server.mjs` serves `app.html` on `127.0.0.1`. The page asks the authenticator for a secp256r1
(ES256, COSE alg −7) passkey and signs a 32-byte challenge that the script chose. The script then
checks the result outside the browser, with node's crypto (`assertion.mjs`). All of these must
hold:

- the signature verifies over `authenticatorData ‖ sha256(clientDataJSON)` under the public key
  returned at creation;
- `clientDataJSON` is a `webauthn.get` over exactly that challenge, from exactly that origin;
- `authenticatorData` is for `localhost` and reports the user present and verified;
- the authenticator holds exactly one resident credential, and it is the one that signed:
  - the same credential id;
  - a private key whose public half is the key returned at creation;
  - the sign counter the assertion reports.

The script exits 0 only if all of them hold. It does not verify the registration's
attestation, nor `tokenBinding` or `crossOrigin`.

**What this does not show.** The challenge here is random: nothing binds it to a transaction,
and no contract verifies the signature. The on-chain version is `passkey.mjs`, below.

## `passkey.mjs`: the testnet harness's passkey owner

`../run.sh` with `OZPB_HARNESS_OWNER=passkey` uses the same page (`app.html`), virtual
authenticator (`authenticator.mjs`) and assertion check (`assertion.mjs`) for a smart account's
owner. It is not run by hand. `../scripts/setup.mjs` calls `createPasskey()`,
and every later owner signature goes through `signChallenge()`:

- The challenge is the account's 32-byte `auth_digest` for one authorization entry.
- The assertion is checked with `assertion.mjs` before it is used.
- `../scripts/owner.mjs` converts the DER signature to the low-s r ‖ s the verifier contract
  takes.
- The OpenZeppelin WebAuthn verifier then checks it on chain.

The harness runs as separate scripts, and a virtual authenticator dies with its browser. So the
credential, private key included, is exported through the DevTools Protocol after creation and
imported into a fresh virtual authenticator for each signature. It is kept with the run's other
throwaway secrets, never printed, never in `out/` or the run directory. That is the one way this
differs from a device, whose key never leaves it: here the authenticator signs with a key the
harness holds. Playwright's `pw:protocol` and `pw:channel` debug logs would print that key, so
`passkey.mjs` refuses to run when `DEBUG` could enable them.

## `recon.mjs` and `drive-pollywallet.mjs`: a real passkey wallet

[pollywallet](https://github.com/kalepail/pollywallet) is a passkey smart-wallet demo on Stellar
testnet. Both scripts take a URL as their argument, or from `POLLYWALLET_URL`. The default is a
local `pnpm dev` on `:3000`. pollywallet's own README notes two things:

- A local server needs an OpenZeppelin Channels API key for its deploy, fund and transfer flows.
- A live demo runs at `https://pollywallet.sdf-ecosystem.workers.dev`.

```
OZPB_BROWSER_CHANNEL=chrome node recon.mjs <url>             # read-only: title, controls, out/recon.png
OZPB_BROWSER_CHANNEL=chrome node drive-pollywallet.mjs <url>
```

- **`recon.mjs`** touches nothing. Run it first: a deployed demo can change without notice, and
  recon shows whether the control the driver clicks is still there.
- **`drive-pollywallet.mjs`** clicks pollywallet's own "Create Smart Wallet" button with the
  virtual authenticator attached.
  - pollywallet's code makes the WebAuthn call, so a resident credential appearing on the
    authenticator shows that its real passkey registration ran under automation. Exit status 0
    means exactly that.
  - Whether a wallet then exists is up to pollywallet's backend. The script reports it
    separately, counting only a contract address that was not on the page before the click.
  - Each run that gets that far deploys a testnet contract through that server's relayer. The
    contract's only signer is a passkey that is gone when the browser closes. Run it by hand;
    never loop it, and never put it in CI against someone else's deployment.

**What a run showed** on 2026-10-15, against the live demo with headless Chrome 155 (the script
was run twice; the second run used the version committed here):

- Each run registered one resident credential.
- Each run ended on "Wallet created!" with a new contract address.
- Testnet reports each contract as an OpenZeppelin-shaped smart account (`__check_auth`,
  `add_context_rule`, `execute`). Its rule 0 has a single `External` signer: a verifier
  contract, plus 97 bytes of key data that begin with an uncompressed P-256 point.
- [`media/pollywallet-wallet-created.png`](media/pollywallet-wallet-created.png) is the
  screenshot from the second run.

**What it does not show.**

- Nothing here installed a policy into a pollywallet account, and the toolkit could not do so
  yet. The account's code hash is not the account wasm pinned in
  `ozpb_domain::pinned_upstream`, so the signed registry would refuse to recognize it
  (`E_INCOMPATIBLE_ACCOUNT`). Its contract metadata shows a different soroban-sdk and stellar-cli
  from our pinned inputs, and so does its verifier's.
- What the testnet harness does instead: with `OZPB_HARNESS_OWNER=passkey` it creates an account
  of the same shape, a single passkey `External` signer on rule 0 with the same key-data layout,
  on the pinned account and the pinned OpenZeppelin WebAuthn verifier. It then installs a
  generated policy into it, with the passkey signing (`../README.md`). pollywallet's own UI cannot
  create that account: it deploys its own wasm through its own relayer.
