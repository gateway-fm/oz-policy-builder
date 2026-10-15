# Browser harness: headless passkeys (Tranche 2)

A passkey wallet's UI is driven headless, with no display and no authenticator hardware. Chrome's
DevTools Protocol provides a virtual CTAP2 authenticator, created in `authenticator.mjs`. It
approves every request as if a verified user had touched it. A CI job, or a job recording a demo,
would use the same technique.

```
cd testnet-harness/browser
npm ci
npm test                                     # offline: the assertion verifier
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

**What this does not show.** The challenge is the size and role of a smart account's
`auth_digest`, but nothing binds it to a transaction, and no contract verifies the signature.
A contract would also need it as 64-byte r‖s rather than the DER that WebAuthn returns, and
nothing here converts it. An
on-chain passkey signer would be an `External` signer behind a WebAuthn verifier contract, and
this tree refuses `External` signers in a PolicySpec. The on-chain install and enforcement in
`../README.md` use a `Delegated` ed25519 signer.
