# Mainnet capability registry

The published log for mainnet, in the layout `ozpb registry verify --replay` and
`ozpb registry monitor` read: `roots.json`, the pinned root policy, and one `vNNNN.signed.json`
per version. The procedure that produces and checks it is
[Registry governance](../../docs/REGISTRY-GOVERNANCE.md).

**Nothing here is signed, and nothing here is trusted yet.**

- `v0001.draft.json` is the **draft, unsigned** genesis. It is derived from the development
  registry's version 6 (`crates/registry/tests/mainnet_draft.rs` checks that it still is) and
  holds only reviewed code that is byte-identical on every network: OpenZeppelin's multisig smart
  account built at v0.7.3 with its bounded scan protocol and method inventory, the ed25519 and
  WebAuthn (passkey) verifiers, the spending-limit policy, and the `policy-templates/scope@1`
  template pack. It keeps the revocation of the v0.7.2 account (GHSA-jpg9-m7w4-c7wc) and carries
  no target-adapter binding: the development registry's Soroswap binding is a testnet-only
  assertion about the testnet router's code. The review references are carried over from the
  development registry except the template pack's, which is pending text beginning
  `PENDING, replace before signing:` — no review of the template pack is referenced yet. The
  custodians replace it with the completed security review's reference, and confirm every other
  reference, before anyone signs.
- The validity interval — `valid_from_unix` 2027-01-01T00:00:00Z, `expires_at_unix`
  2027-07-01T00:00:00Z — is a **placeholder**. How long the custodians vouch for version 1 is
  their decision at signing; they set both values in the draft before anyone signs, since the
  interval is part of the root. No one commits to keeping this registry valid beyond the interval
  they sign.
- `roots.json` holds **no keys**: the root policy is set at the key ceremony. Until then it is a
  placeholder that every command refuses (`E_REGISTRY_ROOT_POLICY`), so nothing can be verified
  under it by accident. Its threshold of 2 is the proposed minimum, not a decision.

At the ceremony the custodians generate their keys and the coordinator writes their public keys
into `roots.json`; they set the interval in the draft, sign it, and the coordinator combines the
signatures into `v0001.signed.json` here, replays the log, and publishes the head with the
release ([Making and signing a version](../../docs/REGISTRY-GOVERNANCE.md#making-and-signing-a-version)).
The draft is then superseded by the signed version and removed. The development root is refused
for mainnet by every consumer, so this log is the only way the toolkit trusts anything there.
