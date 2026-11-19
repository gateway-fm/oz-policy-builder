# Test fixture — not the mainnet registry

`registry.signed.json` is the committed mainnet draft (`registry/mainnet/v0001.draft.json`) with its
pending review reference replaced by a test-fixture marker, signed by two throwaway custodian keys
(`fixture-a`, `fixture-b`) that were deleted after signing. `registry-roots.json` pins those two
throwaway keys and the checkpoint `ozpb registry verify` printed for the snapshot.

It exists only so the wallet's tests can start a mainnet-configured session on a version-1 registry.
Nothing here is signed by a real custodian, and no deployment should pin these roots. The real
mainnet registry is produced by the key ceremony in [Registry governance](../../../../docs/REGISTRY-GOVERNANCE.md).
