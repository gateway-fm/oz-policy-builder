# Publishing a generated policy

A generated policy is installed by its Wasm, and the network names that Wasm by its SHA-256, the
contract code hash. Anyone can read the hash of an installed policy; nothing on chain says what
source it was built from. `ozpb publish-artifact` lays out what a reviewer needs to answer that,
keyed by the hash: the generated crate exactly as `generate` emitted it, the PolicySpec, the
BuildManifest and the Wasm. `ozpb verify-published` checks such a directory and reproduces it
through the same `verify` that `ozpb verify` runs ([architecture §6.3](architecture.md#63-reproducibility-and-artifact-provenance)).

Both commands work on local directories. Where the result is hosted — a release asset, a
repository, a static site — is the publisher's choice; the toolkit uploads nothing.

## What a published build holds

```text
<out>/<wasm sha256>/<build manifest hash>/
    SHA256SUMS            every other file with its SHA-256, in path order (`sha256sum` format)
    policy-spec.json      the PolicySpec the policy was generated from
    build-manifest.json   the BuildManifest generate emitted
    policy.wasm           the Wasm whose SHA-256 names the outer directory
    source/               every file generate emitted: Cargo.toml, Cargo.lock,
                          rust-toolchain.toml, rustfmt.toml, src/lib.rs, src/contract.rs
```

The outer directory is the on-chain code hash. The inner one is the BuildManifest hash `generate`
prints (`ozpb:v2:build-manifest`, [canonical hashing](CANONICAL-HASHING.md)), because one Wasm
has many builds: only the normalized codegen input decides its bytes, so equal grants for other
accounts, or the same grant re-synthesized under a newer registry snapshot, share one Wasm with
different specs and manifests ([architecture §4.4](architecture.md#44-code-generation-cratescodegen)).
Each build sits beside the others under the same code hash.

The spec and manifest are written in the toolkit's own form (two-space JSON and a final newline),
so a reformatted copy of the same content publishes the same bytes. `SHA256SUMS` carries plain
SHA-256 over each file's bytes, like `lockfile_hash` and `wasm_hash`
([hashes that are not domain-separated](CANONICAL-HASHING.md#hashes-that-are-deliberately-not-domain-separated)),
so `sha256sum -c SHA256SUMS` (`shasum -a 256 -c` on macOS), run inside the build directory, checks
a copy without this toolkit. It is unsigned: it catches a damaged or incomplete copy, not an
edited one, since whoever edits a file can rewrite it.

**The spec is published.** It names the smart account, its code hash, the network, the registry
snapshot root and the hashes of the recordings the grant was synthesized from. The Wasm already
carries the target, the signers and the permitted calls; publishing the spec also links that
account to this policy. Publish only if that is acceptable.

## Publishing yours

After `ozpb generate --out ./generated` (the [developer guide](DEVELOPERS.md#cli)), give
`publish-artifact` the same files `verify` takes:

```bash
ozpb publish-artifact --spec spec.json --generated-dir ./generated \
  --wasm ./generated/generated_sub_transfer_r0.wasm \
  --manifest ./generated/build-manifest.json --out ./published
```

It prints the Wasm hash, the manifest hash, the directory it wrote and whether that build was
already there. It writes the build into a staging directory and renames it into place, so a
build is there whole or not at all. Publishing the same build again changes nothing. It refuses,
writing nothing:

| Code | When |
| --- | --- |
| `E_PUBLISH_WASM_MISMATCH` | The Wasm's SHA-256 is not the manifest's `wasm_hash`. |
| `E_PUBLISH_MANIFEST_MISMATCH` | The manifest does not describe the files: another spec (`spec_hash`), an edited, added or removed crate file (`source_hash`), another or no `Cargo.lock` (`lockfile_hash`), binary build output in the generated directory, or a manifest not written the way the toolkit writes it, which `verify` could never reproduce. |
| `E_PUBLISH_PATH` | A crate file name that is not a plain relative path; `<out>/<wasm hash>` is a symlink; or an existing destination is, or holds, a symlink or a special file. |
| `E_PUBLISH_CONFLICT` | `<out>/<wasm hash>/<manifest hash>/` already holds other content. It is left as it is. |
| `E_RESOURCE_LIMIT` | An existing destination is over the reader's ceilings below. |
| `E_SPEC_INVALID` | The spec does not parse or validate. |

A hand-edited crate is a custom artifact with no BuildManifest of its own
([architecture §4.4](architecture.md#44-code-generation-cratescodegen)), so it is refused rather
than published under the generated one's.

## Checking an installed policy against its source

Fetch the installed Wasm and hash it; the result names the directory to look for:

```bash
stellar contract fetch --id <policy C-address> --network testnet -o installed.wasm
shasum -a 256 installed.wasm      # <wasm sha256>
ozpb verify-published ./published/<wasm sha256>/<build manifest hash>
```

`verify-published` takes the two hashes from the last two names of the path it is given, never
from where that path resolves, and refuses it if either directory is a symlink. It reads the build
as untrusted content: it refuses a symlink or special file inside it, a name that is not UTF-8,
and more than 64 entries or 16 MiB. It is not defended against someone writing to the directory
while it reads; check a copy nobody else is writing to. It then checks, in order, that
`policy.wasm` hashes to the outer directory's name, that `SHA256SUMS` lists exactly the other
files with their hashes, that the files are what `publish-artifact` writes from them — which holds
the manifest to the spec, the crate, the lockfile and the Wasm — and that the inner directory is
named for that manifest. The lockfile check is the one `verify` does not make. Only then does it
regenerate and rebuild from the published spec, with the rule index the manifest names, and
compare the source, the Wasm and the manifest, exactly as `ozpb verify` does. It prints the two
hashes and the `verify` report.

| Exit | Meaning |
| --- | --- |
| 0 | `verify.matches` is `true`: reproduced, and the offline behavioural check passed. |
| 3 | `verify` ran and `verify.matches` is `false`: a dimension did not reproduce, or the offline behavioural check failed. The report says which. |
| 1 | Refused before the rebuild (an `E_PUBLISH_*`, `E_SPEC_INVALID` or `E_RESOURCE_LIMIT` code leads the error), or the build itself failed. |
| 2 | The command line was not understood. |

`ozpb verify` exits 0 whether or not its report matches; `verify-published` is meant to be
scripted against, so a mismatch is a non-zero exit.

What a reproduction establishes, and what it does not:

- **A match says this source, built with the pinned toolchain, gives exactly this Wasm and every
  reproducible manifest field.** When the manifest came from another toolkit build, the report
  says the producer record differs: that record (toolkit commit, template pack, build image)
  describes the build that made the claim and is reported, never compared
  ([G9](MAINNET-GATES.md#g9-artifact-chain-and-buildmanifest)).
- **Reproduce with the release that generated it.** The manifest's `producer.toolkit_source`
  names that toolkit's commit. Another release reproduces only if its templates and pins are
  unchanged, and the build needs the `stellar-cli` version the manifest records, since its
  version is compiled into the Wasm.
- **Comparable hosts only.** Nothing pins the operating system or a container by default, so a
  byte-identical Wasm is guaranteed only on a sufficiently similar host
  ([ecosystem conformance §2](ECOSYSTEM-CONFORMANCE.md#2-artifact-identity-and-its-verification-ℹ️-verification-seps-are-draft)).
- **Not the registry root, the installation or live state.** Like `verify`, it records the
  registry root the spec names without checking it, and it says nothing about which account
  installed the policy or what that account's rules allow. Those are the live checks'
  ([user guide](USER-GUIDE.md)).

## Not a SEP-58 source archive

SEP-58 (Draft) keys rebuild verification to `source_sha256`, the SHA-256 of a source archive. A
published build is a directory of files with a `SHA256SUMS` index, not that archive, so it gives
no `source_sha256` and no such field is recorded anywhere
([ecosystem conformance §2](ECOSYSTEM-CONFORMANCE.md#2-artifact-identity-and-its-verification-ℹ️-verification-seps-are-draft)).
Explorers' verification badges do not read it.

## The project's own reviewed artifacts

The natural place for this project's reviewed generated policies is beside its release
binaries, as assets of the GitHub Release that `release-binaries.yml` builds and attests. That
workflow does not produce them today: building a policy needs `stellar-cli` on each runner, and a
Wasm built on three platforms is one Wasm only if the builds agree, which would have to be
checked before anything is attached. Until it does, no reviewed artifact is published by this
project; [`contracts/golden-transfer-policy/`](../contracts/golden-transfer-policy) is the
generated source the tests hold to the emitter, not a published build.
