# Versioning

Releases are numbered `MAJOR.MINOR.PATCH` ([Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)),
tagged `v` plus the version that `Cargo.toml` states for the workspace. The number describes the
interfaces below and nothing else: what a breaking change to them is, what a release may change
without one, and which releases are supported. The release that delivers the third milestone is
**1.0.0**, the first release this policy covers; 0.x releases and their release candidates made
no compatibility promise.

## What is versioned

**The MCP wire contract.** The tool names the server lists, each tool's request and response
JSON Schema, and the `E_*` error codes. The schemas are generated with `schemars` from the
structs in `crates/api-types`, the same ones the server parses and returns
([architecture §4.11](architecture.md#411-engineering-architecture--workspace-boundaries-and-idioms)),
and the codes come from the one `error_codes!` table in `crates/api-types/src/lib.rs`. Each
release attaches `ozpb-wire-contract-<tag>.json`: the `tools/list` answer of that release's built
server, every tool with its input and output schema, and the code list. Comparing two releases'
files shows what changed. The streamable HTTP transport is served at `/v1/mcp`.

**The CLI and operator configuration.** `ozpb` commands, flags and their environment-variable
fallbacks, the JSON a command prints on standard output (the same `api-types` structures), and
the exit statuses a command documents, such as `ozpb registry monitor`'s
([registry governance](REGISTRY-GOVERNANCE.md#monitoring)). A command that documents only zero
and non-zero promises only that distinction. For the server: the `OZPB_*` variables
([developer guide](DEVELOPERS.md#build-configuration-operator-side)), `--http`, and the files the
self-hosted deployment mounts ([self-hosting](SELF-HOSTING.md#configure-the-operator-boundary)).

**Persisted and exchanged formats.** Each carries its version where it has one:

| Format | Version | Defined in |
| --- | --- | --- |
| PolicySpec | `schema: "policy-spec/v1"`; hashed under `ozpb:v1:policy-spec` | `crates/policy-spec/src/lib.rs` (`SPEC_SCHEMA`) |
| RecordingBundle | `schema: "recording/v2"`; hashed under `ozpb:v1:recording` | `crates/recorder-core/src/lib.rs` (`RECORDING_SCHEMA`) |
| BuildManifest | `schema: "build-manifest/v2"`; hashed under `ozpb:v2:build-manifest` | `crates/build-runner/src/lib.rs` (`BUILD_MANIFEST_SCHEMA`) |
| PolicyBindingSet | `schema: "policy-binding-set/v1"`; hashed under `ozpb:v1:policy-binding-set` | `crates/api-types/src/policy_operations.rs` |
| Registry snapshot | `schema: "registry/v1"`; hashed under `ozpb:v1:registry-snapshot` (its `version` and `log_index` number the content, not the format) | `crates/registry/src/lib.rs` (`REGISTRY_SCHEMA`) |
| Registry governance files | `registry-change/v1`, `registry-signature/v1`, `registry-monitor/v1` | `crates/registry/src/governance.rs` |
| Registry roots file and checkpoint | no version field: `{threshold, keys[, checkpoint]}` and `{version, log_index, root, revocations}`, both closed objects | `crates/toolkit/src/lib.rs` (`registry_trust_from_roots_json`), `crates/registry/src/lib.rs` (`RegistryCheckpoint`) |
| Grant proposal | `schema: "ozpb-grant-proposal/v1"` | `wallet/shared/proposal.mjs` |
| Reference suite cases | `ozpb-reference-suite-cases/v1` | `crates/harness/src/lib.rs` (`CASES_FORMAT`) |
| Build worker launcher frames | `build-worker-job/v1` in, `build-worker-result/v1` and `contained-build-result/v2` out ([launcher contract](ISOLATED-BUILDS.md#launcher-contract-for-another-provider)) | `crates/build-runner/src/worker.rs`, `deployment/worker-launcher.py` |
| Native worker frames | `schema: 1` in the job and result frames ([machine protocol](NATIVE-EXECUTION.md#machine-protocol)) | `execution-runtime/src/execution.rs`, `execution-runtime/src/captured.rs` |
| Release wire contract | `schema: "ozpb-wire-contract/v1"` | `scripts/release-artifacts.py` |

The hash domains are specified in [canonical hashing](CANONICAL-HASHING.md#domains).

**Generated artifacts.** The Wasm and BuildManifest a spec builds to. `verify` and the
recognition of an installed generated policy both rebuild it from its spec and compare the
result with the claim, every manifest field except `producer`. Anything that changes that
result for an existing spec changes whether installed policies are recognized: the generated
source, the generated crate's lockfile, the pinned Soroban SDK and OpenZeppelin versions
([Soroban dependencies](SOROBAN-DEPENDENCIES.md)), the pinned Rust and Stellar CLI
(`ozpb_domain::pinned_upstream`), or the codegen version the artifact states in `ozpb_generator`
(`oz-policy-builder/codegen@1`). The workspace version is in none of these.

Not versioned: human-readable text (`message`, the strings in `details`, help output, logs), the
internal Rust API of the crates, the container images' contents beyond the configuration above,
and the content of a registry. A signed registry version that revokes a capability is the
[revocation procedure](REGISTRY-GOVERNANCE.md#revocation-and-emergency-removal) working, not a
change to the toolkit.

## Breaking and additive

**Breaking — a new major version:**

- removing or renaming a tool, command, flag, environment variable, field or `E_*` code, or
  changing what one means, its type, or a default in a way that grants more;
- a new required input field, or refusing an input an earlier release accepted;
- a new value in an output enumeration, except a new `E_*` code; a new field in an object the
  published schema closes (`additionalProperties: false`);
- a change to a documented exit status;
- a format change after which a document an earlier release wrote is refused, read differently,
  or hashes differently, including a new `schema` version or hash domain the earlier one does
  not read (as `recording/v2` and `build-manifest/v2` did);
- a change to a frame either worker protocol exchanges;
- any change to the generated artifact of an existing spec, as above.

**Additive — a minor version:** a new tool, command, flag or optional input field; a new output
field in an open object (clients ignore output fields they do not recognize); a new `E_*` code
(clients treat a code they do not recognize as a failure); accepting an input an earlier release
refused; a new optional format field, written only when the feature it serves is used, whose
absence leaves a document's meaning and canonical hash unchanged. A document that uses a new
field is not readable by an earlier release, so upgrade every component that exchanges it first.

**Patch:** fixes that change none of the above.

**Exceptions.** A fix for a security defect, or a change the Stellar network forces (a protocol
upgrade the pinned SDK cannot follow), may break a contract in a minor or patch release when
waiting for a major one would leave users exposed or unable to work. The release notes list it
under breaking changes and say what to do, as the v1.0.0 notes do for the
[account advisory](release-notes/v1.0.0.md#security).

## What 1.0 promises, and for how long

During the grant period, which ends when the Stellar Community Fund accepts the third milestone,
no 1.x release breaks the contracts above except under the exceptions; a breaking change waits
for 2.0.0. The latest release line is the supported one, as in
[SECURITY.md](../SECURITY.md#supported-versions): fixes go on `main` and into its next release,
with no maintained branches and no backports. A 2.0.0, if there is one, ends support for 1.x.

After the grant period there is no commitment: no further releases, fixes or support are
promised ([architecture §10, Maintenance](architecture.md#10-delivery-plan)). Releases already
published stay as they are, and the code remains open source for anyone to run, fork or maintain.

## Pre-releases

A tag `vX.Y.Z-rc.N` is a candidate for `X.Y.Z`. Its contracts may still change before that
release, and it is published as a GitHub pre-release. The release workflows run for it as for a
release, under the same tag check.

## The release gate

The steps to make release `X.Y.Z`; the decision to release, and the version, are the owner's.

1. **Choose the number** from the draft notes in `docs/release-notes/`: a breaking change outside
   the exceptions makes it major, an addition minor, anything else a patch.
2. **Prepare one release commit** on top of the reviewed `main`:
   - set `version` under `[workspace.package]` in `Cargo.toml`, and the same `version` in
     `execution-runtime/Cargo.toml`, the worker's own workspace (the binaries workflow refuses
     the two disagreeing);
   - let the lockfiles follow, and move nothing else. The root workspace, `execution-runtime/` and
     `contracts/` each record the workspace crates' version (the last two depend on them by path):
     run `cargo update --workspace` with each one's `--manifest-path`, then check that
     `cargo metadata --locked --format-version 1 --manifest-path <workspace>/Cargo.toml` succeeds
     for all three and that `git diff` changes only `ozpb-*` versions;
   - set `version` in `.claude-plugin/plugin.json`;
   - rename the draft notes to `docs/release-notes/vX.Y.Z.md` if they carry another number, and
     replace "draft" and "Not yet released" with the release date.

   Leave these alone: the `version` of every crate under `contracts/` and the crate version
   codegen emits. A contract crate's version is part of the `-C metadata` cargo compiles it with,
   which can change its Wasm, and the generated crates are byte-for-byte fixtures. The workspace
   version reaches no Wasm and no fixture: the CLI's `--version` reports it, and the release
   workflows check the tag against it.
3. **Run the gates on that commit**: `bash scripts/verify-phase1.sh`, the CI workflow, the
   `nightly live` workflow dispatched on it, and a dry run of the binaries
   (`gh workflow run release-binaries.yml --ref <branch>`), which builds and packages every
   platform without uploading. A release that delivers a milestone also needs the acceptance its
   verification guide records ([TRANCHE-3-VERIFICATION.md](TRANCHE-3-VERIFICATION.md) for the
   third).
4. **Merge** the release commit to `main`, then create an annotated tag `vX.Y.Z` on it and push
   the tag.
5. **Publish a GitHub Release** from the tag, titled for the milestone it delivers when it
   delivers one, with the release notes as its body; mark a `-rc.N` as a pre-release.
   Publication runs `publish-image.yml` (images, [self-hosting](SELF-HOSTING.md#build-the-reviewed-revision))
   and `release-binaries.yml` (binaries, `SHA256SUMS`, the wire contract, attestations). Both
   refuse a tag that does not name the workspace version.
6. **Check the result**: both workflows green; the assets present and one of them passing
   `gh attestation verify` with the workflow, tag and runner checks that
   [self-hosting](SELF-HOSTING.md#obtain-and-verify) gives; the image references from
   `publish-image.yml`'s summary added to the release body. `release-binaries.yml` never
   replaces an asset, so delete a partial upload before re-running it, and re-run all its jobs:
   a re-run of only the failed ones stops, since files pass between its jobs under names that
   carry the attempt. It uploads after publication, so it needs GitHub's immutable releases off
   for this repository.
7. **If the release changes a registry**, attach its new head, `roots.json` and the head
   checkpoint ([publishing](REGISTRY-GOVERNANCE.md#publishing)).
