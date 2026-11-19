//! Publishing a generated artifact keyed by its Wasm hash (architecture §6.3), and checking a
//! published directory before `verify` reproduces it (`docs/PUBLISHING.md`).
//!
//! Pure: these functions take and return file contents by path. Reading and writing the
//! directory is the shell's job.

use super::{spec_error, EC};
use base64::Engine;
use ozpb_api_types::{ToolError, VerifyInput};
use ozpb_build_runner::BuildManifest;
use ozpb_policy_spec::PolicySpec;
use std::collections::BTreeMap;

/// Every other file of a published build with its plain SHA-256, in `sha256sum` format.
pub const PUBLISHED_INDEX: &str = "SHA256SUMS";
/// The PolicySpec the artifact was generated from.
pub const PUBLISHED_SPEC: &str = "policy-spec.json";
/// The BuildManifest.
pub const PUBLISHED_MANIFEST: &str = "build-manifest.json";
/// The Wasm whose SHA-256 names the parent directory.
pub const PUBLISHED_WASM: &str = "policy.wasm";
/// The directory holding every file `generate` emitted, `Cargo.lock` included.
pub const PUBLISHED_SOURCE_DIR: &str = "source";
/// Most entries, files and directories together, a reader admits from a published build. The
/// layout holds four files and a crate of six.
pub const MAX_PUBLISHED_ENTRIES: usize = 64;
/// Most bytes a reader admits from a published build, all files together.
pub const MAX_PUBLISHED_BYTES: u64 = 16 * 1024 * 1024;

const LOCKFILE: &str = "Cargo.lock";

/// What `generate` produced, as the files a user holds after `ozpb generate --out`.
pub struct PublishInput<'a> {
    pub spec: &'a [u8],
    /// Every file `generate` emitted, `Cargo.lock` included, by its path in the crate.
    pub generated_files: &'a BTreeMap<String, String>,
    pub wasm: &'a [u8],
    pub manifest: &'a [u8],
}

/// One published build: where it goes, `<wasm_hash>/<manifest_hash>/`, and every file in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedArtifact {
    /// Lowercase hex SHA-256 of the Wasm: the on-chain code hash, and the outer directory.
    pub wasm_hash: String,
    /// Lowercase hex BuildManifest hash (`ozpb:v2:build-manifest`): the inner directory. One Wasm
    /// can be built from many specs, since only the normalized input decides its bytes.
    pub manifest_hash: String,
    /// Each file by its `/`-separated path inside the inner directory, the index included.
    pub files: BTreeMap<String, Vec<u8>>,
    /// How many rules the published spec holds. The manifest binds the whole spec, so every
    /// rule in it is published with this one rule's build.
    pub spec_rules: usize,
}

fn sha256_hex(bytes: &[u8]) -> String {
    ozpb_domain::sha256(bytes).to_hex()
}

/// A name that stays inside the directory it is joined to on every platform: `/`-separated
/// components of letters, digits, `.`, `_` and `-`, none of them empty, `.` or `..`. Generated
/// crates use nothing else, and the charset leaves no drive prefix, backslash, space or control
/// character for a filesystem or a `sha256sum` line to interpret.
fn is_plain_relative_path(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn refuse_unsafe_names<'a>(names: impl IntoIterator<Item = &'a String>) -> Result<(), ToolError> {
    let unsafe_names: Vec<String> = names
        .into_iter()
        .filter(|name| !is_plain_relative_path(name))
        .map(|name| format!("{name:?}"))
        .collect();
    if unsafe_names.is_empty() {
        return Ok(());
    }
    Err(ToolError::new(
        EC::EPublishPath,
        "file names must be plain relative paths inside the published directory",
    )
    .with_details(unsafe_names))
}

fn manifest_mismatch(message: impl Into<String>) -> ToolError {
    ToolError::new(EC::EPublishManifestMismatch, message)
}

fn index_mismatch(message: impl Into<String>) -> ToolError {
    ToolError::new(EC::EPublishIndexMismatch, message)
}

fn internal(error: impl std::fmt::Display) -> ToolError {
    ToolError::new(EC::EInternal, error.to_string())
}

fn pretty_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ToolError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(internal)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Lay out a generated artifact for publication under its Wasm hash.
///
/// Refuses unless the BuildManifest describes every supplied file: the Wasm by `wasm_hash`, the
/// spec by `spec_hash`, the crate by `source_hash` and `lockfile_hash`. What is published is then
/// one artifact, and a build a reviewer could not reproduce is refused here rather than there.
/// The spec and manifest are written in the form the toolkit writes them, so the same content
/// always publishes the same bytes. A manifest that parses but is not in that form is refused:
/// `verify` compares a claimed manifest as written, so it could never reproduce.
pub fn publish_artifact(input: &PublishInput<'_>) -> Result<PublishedArtifact, ToolError> {
    refuse_unsafe_names(input.generated_files.keys())?;
    let not_a_manifest = |error: serde_json::Error| {
        manifest_mismatch(format!(
            "the manifest is not a {}: {error}",
            ozpb_build_runner::BUILD_MANIFEST_SCHEMA
        ))
    };
    let manifest_json: serde_json::Value =
        serde_json::from_slice(input.manifest).map_err(not_a_manifest)?;
    let manifest: BuildManifest =
        serde_json::from_value(manifest_json.clone()).map_err(not_a_manifest)?;
    if manifest.schema != ozpb_build_runner::BUILD_MANIFEST_SCHEMA {
        return Err(manifest_mismatch(format!(
            "the manifest names schema {:?}; this toolkit reads {}",
            manifest.schema,
            ozpb_build_runner::BUILD_MANIFEST_SCHEMA
        )));
    }
    if serde_json::to_value(&manifest).map_err(internal)? != manifest_json {
        return Err(manifest_mismatch(
            "the manifest is not written the way the toolkit writes it (for example, a hash in \
             uppercase); verify compares a manifest as written, so it could never reproduce",
        ));
    }
    let wasm_hash = ozpb_domain::sha256(input.wasm);
    if wasm_hash != manifest.wasm_hash {
        return Err(ToolError::new(
            EC::EPublishWasmMismatch,
            format!(
                "the Wasm's SHA-256 is {}; the manifest names {}",
                wasm_hash.to_hex(),
                manifest.wasm_hash.to_hex()
            ),
        ));
    }
    let spec: PolicySpec = serde_json::from_slice(input.spec)
        .map_err(|error| ToolError::new(EC::ESpecInvalid, format!("malformed spec: {error}")))?;
    let spec = spec.validate().map_err(|errors| spec_error(&errors))?;
    if spec.hash() != manifest.spec_hash {
        return Err(manifest_mismatch(format!(
            "the spec's hash is {}; the manifest was built from {}",
            spec.hash().to_hex(),
            manifest.spec_hash.to_hex()
        )));
    }
    if ozpb_build_runner::source_hash(input.generated_files).map_err(internal)?
        != manifest.source_hash
    {
        return Err(manifest_mismatch(
            "the crate's files are not the source the manifest was built from: a file was \
             edited, added or removed after generation",
        ));
    }
    let lockfile = input
        .generated_files
        .get(LOCKFILE)
        .ok_or_else(|| manifest_mismatch("the crate has no Cargo.lock; generate emits one"))?;
    if ozpb_domain::sha256(lockfile.as_bytes()) != manifest.lockfile_hash {
        return Err(manifest_mismatch(
            "Cargo.lock is not the lockfile the manifest was built with",
        ));
    }

    let mut files: BTreeMap<String, Vec<u8>> = input
        .generated_files
        .iter()
        .map(|(name, contents)| {
            (
                format!("{PUBLISHED_SOURCE_DIR}/{name}"),
                contents.as_bytes().to_vec(),
            )
        })
        .collect();
    files.insert(PUBLISHED_SPEC.to_string(), pretty_json(spec.spec())?);
    files.insert(PUBLISHED_MANIFEST.to_string(), pretty_json(&manifest_json)?);
    files.insert(PUBLISHED_WASM.to_string(), input.wasm.to_vec());
    let index: String = files
        .iter()
        .map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)))
        .collect();
    files.insert(PUBLISHED_INDEX.to_string(), index.into_bytes());
    Ok(PublishedArtifact {
        wasm_hash: wasm_hash.to_hex(),
        manifest_hash: manifest.hash().map_err(internal)?.to_hex(),
        files,
        spec_rules: spec.spec().rules.len(),
    })
}

/// Read `SHA256SUMS`: one `<64 lowercase hex>  <path>` line per file.
fn parse_index(bytes: &[u8]) -> Result<BTreeMap<String, String>, ToolError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| index_mismatch(format!("{PUBLISHED_INDEX} is not UTF-8 text")))?;
    let mut listed = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let entry = line.split_once("  ").filter(|(hash, name)| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                && !name.is_empty()
        });
        let Some((hash, name)) = entry else {
            return Err(index_mismatch(format!(
                "{PUBLISHED_INDEX} line {} is not `<sha256>  <path>`",
                number + 1
            )));
        };
        if listed.insert(name.to_string(), hash.to_string()).is_some() {
            return Err(index_mismatch(format!(
                "{PUBLISHED_INDEX} lists {name} twice"
            )));
        }
    }
    Ok(listed)
}

/// Check a published build and turn it into the `verify` input that reproduces it.
///
/// In order: every name is a plain relative path; the Wasm is the one the outer directory is
/// named for; the index lists exactly the other files with their SHA-256; the files are the
/// build [`publish_artifact`] writes from them, which holds the manifest to the spec, crate and
/// Wasm; and the inner directory is named for that manifest. The index is unsigned — whoever
/// can edit a file can rewrite it — so it catches a damaged or incomplete copy, and the checks
/// after it hold on their own. The lockfile check is the one `verify` does not repeat. The rule
/// index comes from the manifest: a wrong one regenerates other source, which `verify` reports.
pub fn check_published(
    wasm_hash: &str,
    manifest_hash: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<VerifyInput, ToolError> {
    refuse_unsafe_names(files.keys())?;
    let wasm = files
        .get(PUBLISHED_WASM)
        .ok_or_else(|| index_mismatch(format!("the build has no {PUBLISHED_WASM}")))?;
    let actual = sha256_hex(wasm);
    if actual != wasm_hash {
        return Err(ToolError::new(
            EC::EPublishWasmMismatch,
            format!("{PUBLISHED_WASM} has SHA-256 {actual}; its directory is named {wasm_hash:?}"),
        ));
    }

    let index = files
        .get(PUBLISHED_INDEX)
        .ok_or_else(|| index_mismatch(format!("the build has no {PUBLISHED_INDEX}")))?;
    let listed = parse_index(index)?;
    let mut findings = Vec::new();
    for (name, bytes) in files {
        if name == PUBLISHED_INDEX {
            continue;
        }
        let hash = sha256_hex(bytes);
        match listed.get(name) {
            None => findings.push(format!("{name}: present but not listed")),
            Some(expected) if *expected != hash => {
                findings.push(format!("{name}: SHA-256 {hash}, listed as {expected}"))
            }
            Some(_) => {}
        }
    }
    for name in listed.keys() {
        if !files.contains_key(name) {
            findings.push(format!("{name}: listed but absent"));
        }
    }
    if !findings.is_empty() {
        return Err(
            index_mismatch(format!("the build does not match its {PUBLISHED_INDEX}"))
                .with_details(findings),
        );
    }

    let required = |name: &str| {
        files
            .get(name)
            .ok_or_else(|| index_mismatch(format!("the build has no {name}")))
    };
    let spec = required(PUBLISHED_SPEC)?;
    let manifest = required(PUBLISHED_MANIFEST)?;
    let source_prefix = format!("{PUBLISHED_SOURCE_DIR}/");
    let mut generated_files = BTreeMap::new();
    for (name, bytes) in files {
        if let Some(relative) = name.strip_prefix(&source_prefix) {
            let text = String::from_utf8(bytes.clone()).map_err(|_| {
                manifest_mismatch(format!(
                    "{name} is not UTF-8 text; generate emits only text"
                ))
            })?;
            generated_files.insert(relative.to_string(), text);
        }
    }
    let republished = publish_artifact(&PublishInput {
        spec,
        generated_files: &generated_files,
        wasm,
        manifest,
    })?;
    if republished.manifest_hash != manifest_hash {
        return Err(manifest_mismatch(format!(
            "the manifest's hash is {}; its directory is named {manifest_hash:?}",
            republished.manifest_hash
        )));
    }
    if republished.files != *files {
        return Err(index_mismatch(format!(
            "the build is not what publish-artifact writes from its own files: only \
             {PUBLISHED_INDEX}, {PUBLISHED_SPEC}, {PUBLISHED_MANIFEST}, {PUBLISHED_WASM} and \
             {PUBLISHED_SOURCE_DIR}/, each in the form publish-artifact writes it"
        ))
        .with_details(differing_names(files, &republished.files)));
    }

    let parse = |bytes: &[u8]| serde_json::from_slice::<serde_json::Value>(bytes).map_err(internal);
    let rule_index = serde_json::from_slice::<BuildManifest>(manifest)
        .map_err(internal)?
        .rule_index;
    Ok(VerifyInput {
        spec: parse(spec)?,
        rule_index: usize::try_from(rule_index).map_err(internal)?,
        claimed_generated_files: generated_files
            .into_iter()
            .filter(|(name, _)| name != LOCKFILE)
            .collect(),
        claimed_wasm_base64: Some(base64::engine::general_purpose::STANDARD.encode(wasm)),
        claimed_build_manifest: Some(parse(manifest)?),
        generated_artifact: None,
    })
}

/// The names whose content differs between two builds, or that only one of them holds.
fn differing_names(
    left: &BTreeMap<String, Vec<u8>>,
    right: &BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
    let mut names: Vec<String> = left
        .iter()
        .filter(|(name, bytes)| right.get(*name) != Some(*bytes))
        .map(|(name, _)| name.clone())
        .chain(
            right
                .keys()
                .filter(|name| !left.contains_key(*name))
                .cloned(),
        )
        .collect();
    names.sort();
    names
}

/// Accept a destination that already holds exactly this build; refuse one that holds anything
/// else. Publishing is idempotent, never an overwrite.
pub fn check_republish(
    existing: &BTreeMap<String, Vec<u8>>,
    artifact: &PublishedArtifact,
) -> Result<(), ToolError> {
    if *existing == artifact.files {
        return Ok(());
    }
    Err(ToolError::new(
        EC::EPublishConflict,
        format!(
            "{}/{} already holds other content; nothing was written",
            artifact.wasm_hash, artifact.manifest_hash
        ),
    )
    .with_details(differing_names(existing, &artifact.files)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{build_config, wire_spec};
    use crate::{generate_code_with_build_config, verify_with_build_config};
    use ozpb_api_types::{GenerateCodeInput, GenerateCodeOutput};

    /// The golden spec generated with the hermetic builder, as `ozpb generate --out` leaves it.
    struct Generated {
        spec: Vec<u8>,
        output: GenerateCodeOutput,
        wasm: Vec<u8>,
        manifest: Vec<u8>,
    }

    fn generated() -> Generated {
        use base64::Engine;
        let spec = serde_json::to_vec_pretty(wire_spec().spec()).unwrap();
        let output = generate_code_with_build_config(
            &GenerateCodeInput {
                spec: serde_json::from_slice(&spec).unwrap(),
                rule_index: 0,
            },
            &build_config(),
        )
        .unwrap();
        let wasm = base64::engine::general_purpose::STANDARD
            .decode(&output.wasm_base64)
            .unwrap();
        let manifest = serde_json::to_vec_pretty(&output.build_manifest).unwrap();
        Generated {
            spec,
            output,
            wasm,
            manifest,
        }
    }

    impl Generated {
        fn input(&self) -> PublishInput<'_> {
            PublishInput {
                spec: &self.spec,
                generated_files: &self.output.files,
                wasm: &self.wasm,
                manifest: &self.manifest,
            }
        }

        fn published(&self) -> PublishedArtifact {
            publish_artifact(&self.input()).unwrap()
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        ozpb_domain::sha256(bytes).to_hex()
    }

    fn check(
        published: &PublishedArtifact,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<VerifyInput, ToolError> {
        check_published(&published.wasm_hash, &published.manifest_hash, files)
    }

    /// Rewrite the index so it lists the directory's files as they now are: a tamperer who
    /// edits a file can always do this, so the checks after the index must hold on their own.
    fn reindex(files: &mut BTreeMap<String, Vec<u8>>) {
        files.remove(PUBLISHED_INDEX);
        let index: String = files
            .iter()
            .map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)))
            .collect();
        files.insert(PUBLISHED_INDEX.to_string(), index.into_bytes());
    }

    fn code(result: Result<impl std::fmt::Debug, ToolError>) -> EC {
        match result {
            Ok(value) => panic!("expected a refusal, got {value:?}"),
            Err(error) => error.code,
        }
    }

    #[test]
    fn a_published_build_is_keyed_by_its_wasm_and_manifest_hashes_and_indexes_every_file() {
        let generated = generated();
        let published = generated.published();

        assert_eq!(published.wasm_hash, generated.output.wasm_hash);
        assert_eq!(published.wasm_hash, sha256_hex(&generated.wasm));
        assert_eq!(
            published.manifest_hash,
            generated.output.build_manifest_hash
        );
        assert_eq!(published.files[PUBLISHED_WASM], generated.wasm);
        // The spec and manifest in the form the toolkit writes them, whatever form they came in.
        let mut spec = serde_json::to_vec_pretty(wire_spec().spec()).unwrap();
        spec.push(b'\n');
        assert_eq!(published.files[PUBLISHED_SPEC], spec);
        let mut manifest = serde_json::to_vec_pretty(&generated.output.build_manifest).unwrap();
        manifest.push(b'\n');
        assert_eq!(published.files[PUBLISHED_MANIFEST], manifest);
        // Exactly the files generate emitted, the lockfile included, under `source/`.
        let source: BTreeMap<&str, &[u8]> = published
            .files
            .iter()
            .filter_map(|(name, bytes)| {
                name.strip_prefix("source/")
                    .map(|name| (name, bytes.as_slice()))
            })
            .collect();
        let emitted: BTreeMap<&str, &[u8]> = generated
            .output
            .files
            .iter()
            .map(|(name, contents)| (name.as_str(), contents.as_bytes()))
            .collect();
        assert_eq!(source, emitted);
        assert!(source.contains_key("Cargo.lock"));
        assert_eq!(published.files.len(), emitted.len() + 4);

        // The index is `sha256sum` output: every other file, in path order, with its plain
        // SHA-256, so `sha256sum -c SHA256SUMS` checks the directory without this toolkit.
        let index = std::str::from_utf8(&published.files[PUBLISHED_INDEX]).unwrap();
        let expected: String = published
            .files
            .iter()
            .filter(|(name, _)| name.as_str() != PUBLISHED_INDEX)
            .map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)))
            .collect();
        assert_eq!(index, expected);
        assert!(index.starts_with(&format!("{}  build-manifest.json\n", sha256_hex(&manifest))));
        assert_eq!(
            generated.published(),
            published,
            "publishing is deterministic"
        );
    }

    /// Two spellings of the same spec and manifest publish the same bytes, so republishing after
    /// a reformat is not a conflict.
    #[test]
    fn the_spec_and_manifest_are_published_in_one_form() {
        let pretty = generated();
        let mut compact = generated();
        compact.spec = serde_json::to_vec(wire_spec().spec()).unwrap();
        compact.manifest = serde_json::to_vec(&compact.output.build_manifest).unwrap();
        assert_ne!(compact.spec, pretty.spec);
        assert_eq!(compact.published(), pretty.published());
    }

    /// The offline round trip: publish, check the directory, and reproduce it through the same
    /// `verify` that `ozpb verify` runs.
    #[test]
    fn a_published_build_reproduces_through_verify() {
        let generated = generated();
        let published = generated.published();

        let input = check(&published, &published.files).unwrap();
        assert_eq!(input.rule_index, 0);
        assert!(!input.claimed_generated_files.contains_key("Cargo.lock"));
        let output = verify_with_build_config(&input, &build_config()).unwrap();
        assert!(output.matches, "{output:?}");
        assert_eq!(
            output.source_reproduction,
            "reproduced: generated non-lock files are byte-identical"
        );
        assert_eq!(
            output.wasm_reproduction,
            "reproduced: Wasm and BuildManifest are identical"
        );
    }

    /// A manifest made by another toolkit build differs only in its producer record. It is
    /// another build of the same Wasm, so it publishes beside the first, and verification says
    /// what it says for `ozpb verify`.
    #[test]
    fn a_manifest_from_another_producer_publishes_beside_and_verify_says_so() {
        let first = generated().published();
        let mut generated = generated();
        let mut manifest = generated.output.build_manifest.clone();
        manifest["producer"]["toolkit_source"] =
            serde_json::json!({"commit": "b".repeat(40), "dirty": false});
        generated.manifest = serde_json::to_vec_pretty(&manifest).unwrap();
        let published = generated.published();
        assert_eq!(published.wasm_hash, first.wasm_hash);
        assert_ne!(published.manifest_hash, first.manifest_hash);

        let input = check(&published, &published.files).unwrap();
        let output = verify_with_build_config(&input, &build_config()).unwrap();
        assert!(output.matches, "{output:?}");
        assert_eq!(
            output.wasm_reproduction,
            "reproduced: Wasm and BuildManifest are identical except its producer record \
             (toolkit revision, template pack, build image), which describes the build that \
             made the claim and is not reproducible"
        );
    }

    /// The checks before `verify` bind the files to each other, not to the truth: whoever edits
    /// the crate can also rewrite `source_hash`, rename the directory to the new manifest hash
    /// and rewrite the index. Such a forgery must pass every publication check and then fail the
    /// rebuild, which regenerates the source from the spec rather than trusting the published one.
    #[test]
    fn a_self_consistent_forgery_passes_the_checks_and_fails_verify() {
        let generated = generated();
        let mut forged = generated.output.files.clone();
        forged
            .get_mut("src/contract.rs")
            .unwrap()
            .push_str("\n// a backdoor would go here\n");
        let mut manifest = generated.output.build_manifest.clone();
        manifest["source_hash"] =
            serde_json::json!(ozpb_build_runner::source_hash(&forged).unwrap().to_hex());
        let manifest = serde_json::to_vec_pretty(&manifest).unwrap();
        let published = publish_artifact(&PublishInput {
            spec: &generated.spec,
            generated_files: &forged,
            wasm: &generated.wasm,
            manifest: &manifest,
        })
        .unwrap();
        assert_eq!(published.wasm_hash, generated.output.wasm_hash);
        assert_ne!(
            published.manifest_hash,
            generated.output.build_manifest_hash
        );

        let input = check(&published, &published.files).unwrap();
        let output = verify_with_build_config(&input, &build_config()).unwrap();
        assert!(!output.matches, "{output:?}");
        assert_eq!(
            output.source_reproduction,
            "MISMATCH: generated non-lock files differ from regeneration"
        );
        assert_eq!(
            output.wasm_reproduction,
            "MISMATCH: claimed BuildManifest differs from reproduction"
        );
    }

    /// The manifest binds the whole spec, so the whole spec is published, every rule in it. The
    /// count is reported so the shell can say so.
    #[test]
    fn the_published_spec_reports_how_many_rules_it_carries() {
        assert_eq!(generated().published().spec_rules, 1);
    }

    #[test]
    fn publishing_refuses_a_wasm_the_manifest_does_not_name() {
        let mut generated = generated();
        generated.wasm.push(0);
        assert_eq!(
            code(publish_artifact(&generated.input())),
            EC::EPublishWasmMismatch
        );
    }

    #[test]
    fn publishing_refuses_files_the_manifest_does_not_describe() {
        // A hand-edited source file is a custom artifact, not this manifest's.
        let mut edited = generated();
        edited
            .output
            .files
            .get_mut("src/contract.rs")
            .unwrap()
            .push_str("\n// edited\n");
        assert_eq!(
            code(publish_artifact(&edited.input())),
            EC::EPublishManifestMismatch
        );

        // Another lockfile, and none.
        let mut relocked = generated();
        relocked
            .output
            .files
            .get_mut("Cargo.lock")
            .unwrap()
            .push('\n');
        assert_eq!(
            code(publish_artifact(&relocked.input())),
            EC::EPublishManifestMismatch
        );
        let mut unlocked = generated();
        unlocked.output.files.remove("Cargo.lock");
        assert_eq!(
            code(publish_artifact(&unlocked.input())),
            EC::EPublishManifestMismatch
        );

        // Another spec: still valid, but not the one the manifest names.
        let mut other_spec = generated();
        let mut spec = wire_spec().spec().clone();
        spec.name = "another-name".to_string();
        let spec = spec.validate().unwrap();
        other_spec.spec = serde_json::to_vec(spec.spec()).unwrap();
        assert_eq!(
            code(publish_artifact(&other_spec.input())),
            EC::EPublishManifestMismatch
        );

        // Not a manifest at all, and a complete one that names another schema.
        let mut not_a_manifest = generated();
        not_a_manifest.manifest = b"{\"schema\": \"build-manifest/v2\"}".to_vec();
        assert_eq!(
            code(publish_artifact(&not_a_manifest.input())),
            EC::EPublishManifestMismatch
        );
        let mut other_schema = generated();
        let mut manifest = other_schema.output.build_manifest.clone();
        manifest["schema"] = serde_json::json!("build-manifest/v1");
        other_schema.manifest = serde_json::to_vec(&manifest).unwrap();
        let error = publish_artifact(&other_schema.input()).unwrap_err();
        assert_eq!(error.code, EC::EPublishManifestMismatch);
        assert!(error.message.contains("build-manifest/v1"), "{error}");

        // A manifest that parses but is not written the way the toolkit writes it: `verify`
        // compares a claim as written, so this one could never reproduce.
        let mut uppercase = generated();
        let mut manifest = uppercase.output.build_manifest.clone();
        let wasm_hash = manifest["wasm_hash"].as_str().unwrap().to_uppercase();
        manifest["wasm_hash"] = serde_json::json!(wasm_hash);
        uppercase.manifest = serde_json::to_vec(&manifest).unwrap();
        assert_eq!(
            code(publish_artifact(&uppercase.input())),
            EC::EPublishManifestMismatch
        );

        // Not a spec at all.
        let mut not_a_spec = generated();
        not_a_spec.spec = b"{}".to_vec();
        assert_eq!(
            code(publish_artifact(&not_a_spec.input())),
            EC::ESpecInvalid
        );

        // Control: the unedited inputs publish.
        assert!(publish_artifact(&generated().input()).is_ok());
    }

    #[test]
    fn publishing_refuses_a_file_name_that_leaves_its_directory() {
        for name in [
            "../outside.rs",
            "src/../../outside.rs",
            "/etc/passwd",
            "src//lib.rs",
            "./src/lib.rs",
            "src\\lib.rs",
            "",
            "src/",
            "C:evil",
        ] {
            let mut generated = generated();
            generated
                .output
                .files
                .insert(name.to_string(), "x".to_string());
            assert_eq!(
                code(publish_artifact(&generated.input())),
                EC::EPublishPath,
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_changed_source_byte_is_refused_by_the_index_and_then_by_the_manifest() {
        let published = generated().published();
        for name in ["source/src/contract.rs", "source/Cargo.lock"] {
            let mut files = published.files.clone();
            let file = files.get_mut(name).unwrap();
            let last = file.len() - 2;
            file[last] ^= 0x01;

            let error = check(&published, &files).unwrap_err();
            assert_eq!(error.code, EC::EPublishIndexMismatch, "{name}");
            assert!(error.details.iter().any(|d| d.contains(name)), "{error}");

            // With the index rewritten to match, the manifest no longer describes the crate.
            // `verify` never compares the lockfile, so for it this is the only check.
            reindex(&mut files);
            assert_eq!(
                code(check(&published, &files)),
                EC::EPublishManifestMismatch,
                "{name}"
            );
        }
    }

    #[test]
    fn a_swapped_wasm_is_refused_whatever_else_is_rewritten() {
        let published = generated().published();
        let other = b"\0asm-another-module".to_vec();

        let mut swapped = published.files.clone();
        swapped.insert(PUBLISHED_WASM.to_string(), other.clone());
        assert_eq!(code(check(&published, &swapped)), EC::EPublishWasmMismatch);

        // Index rewritten and the directory renamed to the new Wasm's hash: the manifest still
        // names the original.
        reindex(&mut swapped);
        assert_eq!(
            code(check_published(
                &sha256_hex(&other),
                &published.manifest_hash,
                &swapped
            )),
            EC::EPublishWasmMismatch
        );
    }

    #[test]
    fn a_build_directory_named_for_another_manifest_is_refused() {
        let published = generated().published();
        assert_eq!(
            code(check_published(
                &published.wasm_hash,
                &"0".repeat(64),
                &published.files
            )),
            EC::EPublishManifestMismatch
        );
    }

    #[test]
    fn an_extra_or_missing_file_is_refused() {
        let published = generated().published();

        let mut extra = published.files.clone();
        extra.insert("source/src/extra.rs".to_string(), b"// extra\n".to_vec());
        let error = check(&published, &extra).unwrap_err();
        assert_eq!(error.code, EC::EPublishIndexMismatch);
        assert!(
            error
                .details
                .iter()
                .any(|d| d.contains("source/src/extra.rs")),
            "{error}"
        );
        // Listed in a rewritten index, an extra source file changes the source the manifest
        // describes.
        reindex(&mut extra);
        assert_eq!(
            code(check(&published, &extra)),
            EC::EPublishManifestMismatch
        );

        // Outside the crate, an extra file is not part of the layout even when listed.
        let mut stray = published.files.clone();
        stray.insert("README.txt".to_string(), b"trust me\n".to_vec());
        reindex(&mut stray);
        assert_eq!(code(check(&published, &stray)), EC::EPublishIndexMismatch);

        let mut missing = published.files.clone();
        missing.remove("source/rust-toolchain.toml");
        assert_eq!(code(check(&published, &missing)), EC::EPublishIndexMismatch);
    }

    #[test]
    fn a_traversal_name_in_a_published_directory_is_refused() {
        let published = generated().published();
        for name in ["../policy.wasm", "source/../../x", "/abs", "source\\x"] {
            let mut files = published.files.clone();
            files.insert(name.to_string(), b"x".to_vec());
            reindex(&mut files);
            assert_eq!(
                code(check(&published, &files)),
                EC::EPublishPath,
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_directory_not_in_the_form_publish_writes_is_refused() {
        let published = generated().published();

        // The same listing in another order.
        let mut reordered = published.files.clone();
        let index = String::from_utf8(reordered[PUBLISHED_INDEX].clone()).unwrap();
        let reversed: String = index
            .lines()
            .rev()
            .map(|line| format!("{line}\n"))
            .collect();
        reordered.insert(PUBLISHED_INDEX.to_string(), reversed.into_bytes());
        assert_eq!(
            code(check(&published, &reordered)),
            EC::EPublishIndexMismatch
        );

        // A line that is not `<sha256>  <path>`, and no index at all.
        let mut malformed = published.files.clone();
        malformed.insert(PUBLISHED_INDEX.to_string(), b"not an index\n".to_vec());
        assert_eq!(
            code(check(&published, &malformed)),
            EC::EPublishIndexMismatch
        );
        let mut unindexed = published.files.clone();
        unindexed.remove(PUBLISHED_INDEX);
        assert_eq!(
            code(check(&published, &unindexed)),
            EC::EPublishIndexMismatch
        );

        // A spec in another spelling, reindexed: the same spec, but not the bytes publish writes.
        let mut respelled = published.files.clone();
        let spec: serde_json::Value = serde_json::from_slice(&respelled[PUBLISHED_SPEC]).unwrap();
        respelled.insert(
            PUBLISHED_SPEC.to_string(),
            serde_json::to_vec(&spec).unwrap(),
        );
        reindex(&mut respelled);
        assert_eq!(
            code(check(&published, &respelled)),
            EC::EPublishIndexMismatch
        );
    }

    #[test]
    fn republishing_identical_content_is_accepted_and_other_content_refused() {
        let published = generated().published();
        check_republish(&published.files, &published).unwrap();

        let mut changed = published.files.clone();
        changed.insert(PUBLISHED_SPEC.to_string(), b"{}".to_vec());
        let error = check_republish(&changed, &published).unwrap_err();
        assert_eq!(error.code, EC::EPublishConflict);
        assert!(
            error.details.iter().any(|d| d.contains(PUBLISHED_SPEC)),
            "{error}"
        );

        let mut extra = published.files.clone();
        extra.insert("notes.txt".to_string(), Vec::new());
        assert_eq!(
            code(check_republish(&extra, &published)),
            EC::EPublishConflict
        );
        let mut missing = published.files.clone();
        missing.remove(PUBLISHED_WASM);
        assert_eq!(
            code(check_republish(&missing, &published)),
            EC::EPublishConflict
        );
    }
}
