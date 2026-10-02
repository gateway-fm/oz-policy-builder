//! CLI entry points for the layer-1 reference suite and artifact reproduction.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Subcommand;
use ozpb_api_types::{ReferenceSuiteInput, VerifyInput};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{print_json, read_json, BuildConfigArgs};

#[derive(Subcommand)]
pub enum Command {
    /// Run the offline reference suite (layer 1 only; not a full dry run).
    ReferenceSuite {
        #[arg(long)]
        spec: PathBuf,
    },
    /// Reproduce a generated crate and Wasm, reporting each verification dimension.
    Verify {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value_t = 0)]
        rule: usize,
        /// Root of the generated crate, including Cargo.toml and src/.
        #[arg(long)]
        generated_dir: PathBuf,
        /// Generated Wasm artifact to reproduce.
        #[arg(long)]
        wasm: PathBuf,
        /// BuildManifest emitted alongside the generated crate.
        #[arg(long)]
        manifest: PathBuf,
        #[command(flatten)]
        build: BuildConfigArgs,
    },
}

impl Command {
    pub fn run(self) -> Result<()> {
        match self {
            Self::ReferenceSuite { spec } => {
                let result = ozpb_toolkit::reference_suite(&ReferenceSuiteInput {
                    spec: read_json(&spec)?,
                })?;
                print_json(&result)?;
            }
            Self::Verify {
                spec,
                rule,
                generated_dir,
                wasm,
                manifest,
                build,
            } => {
                let claimed_generated_files =
                    read_generated_files(&generated_dir, &wasm, &manifest)?;
                let claimed_wasm =
                    std::fs::read(&wasm).with_context(|| format!("reading {}", wasm.display()))?;
                let result = ozpb_toolkit::verify_with_build_config(
                    &VerifyInput {
                        spec: read_json(&spec)?,
                        rule_index: rule,
                        claimed_generated_files,
                        claimed_wasm_base64: Some(
                            base64::engine::general_purpose::STANDARD.encode(claimed_wasm),
                        ),
                        claimed_build_manifest: Some(read_json(&manifest)?),
                    },
                    &build.resolve()?,
                )?;
                print_json(&result)?;
            }
        }
        Ok(())
    }
}

/// Read the complete generated crate, except Cargo.lock and the separately supplied
/// Wasm/manifest artifacts. The toolkit compares this exact path set with regeneration.
fn read_generated_files(
    generated_dir: &Path,
    wasm: &Path,
    manifest: &Path,
) -> Result<BTreeMap<String, String>> {
    if std::fs::symlink_metadata(generated_dir)
        .with_context(|| format!("reading {}", generated_dir.display()))?
        .file_type()
        .is_symlink()
    {
        bail!(
            "generated crate root cannot be a symlink: {}",
            generated_dir.display()
        );
    }
    let root = generated_dir
        .canonicalize()
        .with_context(|| format!("reading {}", generated_dir.display()))?;
    if !root.is_dir() {
        bail!(
            "generated crate root is not a directory: {}",
            root.display()
        );
    }
    let wasm = wasm
        .canonicalize()
        .with_context(|| format!("reading {}", wasm.display()))?;
    let manifest = manifest
        .canonicalize()
        .with_context(|| format!("reading {}", manifest.display()))?;

    let mut files = BTreeMap::new();
    let mut directories = vec![root.clone()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("reading {}", directory.display()))?
        {
            let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
            let path = entry.path();
            let relative = path.strip_prefix(&root)?;
            if relative == Path::new("Cargo.lock") || path == wasm || path == manifest {
                continue;
            }
            let kind = entry
                .file_type()
                .with_context(|| format!("reading {}", path.display()))?;
            if kind.is_symlink() {
                bail!("generated crate contains a symlink: {}", path.display());
            }
            if kind.is_dir() {
                directories.push(path);
                continue;
            }
            if !kind.is_file() {
                bail!(
                    "generated crate contains a non-file entry: {}",
                    path.display()
                );
            }
            let key = relative
                .to_str()
                .context("generated crate contains a non-UTF-8 path")?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("reading generated file {}", path.display()))?;
            files.insert(key, contents);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command as CliCommand};
    use clap::Parser;

    #[test]
    fn commands_parse_at_the_top_level_with_the_crate_root_and_build_flags() {
        let suite = Cli::try_parse_from(["ozpb", "reference-suite", "--spec", "spec.json"])
            .expect("reference suite command");
        assert!(matches!(
            suite.command,
            CliCommand::Verification(Command::ReferenceSuite { .. })
        ));

        let verify = Cli::try_parse_from([
            "ozpb",
            "verify",
            "--spec",
            "spec.json",
            "--generated-dir",
            "generated",
            "--wasm",
            "generated/policy.wasm",
            "--manifest",
            "generated/build-manifest.json",
            "--build-jobs",
            "2",
        ])
        .expect("verify command");
        match verify.command {
            CliCommand::Verification(Command::Verify {
                generated_dir,
                build,
                ..
            }) => {
                assert_eq!(generated_dir, Path::new("generated"));
                assert_eq!(build.build_jobs, Some(2));
            }
            _ => panic!("expected verify command"),
        }
    }

    #[test]
    fn generated_file_reader_includes_every_non_lock_file_and_rejects_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("generated");
        std::fs::create_dir_all(root.join("src")).unwrap();
        for (path, contents) in [
            ("Cargo.toml", "package"),
            ("rust-toolchain.toml", "toolchain"),
            ("src/lib.rs", "lib"),
            ("src/contract.rs", "contract"),
            ("src/extra.rs", "extra"),
            ("Cargo.lock", "lock"),
            ("policy.wasm", "wasm"),
            ("build-manifest.json", "{}"),
        ] {
            std::fs::write(root.join(path), contents).unwrap();
        }
        let files = read_generated_files(
            &root,
            &root.join("policy.wasm"),
            &root.join("build-manifest.json"),
        )
        .unwrap();
        assert_eq!(files.len(), 5);
        assert_eq!(files.get("Cargo.toml"), Some(&"package".to_string()));
        assert_eq!(files.get("src/extra.rs"), Some(&"extra".to_string()));
        assert!(!files.contains_key("Cargo.lock"));
        assert!(!files.contains_key("build-manifest.json"));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(temp.path(), root.join("src/outside")).unwrap();
            let error = read_generated_files(
                &root,
                &root.join("policy.wasm"),
                &root.join("build-manifest.json"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("symlink"));
        }
    }
}
