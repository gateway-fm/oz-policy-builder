//! `ozpb publish-artifact` and `ozpb verify-published`: the file I/O around the toolkit's
//! publication checks (`docs/PUBLISHING.md`). Which files make a published directory, and
//! whether one is consistent, is decided in `ozpb_toolkit::publication`; this module reads and
//! writes them.

use anyhow::{Context, Result};
use clap::Args;
use ozpb_api_types::{ErrorCode as EC, ToolError, VerifyOutput};
use ozpb_toolkit::{PublishInput, PublishedArtifact, MAX_PUBLISHED_BYTES, MAX_PUBLISHED_ENTRIES};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::verification::read_generated_files;
use crate::{print_json, BuildConfigArgs};

/// Exit status of `verify-published` when the build was read and checked, `verify` ran, and its
/// report says `matches: false`: a dimension did not reproduce, or the offline behavioural check
/// failed. The report is printed. A refusal or failure before that exits 1. `ozpb verify` exits
/// 0 either way; this command is the one a reviewer scripts against.
pub const EXIT_NOT_REPRODUCED: i32 = 3;

#[derive(Args, Debug)]
pub struct PublishArgs {
    /// The PolicySpec the artifact was generated from. It is published whole: the smart account,
    /// the recordings it cites and every rule in it, not only the one this build is for.
    #[arg(long)]
    spec: PathBuf,
    /// The directory `ozpb generate --out` wrote: the crate, its Wasm and its BuildManifest.
    #[arg(long)]
    generated_dir: PathBuf,
    /// The generated Wasm.
    #[arg(long)]
    wasm: PathBuf,
    /// The BuildManifest emitted alongside the generated crate.
    #[arg(long)]
    manifest: PathBuf,
    /// Directory to publish into; the build is written to
    /// `<out>/<wasm sha256 hex>/<build manifest hash>/`.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyPublishedArgs {
    /// A published build, `<dir>/<wasm sha256 hex>/<build manifest hash>`.
    directory: PathBuf,
    #[command(flatten)]
    build: BuildConfigArgs,
}

pub fn publish(args: PublishArgs) -> Result<()> {
    let claimed = read_generated_files(&args.generated_dir, &args.wasm, &args.manifest)?;
    if !claimed.unrepresentable.is_empty() {
        return Err(ToolError::new(
            EC::EPublishManifestMismatch,
            "the generated directory holds files generate does not emit (binary content or a \
             name that is not UTF-8); publish the directory `ozpb generate --out` wrote",
        )
        .with_details(claimed.unrepresentable)
        .into());
    }
    let mut generated_files = claimed.files;
    let lockfile = args.generated_dir.join("Cargo.lock");
    if let Some(text) = read_optional_text(&lockfile)? {
        generated_files.insert("Cargo.lock".to_string(), text);
    }
    let read =
        |path: &Path| std::fs::read(path).with_context(|| format!("reading {}", path.display()));
    let artifact = ozpb_toolkit::publish_artifact(&PublishInput {
        spec: &read(&args.spec)?,
        generated_files: &generated_files,
        wasm: &read(&args.wasm)?,
        manifest: &read(&args.manifest)?,
    })?;
    let written = write_published(&args.out, &artifact)?;
    if artifact.spec_rules > 1 {
        eprintln!(
            "note: the published spec holds {} rules, and all of them are published with this \
             build: their signers, targets, limits and expiry",
            artifact.spec_rules
        );
    }
    print_json(&serde_json::json!({
        "wasm_hash": artifact.wasm_hash,
        "build_manifest_hash": artifact.manifest_hash,
        "directory": args.out.join(&artifact.wasm_hash).join(&artifact.manifest_hash),
        "files": artifact.files.len(),
        "spec_rules": artifact.spec_rules,
        "already_published": written == Written::AlreadyPresent,
    }))
}

/// A lockfile `generate` wrote is text. A missing one is left for the toolkit to refuse by name;
/// one that is not UTF-8 cannot be the lockfile any manifest was built with.
fn read_optional_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|_| {
            ToolError::new(
                EC::EPublishManifestMismatch,
                format!("{} is not UTF-8 text", path.display()),
            )
            .into()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Written {
    New,
    AlreadyPresent,
}

/// Write `<out>/<wasm hash>/<manifest hash>/` whole or not at all: the files go into a fresh
/// directory beside it, which is renamed into place. A destination that already exists is read
/// and must hold exactly this build; it is never modified.
fn write_published(out: &Path, artifact: &PublishedArtifact) -> Result<Written> {
    let parent = out.join(&artifact.wasm_hash);
    std::fs::create_dir_all(&parent).with_context(|| format!("creating {}", parent.display()))?;
    // Not followed: a symlink here would put the build outside `out`.
    if !std::fs::symlink_metadata(&parent)
        .with_context(|| format!("reading {}", parent.display()))?
        .file_type()
        .is_dir()
    {
        return Err(path_error(format!(
            "{} is not a directory (a symlink is not followed)",
            parent.display()
        )));
    }
    let destination = parent.join(&artifact.manifest_hash);
    let already_present = || -> Result<Written> {
        ozpb_toolkit::check_republish(&read_published_tree(&destination)?, artifact)?;
        Ok(Written::AlreadyPresent)
    };
    if exists(&destination)? {
        return already_present();
    }
    let staging = tempfile::Builder::new()
        .prefix(".ozpb-publish-")
        .tempdir_in(&parent)
        .with_context(|| format!("creating a staging directory in {}", parent.display()))?;
    for (name, bytes) in &artifact.files {
        // Every name is a plain relative path: the toolkit refused anything else.
        let path = staging.path().join(name);
        if let Some(directory) = path.parent() {
            std::fs::create_dir_all(directory)
                .with_context(|| format!("creating {}", directory.display()))?;
        }
        std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    // A published build is for others to read; the staging directory is created owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(staging.path(), std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("setting permissions on {}", staging.path().display()))?;
    }
    match std::fs::rename(staging.path(), &destination) {
        Ok(()) => {
            // Moved: nothing is left at the staging path for the guard to remove.
            let _ = staging.keep();
            Ok(Written::New)
        }
        // Another publisher of the same build finished first; the same rule as above applies.
        // The staging directory is removed when its guard drops.
        Err(_) if exists(&destination)? => already_present(),
        Err(error) => Err(error).with_context(|| format!("moving into {}", destination.display())),
    }
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// What `verify-published` prints.
#[derive(Debug, serde::Serialize)]
pub struct VerifyPublishedReport {
    /// The outer directory's name: the Wasm hash a reviewer compares with the on-chain one.
    pub wasm_hash: String,
    /// The inner directory's name: the hash of the BuildManifest that claims it.
    pub build_manifest_hash: String,
    /// `verify` over the published spec, crate, Wasm and manifest.
    pub verify: VerifyOutput,
}

pub fn verify_published(args: VerifyPublishedArgs) -> Result<()> {
    let report = check_and_verify(&args.directory, &args.build.resolve()?)?;
    print_json(&report)?;
    match exit_status(&report) {
        0 => Ok(()),
        status => std::process::exit(status),
    }
}

/// 0 when the report matches, [`EXIT_NOT_REPRODUCED`] when it does not. A refusal never reaches
/// a report: it is an error, which exits 1.
fn exit_status(report: &VerifyPublishedReport) -> i32 {
    if report.verify.matches {
        0
    } else {
        EXIT_NOT_REPRODUCED
    }
}

fn check_and_verify(
    directory: &Path,
    build_config: &ozpb_toolkit::BuildConfig,
) -> Result<VerifyPublishedReport> {
    let (wasm_hash, build_manifest_hash) = build_names(directory)?;
    let files = read_published_tree(directory)?;
    let input = ozpb_toolkit::check_published(&wasm_hash, &build_manifest_hash, &files)?;
    let verify = ozpb_toolkit::verify_with_build_config(&input, build_config)?;
    Ok(VerifyPublishedReport {
        wasm_hash,
        build_manifest_hash,
        verify,
    })
}

/// The Wasm and manifest hashes a build is checked against: the last two names of the path the
/// reviewer typed, never of where it resolves. The Wasm-hash directory must not be a symlink —
/// one would have the command check, and reproduce, whatever build it points at under the name
/// asked about — and the build directory itself is refused as one by the tree reader.
fn build_names(directory: &Path) -> Result<(String, String)> {
    let shape = || {
        path_error(format!(
            "{} is not <dir>/<wasm hash>/<build manifest hash>",
            directory.display()
        ))
    };
    let mut names = directory
        .components()
        .rev()
        .map(|component| match component {
            std::path::Component::Normal(name) => name.to_str().map(str::to_string),
            _ => None,
        });
    let manifest_hash = names.next().flatten().ok_or_else(shape)?;
    let wasm_hash = names.next().flatten().ok_or_else(shape)?;
    let parent: PathBuf = {
        let components: Vec<_> = directory.components().collect();
        components[..components.len() - 1].iter().collect()
    };
    let kind = std::fs::symlink_metadata(&parent)
        .with_context(|| format!("reading {}", parent.display()))?
        .file_type();
    if !kind.is_dir() {
        return Err(path_error(format!(
            "{} is not a directory (a symlink is not followed)",
            parent.display()
        )));
    }
    Ok((wasm_hash, manifest_hash))
}

fn path_error(message: String) -> anyhow::Error {
    ToolError::new(EC::EPublishPath, message).into()
}

/// Open a file for reading without following a link and without blocking (a FIFO swapped in
/// after the directory listing would otherwise wait for a writer forever), and refuse anything
/// but a regular file by what was opened rather than by what was listed.
fn open_regular(path: &Path, name: &str) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
    }
    let file = options
        .open(path)
        .map_err(|error| path_error(format!("{name} cannot be opened as a file: {error}")))?;
    let kind = file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?
        .file_type();
    if !kind.is_file() {
        return Err(path_error(format!("{name} is not a regular file")));
    }
    Ok(file)
}

/// Read every regular file under a published build by its `/`-separated relative path.
///
/// A published build usually arrives from somewhere else, so it is read as untrusted content: a
/// symlink anywhere in it (the root included), a special file or a name that is not UTF-8 is
/// refused, and so are more than [`MAX_PUBLISHED_ENTRIES`] entries or [`MAX_PUBLISHED_BYTES`]
/// bytes, before the excess is read. Files are opened without following a link, but a directory
/// is listed by path: a concurrent writer that swaps a listed subdirectory for a symlink is not
/// defended against. Read a copy nobody else is writing.
fn read_published_tree(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    // A trailing separator makes symlink_metadata follow the link on Unix.
    let root_entry: PathBuf = root.components().collect();
    let kind = std::fs::symlink_metadata(&root_entry)
        .with_context(|| format!("reading {}", root.display()))?
        .file_type();
    if !kind.is_dir() {
        return Err(path_error(format!(
            "{} is not a directory (a symlink is not followed)",
            root.display()
        )));
    }
    let over = |what: String| -> anyhow::Error {
        ToolError::new(
            EC::EResourceLimit,
            format!("more than {what} under {}", root.display()),
        )
        .into()
    };
    let mut files = BTreeMap::new();
    let mut entries = 0usize;
    let mut budget = MAX_PUBLISHED_BYTES;
    let mut directories = vec![root_entry.clone()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory)
            .with_context(|| format!("reading {}", directory.display()))?
        {
            let entry = entry.with_context(|| format!("reading {}", directory.display()))?;
            entries += 1;
            if entries > MAX_PUBLISHED_ENTRIES {
                return Err(over(format!("{MAX_PUBLISHED_ENTRIES} entries")));
            }
            let path = entry.path();
            let relative = path.strip_prefix(&root_entry)?;
            let name = relative
                .to_str()
                .ok_or_else(|| path_error(format!("{relative:?} is not a UTF-8 name")))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            let kind = entry
                .file_type()
                .with_context(|| format!("reading {}", path.display()))?;
            if kind.is_symlink() {
                return Err(path_error(format!("{name} is a symlink")));
            }
            if kind.is_dir() {
                directories.push(path);
                continue;
            }
            // Refused by what was listed, and again by what was opened.
            if !kind.is_file() {
                return Err(path_error(format!("{name} is not a regular file")));
            }
            let mut bytes = Vec::new();
            open_regular(&path, &name)?
                .take(budget + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading {}", path.display()))?;
            budget = budget
                .checked_sub(bytes.len() as u64)
                .ok_or_else(|| over(format!("{MAX_PUBLISHED_BYTES} bytes")))?;
            files.insert(name, bytes);
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;

    fn sha256_hex(bytes: &[u8]) -> String {
        ozpb_domain::sha256(bytes).to_hex()
    }

    /// A build as the toolkit lays one out, without a toolchain: the shell only moves bytes, and
    /// the toolkit's own tests hold what a consistent build is.
    fn synthetic() -> PublishedArtifact {
        let wasm = b"\0asm-synthetic".to_vec();
        let mut files = BTreeMap::from([
            ("policy.wasm".to_string(), wasm.clone()),
            ("source/src/lib.rs".to_string(), b"// lib\n".to_vec()),
        ]);
        let index: String = files
            .iter()
            .map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)))
            .collect();
        files.insert("SHA256SUMS".to_string(), index.into_bytes());
        PublishedArtifact {
            wasm_hash: sha256_hex(&wasm),
            manifest_hash: "ab".repeat(32),
            files,
            spec_rules: 1,
        }
    }

    fn code(error: anyhow::Error) -> EC {
        error
            .downcast_ref::<ToolError>()
            .unwrap_or_else(|| panic!("expected a ToolError, got {error:#}"))
            .code
    }

    #[test]
    fn the_commands_parse() {
        let cli = Cli::try_parse_from([
            "ozpb",
            "publish-artifact",
            "--spec",
            "spec.json",
            "--generated-dir",
            "generated",
            "--wasm",
            "generated/policy.wasm",
            "--manifest",
            "generated/build-manifest.json",
            "--out",
            "published",
        ])
        .expect("publish-artifact");
        assert!(matches!(cli.command, Command::PublishArtifact(_)));
        let cli = Cli::try_parse_from([
            "ozpb",
            "verify-published",
            "published/aa/bb",
            "--build-jobs",
            "2",
        ])
        .expect("verify-published");
        match cli.command {
            Command::VerifyPublished(args) => {
                assert_eq!(args.directory, Path::new("published/aa/bb"));
                assert_eq!(args.build.build_jobs, Some(2));
            }
            _ => panic!("expected verify-published"),
        }
    }

    #[test]
    fn a_build_is_written_whole_read_back_and_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let out = temp.path().join("published");
        let artifact = synthetic();
        assert_eq!(write_published(&out, &artifact).unwrap(), Written::New);
        let destination = out.join(&artifact.wasm_hash).join(&artifact.manifest_hash);
        assert_eq!(read_published_tree(&destination).unwrap(), artifact.files);
        // Nothing is left beside it.
        let beside: Vec<_> = std::fs::read_dir(out.join(&artifact.wasm_hash))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            beside,
            vec![std::ffi::OsString::from(&artifact.manifest_hash)]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o755,
                "a published build is readable by others"
            );
        }

        // The same build again is accepted and changes nothing.
        assert_eq!(
            write_published(&out, &artifact).unwrap(),
            Written::AlreadyPresent
        );

        // Other content under the same name is refused and left as it is.
        let index = destination.join("SHA256SUMS");
        std::fs::write(&index, b"edited\n").unwrap();
        assert_eq!(
            code(write_published(&out, &artifact).unwrap_err()),
            EC::EPublishConflict
        );
        assert_eq!(std::fs::read(&index).unwrap(), b"edited\n");
    }

    /// The command reads the two hashes from the path it is given and refuses a damaged build
    /// before anything is compiled.
    #[test]
    fn a_tampered_build_is_refused_before_anything_is_built() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = synthetic();
        write_published(temp.path(), &artifact).unwrap();
        let destination = temp
            .path()
            .join(&artifact.wasm_hash)
            .join(&artifact.manifest_hash);
        // No builder is ever reached: every case is refused while reading the directory.
        let unreachable = ozpb_toolkit::BuildConfig {
            stellar_binary: temp.path().join("no-such-stellar"),
            ..ozpb_toolkit::BuildConfig::default()
        };

        // Control: the untouched synthetic build has no spec, so it is refused for that, without
        // details. Each tampered case below must be refused for its own reason instead.
        let error = check_and_verify(&destination, &unreachable).unwrap_err();
        let error = error.downcast_ref::<ToolError>().unwrap();
        assert_eq!(error.code, EC::EPublishIndexMismatch);
        assert!(error.message.contains("policy-spec.json"), "{error}");
        assert!(error.details.is_empty(), "{error}");
        let details = |error: anyhow::Error| -> (EC, Vec<String>) {
            let error = error.downcast_ref::<ToolError>().unwrap();
            (error.code, error.details.clone())
        };

        let lib = destination.join("source/src/lib.rs");
        std::fs::write(&lib, b"// edited\n").unwrap();
        let (code_, found) = details(check_and_verify(&destination, &unreachable).unwrap_err());
        assert_eq!(code_, EC::EPublishIndexMismatch);
        assert!(
            found
                .iter()
                .any(|d| d.starts_with("source/src/lib.rs: SHA-256")),
            "{found:?}"
        );
        std::fs::write(&lib, b"// lib\n").unwrap();

        std::fs::write(destination.join("source/src/extra.rs"), b"// extra\n").unwrap();
        let (code_, found) = details(check_and_verify(&destination, &unreachable).unwrap_err());
        assert_eq!(code_, EC::EPublishIndexMismatch);
        assert_eq!(found, vec!["source/src/extra.rs: present but not listed"]);
        std::fs::remove_file(destination.join("source/src/extra.rs")).unwrap();

        std::fs::write(destination.join("policy.wasm"), b"\0asm-another").unwrap();
        assert_eq!(
            code(check_and_verify(&destination, &unreachable).unwrap_err()),
            EC::EPublishWasmMismatch
        );
    }

    /// The two hashes are the names the reviewer typed. A symlinked Wasm-hash directory would
    /// otherwise check, and reproduce, whatever build it points at under the other name.
    #[cfg(unix)]
    #[test]
    fn verify_published_reads_its_hashes_from_the_path_it_was_given() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = synthetic();
        write_published(temp.path(), &artifact).unwrap();
        let unreachable = ozpb_toolkit::BuildConfig {
            stellar_binary: temp.path().join("no-such-stellar"),
            ..ozpb_toolkit::BuildConfig::default()
        };

        let claimed = "cd".repeat(32);
        std::os::unix::fs::symlink(
            temp.path().join(&artifact.wasm_hash),
            temp.path().join(&claimed),
        )
        .unwrap();
        let through_link = temp.path().join(&claimed).join(&artifact.manifest_hash);
        assert_eq!(
            code(check_and_verify(&through_link, &unreachable).unwrap_err()),
            EC::EPublishPath
        );

        // A path that does not end in the two names is refused rather than resolved.
        let inside = temp
            .path()
            .join(&artifact.wasm_hash)
            .join(&artifact.manifest_hash)
            .join("source")
            .join("..");
        assert_eq!(
            code(check_and_verify(&inside, &unreachable).unwrap_err()),
            EC::EPublishPath
        );
    }

    #[cfg(unix)]
    #[test]
    fn publishing_through_a_symlinked_wasm_hash_directory_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = synthetic();
        let elsewhere = temp.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let out = temp.path().join("published");
        std::fs::create_dir(&out).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join(&artifact.wasm_hash)).unwrap();
        assert_eq!(
            code(write_published(&out, &artifact).unwrap_err()),
            EC::EPublishPath
        );
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_or_special_file_in_a_published_build_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = synthetic();
        write_published(temp.path(), &artifact).unwrap();
        let destination = temp
            .path()
            .join(&artifact.wasm_hash)
            .join(&artifact.manifest_hash);

        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&destination, &link).unwrap();
        assert_eq!(
            code(read_published_tree(&link).unwrap_err()),
            EC::EPublishPath
        );
        let mut with_separator = link.into_os_string();
        with_separator.push("/");
        assert_eq!(
            code(read_published_tree(Path::new(&with_separator)).unwrap_err()),
            EC::EPublishPath
        );

        let hosts = destination.join("source/src/hosts");
        std::os::unix::fs::symlink("/etc/hosts", &hosts).unwrap();
        assert_eq!(
            code(read_published_tree(&destination).unwrap_err()),
            EC::EPublishPath
        );
        std::fs::remove_file(&hosts).unwrap();

        // A FIFO would block a plain open for a writer that never comes.
        nix::unistd::mkfifo(
            &destination.join("source/src/fifo"),
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert_eq!(
            code(read_published_tree(&destination).unwrap_err()),
            EC::EPublishPath
        );
    }

    #[test]
    fn a_published_build_over_the_ceilings_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("many");
        std::fs::create_dir(&root).unwrap();
        for index in 0..=MAX_PUBLISHED_ENTRIES {
            std::fs::create_dir(root.join(format!("d{index}"))).unwrap();
        }
        assert_eq!(
            code(read_published_tree(&root).unwrap_err()),
            EC::EResourceLimit
        );

        let root = temp.path().join("large");
        std::fs::create_dir(&root).unwrap();
        let file = std::fs::File::create(root.join("large")).unwrap();
        file.set_len(MAX_PUBLISHED_BYTES + 1).unwrap();
        assert_eq!(
            code(read_published_tree(&root).unwrap_err()),
            EC::EResourceLimit
        );
    }

    /// The hermetic builder, which only a test can name: the CLI's flags cannot select it.
    fn stub() -> ozpb_toolkit::BuildConfig {
        ozpb_build_runner::BuildConfig {
            builder: ozpb_build_runner::Builder::Stub,
            ..ozpb_build_runner::BuildConfig::default()
        }
    }

    /// `verify-published` end to end, the builder aside: the committed example spec generated as
    /// `generate --out` writes it, published, read back and reproduced (exit 0); then forged
    /// consistently — an edited contract, its `source_hash`, the directory renamed to the new
    /// manifest hash and the index rewritten — which every check before the rebuild accepts and
    /// the rebuild does not reproduce (exit 3).
    #[test]
    fn verify_published_exits_zero_when_it_reproduces_and_three_for_a_consistent_forgery() {
        let temp = tempfile::tempdir().unwrap();
        let spec = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/examples/subscription-spec.json");
        let generated = ozpb_toolkit::generate_code_with_build_config(
            &ozpb_api_types::GenerateCodeInput {
                spec: crate::read_json(&spec).unwrap(),
                rule_index: 0,
            },
            &stub(),
        )
        .unwrap();
        let generated_dir = temp.path().join("generated");
        let wasm = crate::write_generation(&generated_dir, &generated).unwrap();
        let out = temp.path().join("published");
        publish(PublishArgs {
            spec,
            manifest: generated_dir.join("build-manifest.json"),
            generated_dir,
            wasm,
            out: out.clone(),
        })
        .unwrap();
        let build = out
            .join(&generated.wasm_hash)
            .join(&generated.build_manifest_hash);

        let report = check_and_verify(&build, &stub()).unwrap();
        assert!(report.verify.matches, "{:?}", report.verify);
        assert_eq!(exit_status(&report), 0);

        let contract = build.join("source/src/contract.rs");
        let mut text = std::fs::read_to_string(&contract).unwrap();
        text.push_str("\n// a backdoor would go here\n");
        std::fs::write(&contract, &text).unwrap();
        let mut files = generated.files.clone();
        files.insert("src/contract.rs".to_string(), text);
        let mut manifest = generated.build_manifest.clone();
        manifest["source_hash"] =
            serde_json::json!(ozpb_build_runner::source_hash(&files).unwrap().to_hex());
        let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        bytes.push(b'\n');
        std::fs::write(build.join("build-manifest.json"), &bytes).unwrap();
        let forged_hash = serde_json::from_value::<ozpb_build_runner::BuildManifest>(manifest)
            .unwrap()
            .hash()
            .unwrap()
            .to_hex();
        let forged = out.join(&generated.wasm_hash).join(&forged_hash);
        std::fs::rename(&build, &forged).unwrap();
        let mut tree = read_published_tree(&forged).unwrap();
        tree.remove("SHA256SUMS");
        let index: String = tree
            .iter()
            .map(|(name, bytes)| format!("{}  {name}\n", sha256_hex(bytes)))
            .collect();
        std::fs::write(forged.join("SHA256SUMS"), index).unwrap();

        let report = check_and_verify(&forged, &stub()).unwrap();
        assert!(!report.verify.matches, "{:?}", report.verify);
        assert!(report.verify.source_reproduction.starts_with("MISMATCH"));
        assert_eq!(exit_status(&report), EXIT_NOT_REPRODUCED);
    }

    #[test]
    fn a_generated_directory_holding_build_output_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let generated = temp.path().join("generated");
        std::fs::create_dir_all(generated.join("target")).unwrap();
        std::fs::write(generated.join("Cargo.toml"), b"[package]\n").unwrap();
        std::fs::write(generated.join("policy.wasm"), b"\0asm").unwrap();
        std::fs::write(generated.join("build-manifest.json"), b"{}").unwrap();
        std::fs::write(generated.join("spec.json"), b"{}").unwrap();
        std::fs::write(generated.join("target/out.bin"), [0xff, 0x00]).unwrap();
        let error = publish(PublishArgs {
            spec: generated.join("spec.json"),
            wasm: generated.join("policy.wasm"),
            manifest: generated.join("build-manifest.json"),
            generated_dir: generated,
            out: temp.path().join("published"),
        })
        .unwrap_err();
        assert_eq!(code(error), EC::EPublishManifestMismatch);
        assert!(!temp.path().join("published").exists());
    }
}
