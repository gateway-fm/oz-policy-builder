//! Which toolkit revision a binary was compiled from, as git reports it about this workspace.
//!
//! Shared by `build.rs`, which records the answer at compile time for the BuildManifest's
//! `producer.toolkit_source`, and by this crate's tests, which hold the recording to the checkout.
//! Nothing here runs when a manifest is written: by then the binary can only repeat what its own
//! build saw, so that is all it is allowed to say.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The workspace paths a toolkit binary is compiled from, relative to the workspace root: every
/// crate, the manifests and lockfile, the toolchain pin, and the generated-crate lockfile the
/// emitter embeds. Whether the checkout is dirty is asked about these alone, so an edited document
/// does not mark a binary dirty, and a change to any of them reruns the build script.
pub(crate) const INPUTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "contracts/golden-transfer-policy/Cargo.lock",
    "crates",
    "rust-toolchain.toml",
];

/// Run git against `root` and return its standard output, or `None` if it cannot answer.
///
/// `--no-optional-locks` keeps `status` from refreshing the index. The build script watches the
/// index for changes, so a probe that rewrote it would invalidate its own result on every build.
fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// `<commit>` or `<commit>+dirty` for the checkout at `root`, or `None` when no commit can be
/// claimed: no git, no repository, or a repository whose top level is not `root` — a toolkit
/// unpacked inside some other checkout must not claim that checkout's commit.
pub(crate) fn probe(root: &Path) -> Option<String> {
    let toplevel = git(root, &["rev-parse", "--show-toplevel"])?;
    if Path::new(toplevel.trim_end()).canonicalize().ok()? != root.canonicalize().ok()? {
        return None;
    }
    let commit = git(root, &["rev-parse", "--verify", "HEAD^{commit}"])?
        .trim_end()
        .to_string();
    let mut status = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    status.extend_from_slice(INPUTS);
    let changes = git(root, &status)?;
    Some(if changes.is_empty() {
        commit
    } else {
        format!("{commit}+dirty")
    })
}

/// The git files whose change can move the answer without touching [`INPUTS`]: `HEAD`, the branch
/// it names, packed refs, the index, and `HEAD`'s reflog. The reflog is what catches a move of a
/// packed branch through a loose ref written later (`reset --soft`, `update-ref`), which none of
/// the others shows. Worktree-aware, because `--git-path` resolves each the way git itself does.
/// Empty when there is no repository.
pub(crate) fn git_state_paths(root: &Path) -> Vec<PathBuf> {
    let mut names = vec![
        "HEAD".to_string(),
        "index".to_string(),
        "packed-refs".to_string(),
        "logs/HEAD".to_string(),
    ];
    if let Some(branch) = git(root, &["symbolic-ref", "-q", "HEAD"]) {
        names.push(branch.trim_end().to_string());
    }
    names
        .iter()
        .filter_map(|name| git(root, &["rev-parse", "--git-path", name]))
        .map(|path| root.join(path.trim_end()))
        .collect()
}
