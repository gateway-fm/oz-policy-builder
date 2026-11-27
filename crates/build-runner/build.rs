//! Record the toolkit revision this binary is compiled from, for `BuildManifest.producer`.
//!
//! The value is what git said about this workspace when the crate was compiled: the commit, and
//! whether any toolkit input differed from it. It is empty when there is no checkout to ask — a
//! source archive — and the manifest then claims no commit rather than one the binary cannot know.
//! The container image's build has no checkout either; it passes the commit its context was cut
//! from as `OZPB_TOOLKIT_SOURCE`. Every input path and the git state that decides the answer are
//! watched, so a recorded value is never older than the sources the binary was built from.

#[path = "src/toolkit_source.rs"]
mod toolkit_source;

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"),
    )
    .join("../..");
    for input in toolkit_source::INPUTS {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    // Only paths that exist: cargo treats a missing one as always changed, which would rerun this
    // script on every build of a checkout without packed refs.
    for path in toolkit_source::git_state_paths(&root) {
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    println!(
        "cargo:rustc-env=OZPB_TOOLKIT_SOURCE={}",
        toolkit_source::probe(&root).unwrap_or_default()
    );
}
