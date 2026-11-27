//! Where `ozpb generate` compiles: never under a directory another local user can add to.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn executable(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The shared `/tmp` of a multi-user Linux host, reproduced: a world-writable temporary directory
/// where another user has planted `.cargo/config.toml` naming a compiler wrapper. Cargo reads that
/// file from every parent of the directory it runs in, so the wrapper would run as the caller.
/// The build is refused before the builder starts, and nothing planted runs.
#[test]
fn a_build_is_refused_before_anything_runs_when_its_temporary_directory_is_shared() {
    let base = tempfile::Builder::new()
        .prefix("ozpb-shared-tmp-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let shared = base.path().join("tmp");
    std::fs::create_dir_all(shared.join(".cargo")).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let planted = base.path().join("planted-ran");
    executable(
        &base.path().join("wrapper"),
        &format!("touch {}; exit 1", planted.display()),
    );
    std::fs::write(
        shared.join(".cargo/config.toml"),
        format!(
            "[build]\nrustc-wrapper = \"{}\"\n",
            base.path().join("wrapper").display()
        ),
    )
    .unwrap();
    let builder_ran = base.path().join("builder-ran");
    let builder = base.path().join("stellar");
    executable(
        &builder,
        &format!("touch {}; exit 1", builder_ran.display()),
    );
    let cache = base.path().join("cache");

    let spec =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples/subscription-spec.json");
    let output = Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .args(["generate", "--spec"])
        .arg(&spec)
        .arg("--stellar-binary")
        .arg(&builder)
        .arg("--build-cache-dir")
        .arg(&cache)
        .env("TMPDIR", &shared)
        // No user cache to stand in for it either.
        .env_remove("HOME")
        .env_remove("XDG_CACHE_HOME")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("E_BUILD_UNAVAILABLE"), "{stderr}");
    assert!(stderr.contains("TMPDIR"), "{stderr}");
    assert!(!builder_ran.exists(), "the builder started");
    assert!(!planted.exists(), "the planted compiler wrapper ran");
}
