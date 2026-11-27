//! `ozpb publish-artifact` and `ozpb verify-published` through the binary: the exit statuses a
//! reviewer's script reads, and the round trip from `ozpb generate` with the real toolchain.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn ozpb(args: &[&OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .args(args)
        .output()
        .expect("run CLI")
}

/// A refusal exits 1 with its code leading the error, before any build is attempted: the
/// configured `stellar` does not exist, and the refusal is still the directory's.
#[test]
fn a_refused_build_exits_one_with_its_code() {
    let temp = tempfile::tempdir().unwrap();
    let build = temp.path().join("0".repeat(64)).join("ab".repeat(32));
    std::fs::create_dir_all(&build).unwrap();
    std::fs::write(build.join("policy.wasm"), b"\0asm-not-the-named-one").unwrap();
    let output = ozpb(&[
        "verify-published".as_ref(),
        build.as_os_str(),
        "--stellar-binary".as_ref(),
        temp.path().join("no-such-stellar").as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.starts_with("Error: E_PUBLISH_WASM_MISMATCH: "),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "a refusal prints no report");
}

/// Generate the committed example spec with the pinned toolchain, publish it twice, and
/// reproduce the published build. Set `OZPB_BUILD_CACHE_DIR` to a warm cache to keep it short.
#[test]
#[ignore = "requires the pinned Rust target, stellar-cli, and cached contract dependencies"]
fn a_generated_policy_publishes_and_reproduces_from_its_published_build() {
    let temp = tempfile::tempdir().unwrap();
    let spec = repo().join("docs/examples/subscription-spec.json");
    let generated = temp.path().join("generated");
    let out = temp.path().join("published");
    let generate = ozpb(&[
        "generate".as_ref(),
        "--spec".as_ref(),
        spec.as_os_str(),
        "--rule".as_ref(),
        "0".as_ref(),
        "--out".as_ref(),
        generated.as_os_str(),
    ]);
    assert!(generate.status.success(), "{generate:?}");
    let wasm: Vec<PathBuf> = std::fs::read_dir(&generated)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension() == Some(OsStr::new("wasm")))
        .collect();
    assert_eq!(wasm.len(), 1, "{wasm:?}");
    let manifest = generated.join("build-manifest.json");

    let publish = || {
        let output = ozpb(&[
            "publish-artifact".as_ref(),
            "--spec".as_ref(),
            spec.as_os_str(),
            "--generated-dir".as_ref(),
            generated.as_os_str(),
            "--wasm".as_ref(),
            wasm[0].as_os_str(),
            "--manifest".as_ref(),
            manifest.as_os_str(),
            "--out".as_ref(),
            out.as_os_str(),
        ]);
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let first = publish();
    assert_eq!(first["already_published"], false, "{first}");
    let second = publish();
    assert_eq!(second["already_published"], true, "{second}");
    assert_eq!(first["directory"], second["directory"]);
    let wasm_hash = first["wasm_hash"].as_str().unwrap();
    assert_eq!(
        wasm_hash,
        ozpb_domain::sha256(&std::fs::read(&wasm[0]).unwrap()).to_hex()
    );

    let build = PathBuf::from(first["directory"].as_str().unwrap());
    let verified = ozpb(&["verify-published".as_ref(), build.as_os_str()]);
    assert_eq!(verified.status.code(), Some(0), "{verified:?}");
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["wasm_hash"], wasm_hash);
    assert_eq!(report["verify"]["matches"], true, "{report}");
    assert_eq!(
        report["verify"]["wasm_reproduction"], "reproduced: Wasm and BuildManifest are identical",
        "{report}"
    );
}
