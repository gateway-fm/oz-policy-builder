//! The channel a generated crate pins must be the channel this repository builds and tests with.
//!
//! Two copies of a compiler version exist by necessity: `rust-toolchain.toml` governs this
//! workspace, and `Pins::rust_channel` is emitted into every generated crate. If they drift, the
//! goldens, the differential suite and the reproducibility gates all run under one compiler while
//! the artifact a user builds runs under another — and since a wasm hash is compiler-dependent,
//! every hash this repository publishes would be unreproducible downstream while every gate here
//! stayed green. Duplication is acceptable; silent duplication is not.
//!
//! That the pin actually reaches the artifact is covered by the golden fixtures, which hold the
//! full emitted file set: `contracts/golden-transfer-policy/rust-toolchain.toml`.

/// The channel declared in the workspace toolchain file, parsed the same way
/// `scripts/verify-pinned-upstream.sh` parses it.
fn workspace_toolchain() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rust-toolchain.toml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

fn workspace_channel() -> String {
    workspace_toolchain()
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("channel")?
                .trim_start()
                .strip_prefix('=')
                .map(|value| value.trim().trim_matches('"').to_string())
        })
        .expect("rust-toolchain.toml must declare a channel")
}

#[test]
fn the_pinned_channel_matches_the_repository_toolchain() {
    assert_eq!(
        ozpb_codegen::Pins::default().rust_channel,
        workspace_channel(),
        "Pins::rust_channel and rust-toolchain.toml disagree; a generated crate would build under \
         a different compiler than the one every gate here uses"
    );
}

/// The values assigned to `key` in a toolchain file's inline-array form, ignoring comments.
///
/// Deliberately not a substring search: `contains("wasm32v1-none")` also matches the target named
/// in a comment, so the guard would stay green after `targets` itself was deleted — a gate that
/// passes for a reason other than the property it names.
fn declared_values(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter_map(|line| line.strip_prefix(key))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .flat_map(|value| {
            value
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
                .map(|item| item.trim().trim_matches('"').to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The workspace must declare the wasm target itself, not leave it to a separate
/// `rustup target add` step. A build outside CI — or inside a temporary directory, which is where
/// a generated crate normally lands — otherwise fails on a missing `wasm32v1-none` that nothing in
/// the repository asked for.
#[test]
fn the_workspace_declares_the_wasm_target() {
    let text = workspace_toolchain();
    let targets = declared_values(&text, "targets");
    assert!(
        targets.iter().any(|t| t == "wasm32v1-none"),
        "rust-toolchain.toml must declare targets = [\"wasm32v1-none\"]; parsed targets: \
         {targets:?}\n{text}"
    );
}

#[test]
fn the_target_check_ignores_comments() {
    // Guards the guard: the parser must not be satisfied by a mention in a comment.
    assert!(declared_values("# targets = [\"wasm32v1-none\"]\n", "targets").is_empty());
    assert_eq!(
        declared_values(
            "[toolchain]\nchannel = \"1.91.1\"  # not wasm32v1-none\ntargets = [\"wasm32v1-none\"]\n",
            "targets"
        ),
        vec!["wasm32v1-none".to_string()]
    );
}
