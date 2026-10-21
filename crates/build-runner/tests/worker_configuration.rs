use ozpb_build_runner::BuildConfig;

#[test]
fn worker_launcher_is_an_explicit_absolute_operator_path() {
    for value in ["", "worker", "./worker", "../worker"] {
        let config = BuildConfig::from_env_with(|name| {
            (name == "OZPB_BUILD_WORKER_LAUNCHER").then(|| value.to_string())
        });
        assert!(
            config.is_err(),
            "relative or empty worker launcher was accepted"
        );
    }
}

#[test]
fn a_missing_worker_launcher_does_not_fall_back_to_local_compilation() {
    let config = BuildConfig::from_env_with(|name| {
        (name == "OZPB_BUILD_WORKER_LAUNCHER")
            .then(|| "/a-path-that-does-not-exist/ozpb-worker".to_string())
    });
    assert!(
        config.is_err(),
        "unavailable worker silently selected a local builder"
    );
}
