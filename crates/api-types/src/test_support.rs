//! Assertions shared by the test modules of this crate.
//!
//! `no_build_settings_on_the_wire` is here rather than in either test module because it states a
//! property of *every* input DTO, and the DTOs are split across two files by milestone. Written
//! once and called from both, the property keeps holding for whichever DTOs remain; written as
//! one test over a list of DTOs from both milestones, removing the post-MVP module would have
//! meant editing an assertion, which is how a property quietly stops being checked.

/// Assert that `schema`'s properties expose no operator-side build setting.
///
/// Build settings stay operator-side: a request-supplied timeout is resource exhaustion and a
/// request-supplied builder path is arbitrary execution. These inputs also lack
/// `deny_unknown_fields`, so a build field arriving on the wire would be silently ignored by an
/// older server — failing *open*.
pub(crate) fn no_build_settings_on_the_wire(dto: &str, schema: schemars::Schema) {
    let properties: Vec<String> = serde_json::to_value(schema)
        .ok()
        .and_then(|value| value.get("properties").cloned())
        .and_then(|props| props.as_object().cloned())
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default();

    assert!(
        !properties.is_empty(),
        "{dto} produced no schema properties; the check would pass vacuously"
    );
    for property in &properties {
        for forbidden in [
            "timeout",
            "builder",
            "stellar_binary",
            "target_dir",
            "cache_dir",
            "build_jobs",
            "cargo_offline",
        ] {
            assert!(
                !property.contains(forbidden),
                "{dto} exposes build setting '{property}' on the wire"
            );
        }
    }
}
