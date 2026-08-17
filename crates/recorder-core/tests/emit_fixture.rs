//! Emits the deterministic fixture's raw XDR as an importable evidence bundle
//! (demo / CI helper). No-op unless EMIT_BUNDLE_PATH is set.
use ozpb_recorder_core::{fixtures as fx, record, RecordOptions};

#[test]
fn emit_import_bundle() {
    let out = std::env::var("EMIT_BUNDLE_PATH").unwrap_or_default();
    if out.is_empty() {
        return;
    }
    let bundle = record(&fx::executed_snapshot(), RecordOptions::default()).unwrap();
    let import = serde_json::json!({
        "network_passphrase": "Test SDF Network ; September 2015",
        "envelope_xdr_base64": bundle.raw.envelope_xdr_base64,
        "result_meta_xdr_base64": bundle.raw.result_meta_xdr_base64,
        "ledger": 4200100,
        "created_at_unix": 1780000000i64,
        "successful": true
    });
    std::fs::write(&out, serde_json::to_string_pretty(&import).unwrap()).unwrap();
}
