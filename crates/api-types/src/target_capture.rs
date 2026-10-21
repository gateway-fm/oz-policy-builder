//! Read-only capture of one native Stellar Asset Contract transfer's target state.
//!
//! The output is the execution runtime's own input: the `capture` of a `CapturedTargetJob`
//! that the native worker's captured-target modes read. It is carried as the domain type itself
//! rather than a wire copy, so the bytes a caller hands the worker cannot drift from what the
//! worker parses; only its schema is described here.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Capture the target state for one unsigned native SAC
/// `transfer(contract account, existing G recipient, amount)` envelope through an
/// operator-configured RPC source.
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureTargetInput {
    /// Hex network ID; the named source must be configured for exactly this network.
    pub network_id: String,
    /// Name of an operator-configured RPC source. The request never carries a URL.
    pub rpc_source: String,
    /// Unsigned transaction envelope, canonical base64 XDR, with no authorization entries.
    /// Confidential input (§6.5): it reaches the configured RPC endpoint (and, over MCP, the
    /// conversation and server that carry the request), and is never echoed in a result, an
    /// error or this type's `Debug` output. The result repeats its call, so it is confidential
    /// too.
    pub envelope_xdr_base64: String,
}

/// The envelope is confidential, so a debug print of a request shows only its length.
impl std::fmt::Debug for CaptureTargetInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureTargetInput")
            .field("network_id", &self.network_id)
            .field("rpc_source", &self.rpc_source)
            .field(
                "envelope_xdr_base64",
                &format_args!("<withheld: {} bytes>", self.envelope_xdr_base64.len()),
            )
            .finish()
    }
}

/// Exactly `ozpb_domain::TargetCapture`: endpoint-reported (`rpc_reported`) ledger header,
/// state-archival configuration, the call, the record-mode authorization used only to discover
/// it, the account's executed Wasm hash, and the footprint entries. Not an inclusion proof.
/// Confidential like the envelope: the call names the account, recipient and amount.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CaptureTargetOutput(pub ozpb_domain::TargetCapture);

/// The schema is the described object itself, not a reference to it: an MCP output schema's
/// root must be an object.
impl JsonSchema for CaptureTargetOutput {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TargetCapture".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        TargetCaptureSchema::json_schema(generator)
    }
}

/// Schema of `ozpb_domain::TargetCapture`, which has no schema of its own. Never constructed;
/// a test holds its properties to the domain type's serialized fields.
#[derive(JsonSchema)]
#[schemars(rename = "TargetCapture", deny_unknown_fields)]
#[allow(dead_code)]
struct TargetCaptureSchema {
    /// Capture format version; currently 1.
    schema: u32,
    /// Always `rpc_reported`: an endpoint's answer, not an inclusion proof.
    provenance: String,
    /// Hex network ID of the source network.
    network_id: String,
    /// The ledger the simulation and the entry read both reported.
    observed_ledger: u32,
    /// Canonical `LedgerHeaderHistoryEntry` XDR for `observed_ledger`, self-consistent only.
    header_xdr: String,
    /// The network's state-archival configuration entry at `observed_ledger`.
    state_archival: TargetEntrySchema,
    /// Canonical `InvokeContractArgs` XDR of the captured call, with no authorization.
    invocation_xdr: String,
    /// Record-mode authorization entry XDR. Discovery only; never evidence of enforcement.
    recording_auth_xdr: String,
    /// Lowercase hex Wasm hash the account instance executed at `observed_ledger`.
    account_code_hash: String,
    /// Read-only footprint keys (canonical `LedgerKey` XDR), excluding the account's own.
    read_only_keys: Vec<String>,
    /// Read-write footprint keys (canonical `LedgerKey` XDR), excluding the account's own.
    read_write_keys: Vec<String>,
    /// One entry per footprint key.
    entries: Vec<TargetEntrySchema>,
}

/// Schema of `ozpb_domain::TargetEntry`.
#[derive(JsonSchema)]
#[schemars(rename = "TargetEntry", deny_unknown_fields)]
#[allow(dead_code)]
struct TargetEntrySchema {
    /// Canonical `LedgerKey` XDR.
    key_xdr: String,
    /// Canonical `LedgerEntryData` XDR; the outer `LedgerEntry` extension is not captured.
    data_xdr: String,
    last_modified_ledger: u32,
    /// Present for contract data and code.
    live_until_ledger: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_domain::{TargetCapture, TargetEntry};

    fn entry(live_until_ledger: Option<u32>) -> TargetEntry {
        TargetEntry {
            key_xdr: "key".into(),
            data_xdr: "data".into(),
            last_modified_ledger: 7,
            live_until_ledger,
        }
    }

    fn capture() -> TargetCapture {
        // Exhaustive on purpose: a field added to the domain type stops this compiling until the
        // schema below is updated with it.
        let TargetCapture {
            schema,
            provenance,
            network_id,
            observed_ledger,
            header_xdr,
            state_archival,
            invocation_xdr,
            recording_auth_xdr,
            account_code_hash,
            read_only_keys,
            read_write_keys,
            entries,
        } = TargetCapture {
            schema: 1,
            provenance: "rpc_reported".into(),
            network_id: "00".repeat(32),
            observed_ledger: 9,
            header_xdr: "header".into(),
            state_archival: entry(None),
            invocation_xdr: "call".into(),
            recording_auth_xdr: "auth".into(),
            account_code_hash: "11".repeat(32),
            read_only_keys: vec!["ro".into()],
            read_write_keys: vec!["rw".into()],
            entries: vec![entry(Some(100))],
        };
        let TargetEntry {
            key_xdr: _,
            data_xdr: _,
            last_modified_ledger: _,
            live_until_ledger: _,
        } = &state_archival;
        TargetCapture {
            schema,
            provenance,
            network_id,
            observed_ledger,
            header_xdr,
            state_archival,
            invocation_xdr,
            recording_auth_xdr,
            account_code_hash,
            read_only_keys,
            read_write_keys,
            entries,
        }
    }

    fn keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn the_output_is_byte_for_byte_the_domain_capture() {
        let domain = capture();
        let wire = serde_json::to_string(&CaptureTargetOutput(domain.clone())).unwrap();
        assert_eq!(wire, serde_json::to_string(&domain).unwrap());
        let back: CaptureTargetOutput = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.0, domain);
    }

    #[test]
    fn the_output_schema_describes_exactly_the_domain_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(CaptureTargetOutput)).unwrap();
        let serialized = serde_json::to_value(capture()).unwrap();
        assert_eq!(schema["type"], "object", "{schema}");
        let entry = schema["$defs"]["TargetEntry"].clone();
        conforms(&schema, &serialized, &[]);
        conforms(
            &entry,
            &serialized["state_archival"],
            &["live_until_ledger"],
        );
        conforms(&entry, &serialized["entries"][0], &["live_until_ledger"]);
    }

    /// `value`'s fields are exactly `schema`'s properties, each of the declared JSON type, all
    /// required except `optional`, and nothing else admitted. A client validating
    /// `structuredContent` against the schema would accept the domain type's output.
    fn conforms(schema: &serde_json::Value, value: &serde_json::Value, optional: &[&str]) {
        assert_eq!(keys(&schema["properties"]), keys(value), "{schema}");
        assert_eq!(schema["additionalProperties"], false, "{schema}");
        let mut required: Vec<String> = schema["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .filter_map(|field| field.as_str().map(str::to_string))
            .collect();
        required.sort();
        let expected: Vec<String> = keys(value)
            .into_iter()
            .filter(|key| !optional.contains(&key.as_str()))
            .collect();
        assert_eq!(required, expected, "{schema}");
        for (field, field_value) in value.as_object().expect("an object") {
            let property = &schema["properties"][field];
            let declared = match &property["type"] {
                serde_json::Value::String(kind) => vec![kind.as_str()],
                serde_json::Value::Array(kinds) => {
                    kinds.iter().filter_map(serde_json::Value::as_str).collect()
                }
                _ => {
                    assert!(property["$ref"].is_string(), "{field}: {property}");
                    vec!["object"]
                }
            };
            let actual = match field_value {
                serde_json::Value::String(_) => "string",
                serde_json::Value::Number(_) => "integer",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
            };
            assert!(declared.contains(&actual), "{field}: {property}");
        }
    }

    #[test]
    fn a_request_never_prints_its_envelope() {
        let input = CaptureTargetInput {
            network_id: "00".repeat(32),
            rpc_source: "testnet".into(),
            envelope_xdr_base64: "CONFIDENTIAL-ENVELOPE".into(),
        };
        let printed = format!("{input:?} {input:#?}");
        assert!(!printed.contains("CONFIDENTIAL-ENVELOPE"), "{printed}");
        assert!(printed.contains("withheld: 21 bytes"), "{printed}");
        crate::test_support::no_build_settings_on_the_wire(
            "CaptureTargetInput",
            schemars::schema_for!(CaptureTargetInput),
        );
    }

    #[test]
    fn a_request_names_a_source_and_never_a_url() {
        let request = serde_json::json!({
            "network_id": "00",
            "rpc_source": "testnet",
            "envelope_xdr_base64": "AAAA",
        });
        assert!(serde_json::from_value::<CaptureTargetInput>(request.clone()).is_ok());
        let mut with_url = request;
        with_url["rpc_url"] = "https://rpc.example".into();
        assert!(serde_json::from_value::<CaptureTargetInput>(with_url).is_err());
    }
}
