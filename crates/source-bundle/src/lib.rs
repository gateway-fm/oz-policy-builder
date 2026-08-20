//! Imported-evidence acquisition adapter (architecture §4.1).
//!
//! A pure import yields `self_supplied` trust: hashing a user-supplied bundle proves
//! internal identity, not that the network accepted it. This adapter never mints any
//! stronger trust level — `ledger_verified` requires an inclusion-proof checker that
//! does not exist in Phase 1.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_recorder_core::EvidenceSnapshot;
use serde::{Deserialize, Serialize};

/// The self-contained import format for transactions outside RPC retention.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedBundle {
    pub network_passphrase: String,
    pub envelope_xdr_base64: String,
    pub result_meta_xdr_base64: Option<String>,
    /// Raw `TransactionResult` XDR. The recorder checks it against `successful`; without
    /// it the outcome is a bare claim and the import is labeled `incomplete` (recordable,
    /// but synthesis refuses it).
    #[serde(default)]
    pub result_xdr_base64: Option<String>,
    pub ledger: Option<u32>,
    pub created_at_unix: Option<i64>,
    /// Whether the supplier claims the transaction succeeded (verified against
    /// `result_xdr_base64` when recording).
    pub successful: bool,
}

/// The largest import document this adapter will parse.
///
/// An import carries no simulated authorizations or state changes, so all the evidence in one
/// counts against the recorder's [`MAX_TOTAL_EVIDENCE_BASE64_BYTES`] ceiling: a longer document
/// cannot describe evidence `record` would admit. Deciding that from `len()` keeps the refusal
/// O(1) instead of allocating a whole parsed document to reach the same answer — and it is the
/// only bound on `network_passphrase`, which the format does not otherwise limit and the
/// recorder only hashes.
///
/// The allowance above the evidence ceiling covers the format's own JSON syntax: seven field
/// names, their quoting and punctuation, the network passphrase, and the two integer anchors.
/// Those measure about 200 bytes, so 4 KiB is roughly twenty times what a maximal document
/// needs — chosen for headroom, and pinned from below by a test rather than left as a number
/// nothing checks. Over the HTTP transport the request body limit binds first, so the top of
/// this range is reachable only over stdio and in-process.
pub const MAX_IMPORT_JSON_BYTES: usize =
    ozpb_recorder_core::MAX_TOTAL_EVIDENCE_BASE64_BYTES + 4 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("E_IMPORT_PARSE: {0}")]
    Parse(String),
    /// Refused on length, before parsing. The prefix is `E_RESOURCE_LIMIT` rather than
    /// `E_IMPORT_PARSE` because that is the code the caller receives, and because the document
    /// is not malformed — it is too big to be admissible evidence, which is the failure the
    /// recorder reports under the same name.
    #[error("E_RESOURCE_LIMIT: import document is {bytes} bytes; maximum is {max}")]
    TooLarge { bytes: usize, max: usize },
}

/// Parse an import document (JSON) into a trust-labeled snapshot: `self_supplied` when the
/// transaction result XDR backs the claimed outcome, `incomplete` otherwise.
///
/// Parsing is not admission. The envelope and result meta named by the document are not
/// decoded here — [`ozpb_recorder_core::record`] is what decodes them, and what turns this
/// snapshot into an artifact. A successful return therefore means "a well-formed document of
/// admissible size, labeled for what its result proves", not "usable evidence".
pub fn import_json(json: &str) -> Result<EvidenceSnapshot, ImportError> {
    if json.len() > MAX_IMPORT_JSON_BYTES {
        return Err(ImportError::TooLarge {
            bytes: json.len(),
            max: MAX_IMPORT_JSON_BYTES,
        });
    }
    let bundle: ImportedBundle =
        serde_json::from_str(json).map_err(|e| ImportError::Parse(e.to_string()))?;
    Ok(snapshot_from(bundle))
}

/// Private on purpose: it converts without validating or bounding anything, so exporting it
/// would be a second way in that skips the document ceiling `import_json` applies. The format
/// itself stays public — the examples drift gate builds and serializes an `ImportedBundle` —
/// but constructing a snapshot from one is this module's business.
fn snapshot_from(bundle: ImportedBundle) -> EvidenceSnapshot {
    EvidenceSnapshot::from_import(
        bundle.network_passphrase,
        bundle.envelope_xdr_base64,
        bundle.result_meta_xdr_base64,
        bundle.result_xdr_base64,
        bundle.ledger,
        bundle.created_at_unix,
        bundle.successful,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_recorder_core::{fixtures as fx, record, Execution, RecordError, RecordOptions};

    /// Render a bundle as the document an importer is handed. Built through the format's own
    /// type rather than a string template, so a field the format gains cannot quietly drop
    /// out of these fixtures and leave every test green about a document nobody sends.
    fn document(bundle: &ImportedBundle) -> String {
        serde_json::to_string(bundle).expect("the import format must serialize")
    }

    /// Re-render a document with one key changed or removed, so the negative cases differ
    /// from the accepted one in exactly the field they are named after.
    fn document_with(
        bundle: &ImportedBundle,
        key: &str,
        value: Option<serde_json::Value>,
    ) -> String {
        let mut object: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&document(bundle)).expect("the rendered format must be an object");
        match value {
            Some(value) => object.insert(key.to_string(), value),
            None => object.remove(key),
        };
        serde_json::Value::Object(object).to_string()
    }

    /// Exactly the evidence of the recorder's own import fixture, expressed in the import
    /// format: a real envelope and result meta, and the transaction result that backs the
    /// claimed outcome. The base64 comes from recording that fixture because this crate does
    /// not depend on `stellar-xdr` — and a fixture that failed to record would fail here
    /// first, rather than being mistaken for a bug in the import path.
    ///
    /// The fixture's `contract_executables` have no field in this format. That absence is
    /// asserted below: it is the one thing an import must not invent.
    fn fixture_bundle(successful: bool) -> ImportedBundle {
        let raw = record(&fx::imported_snapshot(true), RecordOptions::default())
            .expect("the recorder's own import fixture must record")
            .raw;
        ImportedBundle {
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            envelope_xdr_base64: raw.envelope_xdr_base64,
            result_meta_xdr_base64: raw.result_meta_xdr_base64,
            result_xdr_base64: Some(fx::transaction_result_base64(successful)),
            ledger: Some(4_200_100),
            created_at_unix: Some(1_780_000_000),
            successful,
        }
    }

    #[test]
    fn imports_are_self_supplied_and_closed_schema() {
        let bundle = fixture_bundle(true);
        let snap = import_json(&document(&bundle)).unwrap();
        assert_eq!(snap.trust().as_str(), "self_supplied");

        let with_extra = document_with(&bundle, "trust", Some("rpc_reported".into()));
        assert!(
            import_json(&with_extra).is_err(),
            "an import must not be able to smuggle a trust level in"
        );
    }

    /// Parsing labels the evidence; recording is what turns it into an artifact. This is the
    /// composition both shells run, and the property the label alone cannot show: the
    /// recording carries the raw evidence the document supplied, the anchors it claimed, the
    /// authorization decoded from its own envelope — and re-derives from that raw evidence.
    #[test]
    fn a_backed_import_records_the_evidence_it_carried() {
        let bundle = fixture_bundle(true);
        let snapshot = import_json(&document(&bundle)).expect("the fixture document must parse");
        let recording = record(&snapshot, RecordOptions::default()).expect("and must record");

        assert_eq!(recording.trust.as_str(), "self_supplied");
        assert_eq!(recording.execution, Execution::ExecutedSuccess);
        assert_eq!(
            recording.raw.envelope_xdr_base64,
            bundle.envelope_xdr_base64
        );
        assert_eq!(
            recording.raw.result_meta_xdr_base64,
            bundle.result_meta_xdr_base64
        );
        assert_eq!(recording.ledger.map(|ledger| ledger.0), bundle.ledger);
        assert_eq!(recording.created_at_unix, bundle.created_at_unix);
        assert_eq!(
            recording.authorizations.len(),
            1,
            "the fixture envelope carries one address-credentialed authorization"
        );
        assert!(
            !recording.token_movements.is_empty(),
            "the fixture meta carries a transfer event"
        );
        assert!(
            recording.contract_executables.is_empty(),
            "the format cannot express an acquisition observation, so an import must not \
             produce one"
        );
        assert_eq!(
            recording.verify().expect("the recording must re-derive"),
            recording.recording_hash().expect("and must hash")
        );
    }

    /// Parsing is not admission: the envelope and the result meta are not looked at until
    /// `record`, so a document naming undecodable evidence imports "successfully" and is
    /// refused one call later. Pinned rather than left implicit — this is the failure a
    /// caller that stopped after `import_json` would never see.
    #[test]
    fn undecodable_envelope_or_meta_is_refused_at_the_recording_boundary() {
        let mut broken_envelope = fixture_bundle(true);
        broken_envelope.envelope_xdr_base64 = "AAAA".to_string();
        let snapshot =
            import_json(&document(&broken_envelope)).expect("the document itself is well-formed");
        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::EnvelopeParse(_))
        ));

        let mut broken_meta = fixture_bundle(true);
        broken_meta.result_meta_xdr_base64 = Some("AAAA".to_string());
        let snapshot = import_json(&document(&broken_meta)).expect("well-formed here too");
        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::MetaParse(_))
        ));
    }

    /// A result that cannot back the claim is no better than none: it parses, but the label
    /// stays `incomplete` rather than overstating what the bundle proves — and `record` names
    /// the disagreement instead of quietly accepting weaker evidence.
    #[test]
    fn imports_whose_result_cannot_back_the_claim_are_incomplete() {
        let mut unusable = fixture_bundle(true);
        unusable.result_xdr_base64 = Some("AAAA".to_string());
        let snapshot = import_json(&document(&unusable)).unwrap();
        assert_eq!(snapshot.trust().as_str(), "incomplete");
        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::ResultMismatch(_))
        ));

        let mut contradicting = fixture_bundle(true);
        contradicting.result_xdr_base64 = Some(fx::transaction_result_base64(false));
        let snapshot = import_json(&document(&contradicting)).unwrap();
        assert_eq!(snapshot.trust().as_str(), "incomplete");
        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::ResultMismatch(_))
        ));
    }

    /// A bundle that ships no transaction result asserts an outcome with nothing to check it
    /// against. It is still recordable — the evidence is viewable, and analysis of it is the
    /// reason the import path exists — but the artifact says `incomplete`, and `incomplete`
    /// does not permit synthesis.
    #[test]
    fn imports_without_a_transaction_result_are_incomplete() {
        let bundle = fixture_bundle(true);
        let json = document_with(&bundle, "result_xdr_base64", None);
        let snapshot = import_json(&json).unwrap();
        assert_eq!(snapshot.trust().as_str(), "incomplete");

        let recording = record(&snapshot, RecordOptions::default())
            .expect("missing evidence is recordable, not a parse failure");
        assert_eq!(recording.trust.as_str(), "incomplete");
        assert!(!recording.trust.allows_synthesis());
    }

    /// A failed execution is evidence, not a behavior example. The import path can carry one
    /// — with a result that backs the failure, so the label is earned — and recording it
    /// still requires saying so.
    #[test]
    fn a_failed_example_needs_the_failure_analysis_opt_in() {
        let bundle = fixture_bundle(false);
        let snapshot = import_json(&document(&bundle)).expect("a backed failure must parse");
        assert_eq!(
            snapshot.trust().as_str(),
            "self_supplied",
            "a result backing a claimed failure earns the label just as a success does"
        );
        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::TxFailed)
        ));

        let recording = record(
            &snapshot,
            RecordOptions {
                allow_failed: true,
                ..RecordOptions::default()
            },
        )
        .expect("failure analysis is opt-in, not forbidden");
        assert_eq!(recording.execution, Execution::ExecutedFailed);
    }

    /// The ceiling is enforced on the document, before it is parsed. Both sides of the
    /// boundary are asserted from one padded document, so the pair differs in a single byte —
    /// and the unpadded document is the control: it must be accepted, or "accepted at the
    /// ceiling" would prove nothing.
    #[test]
    fn a_document_over_the_ceiling_is_refused_before_parsing() {
        let bundle = fixture_bundle(true);
        assert!(import_json(&document(&bundle)).is_ok(), "control");

        // Padding goes in the passphrase: it is the one field the format gives no length of
        // its own, so without this ceiling the recorder would hash whatever arrived.
        let overhead = document(&bundle).len() - bundle.network_passphrase.len();
        let of_length = |bytes: usize| {
            let mut padded = bundle.clone();
            padded.network_passphrase = "A".repeat(bytes - overhead);
            let rendered = document(&padded);
            assert_eq!(rendered.len(), bytes, "padding must land on the byte");
            rendered
        };

        assert!(
            import_json(&of_length(MAX_IMPORT_JSON_BYTES)).is_ok(),
            "the ceiling itself is admissible"
        );
        assert!(matches!(
            import_json(&of_length(MAX_IMPORT_JSON_BYTES + 1)),
            Err(ImportError::TooLarge { bytes, max })
                if bytes == MAX_IMPORT_JSON_BYTES + 1 && max == MAX_IMPORT_JSON_BYTES
        ));
    }

    /// The allowance over the recorder's evidence ceiling is a judgement, so pin the thing it
    /// exists to cover: the format's own syntax around a document, measured rather than
    /// assumed.
    ///
    /// The boundary test above derives its padding from the constant, so it stays green for any
    /// allowance including zero. This one does not — it is what makes the chosen number
    /// non-vacuous, and it reports both figures when it fails so the margin is visible rather
    /// than inferred.
    #[test]
    fn the_allowance_over_the_evidence_ceiling_covers_the_formats_syntax() {
        let bundle = fixture_bundle(true);
        let evidence = bundle.envelope_xdr_base64.len()
            + bundle.result_meta_xdr_base64.as_deref().map_or(0, str::len)
            + bundle.result_xdr_base64.as_deref().map_or(0, str::len);
        let syntax = document(&bundle).len() - evidence;
        let allowance = MAX_IMPORT_JSON_BYTES - ozpb_recorder_core::MAX_TOTAL_EVIDENCE_BASE64_BYTES;
        assert!(
            allowance >= syntax,
            "the allowance ({allowance} bytes) must cover everything in a document that is not \
             evidence ({syntax} bytes: field names, punctuation, the passphrase and the anchors)"
        );
    }

    /// The format's required fields are required. Asserted against the same document with the
    /// field present, so the case cannot pass because the document was malformed some other
    /// way.
    #[test]
    fn a_missing_required_field_is_a_parse_failure() {
        let bundle = fixture_bundle(true);
        assert!(import_json(&document(&bundle)).is_ok(), "control");
        assert!(matches!(
            import_json(&document_with(&bundle, "successful", None)),
            Err(ImportError::Parse(_))
        ));
    }
}
