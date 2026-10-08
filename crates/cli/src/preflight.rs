//! CLI shell for a state-dependent RPC simulation of one exact transaction.

use anyhow::{Context, Result};
use ozpb_api_types::{PreflightTransactionOutcome, PreflightTransactionOutput};
use ozpb_source_rpc::{
    preflight_transaction, HttpTransport, PreflightObservation, PreflightOutcome,
};

use crate::print_json;
use std::io::Read;
use std::path::PathBuf;

pub fn run(rpc_url: String, network_passphrase: String, envelope_file: PathBuf) -> Result<()> {
    let envelope_xdr_base64 = read_envelope(&envelope_file)?;
    let transport = HttpTransport::new(rpc_url);
    let observation = preflight_transaction(&transport, &network_passphrase, &envelope_xdr_base64)?;
    print_json(&to_wire(observation))
}

fn read_envelope(path: &PathBuf) -> Result<String> {
    // Match the RPC decoder's XDR bound before loading caller-controlled input. Allow
    // one trailing LF or CRLF from a text file; remove it before parsing the exact XDR.
    let maximum = ozpb_source_rpc::xdr_limits().len.div_ceil(3) * 4 + 2;
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > maximum {
        anyhow::bail!("E_RESOURCE_LIMIT: preflight envelope file exceeds {maximum} bytes");
    }
    let text =
        String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if text.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        anyhow::bail!("E_RPC: preflight envelope file has extra line breaks");
    }
    Ok(text.to_string())
}

fn to_wire(observation: PreflightObservation) -> PreflightTransactionOutput {
    PreflightTransactionOutput {
        envelope_xdr_sha256: observation.envelope_xdr_sha256,
        network_id: observation.network_id,
        reported_ledger: observation.reported_ledger,
        outcome: match observation.outcome {
            PreflightOutcome::SimulatedSuccess => PreflightTransactionOutcome::SimulatedSuccess,
            PreflightOutcome::SimulationFailed => PreflightTransactionOutcome::SimulationFailed,
            PreflightOutcome::RestorationRequired => {
                PreflightTransactionOutcome::RestorationRequired
            }
        },
        auth_mode: observation.auth_mode,
        evidence_trust: observation.evidence_trust,
        state_dependent: observation.state_dependent,
        writes_committed: observation.writes_committed,
    }
}

#[cfg(test)]
mod tests {
    use super::read_envelope;

    #[test]
    fn removes_only_one_terminal_line_break_from_an_envelope_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("envelope.xdr.base64");
        std::fs::write(&path, "AAAA\r\n").expect("write CRLF envelope");
        assert_eq!(read_envelope(&path).unwrap(), "AAAA");

        std::fs::write(&path, "AAAA\n\n").expect("write extra newline envelope");
        let error = read_envelope(&path).unwrap_err().to_string();
        assert!(error.contains("extra line breaks"), "{error}");
        assert!(!error.contains("AAAA"), "{error}");
    }
}
