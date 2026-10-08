//! CLI shell for a state-dependent RPC simulation of one exact transaction.

use anyhow::{Context, Result};
use ozpb_source_rpc::{preflight_transaction, HttpTransport};

use crate::print_json;
use std::io::Read;
use std::path::PathBuf;

pub fn run(rpc_url: String, network_passphrase: String, envelope_file: PathBuf) -> Result<()> {
    let envelope_xdr_base64 = read_envelope(&envelope_file)?;
    let transport = HttpTransport::new(rpc_url);
    let observation = preflight_transaction(&transport, &network_passphrase, &envelope_xdr_base64)?;
    print_json(&ozpb_toolkit::preflight_transaction_output(observation))
}

fn read_envelope(path: &PathBuf) -> Result<String> {
    // Stop at the adapter's envelope bound before loading caller-controlled input, allowing
    // one trailing LF or CRLF from a text file; remove it before parsing the exact XDR. An
    // envelope over the bound that still fits this allowance is refused by the adapter with
    // the same code.
    let maximum = ozpb_source_rpc::MAX_XDR_BASE64_BYTES + 2;
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > maximum {
        anyhow::bail!("E_RESOURCE_LIMIT: preflight envelope file exceeds {maximum} bytes");
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        anyhow::anyhow!(
            "E_ENVELOPE_PARSE: {} is not UTF-8 base64 text",
            path.display()
        )
    })?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    if text.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        anyhow::bail!("E_ENVELOPE_PARSE: preflight envelope file has extra line breaks");
    }
    Ok(text.to_string())
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
        assert!(error.starts_with("E_ENVELOPE_PARSE: "), "{error}");
        assert!(error.contains("extra line breaks"), "{error}");
        assert!(!error.contains("AAAA"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_text_is_an_envelope_parse_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("envelope.xdr.base64");
        std::fs::write(&path, [0xff, 0xfe, b'A']).expect("write binary envelope");
        let error = read_envelope(&path).unwrap_err().to_string();
        assert!(error.starts_with("E_ENVELOPE_PARSE: "), "{error}");
    }
}
