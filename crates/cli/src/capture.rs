//! CLI shell for capturing one native SAC transfer's target state through an operator source.
//!
//! The endpoint comes from the operator's RPC source file, never from the request: the request
//! names a source and carries the unsigned envelope, which is confidential and is read from a
//! file so it stays out of process arguments. Nothing here echoes it.

use anyhow::{Context, Result};
use ozpb_api_types::CaptureTargetInput;
use ozpb_source_rpc::{capture_native_target, HttpTransport, MAX_XDR_BASE64_BYTES};
use std::io::Read;
use std::path::Path;

use crate::print_json;

/// Room for the envelope at its bound even when a JSON writer escapes every `/` as `\/`, the
/// only two-byte escape a base64 character can take, plus the request's other fields. A request
/// spelling base64 characters as six-byte `\uXXXX` escapes can exceed it and is refused as
/// oversized. Over it, the file is refused before it is parsed.
const MAX_REQUEST_BYTES: usize = 2 * MAX_XDR_BASE64_BYTES + 64 * 1024;

pub fn run(request: &Path, rpc_sources: &Path) -> Result<()> {
    let input = read_request(request)?;
    let sources = std::fs::read_to_string(rpc_sources)
        .with_context(|| format!("reading {}", rpc_sources.display()))?;
    let sources = ozpb_toolkit::rpc_sources_from_json(&sources)?;
    let source =
        ozpb_toolkit::resolve_capture_rpc_source(&sources, &input.rpc_source, &input.network_id)?;
    let capture = capture_native_target(
        &HttpTransport::new(source.rpc_url.clone()),
        &source.network_passphrase,
        &input.envelope_xdr_base64,
    );
    // The refusal's message already leads with its code, as the preflight command prints it.
    let output = ozpb_toolkit::capture_target_output(capture)
        .map_err(|error| anyhow::Error::msg(error.message))?;
    print_json(&output)
}

/// The request, read under a bound. A parse error reports where, never what: the JSON parser's
/// own message can quote the document, and the document is the envelope.
pub(crate) fn read_request(path: &Path) -> Result<CaptureTargetInput> {
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        anyhow::bail!(
            "E_RESOURCE_LIMIT: capture-target request {} exceeds {MAX_REQUEST_BYTES} bytes",
            path.display()
        );
    }
    // Validate syntax separately, without retaining a Value (which would erase duplicate keys).
    // Typed deserialization then keeps strict fields while withholding all shape-error details.
    serde_json::from_slice::<serde::de::IgnoredAny>(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "parsing {}: not a capture-target request ({:?} error at line {} column {}; detail \
             withheld because the request carries a confidential envelope)",
            path.display(),
            error.classify(),
            error.line(),
            error.column()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        anyhow::anyhow!("parsing {}: not a capture-target request (invalid shape; confidential details withheld)", path.display())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_file(envelope_json: &str) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("temporary request");
        std::fs::write(
            file.path(),
            format!(
                "{{\"network_id\": \"00\", \"rpc_source\": \"testnet\", \
                 \"envelope_xdr_base64\": \"{envelope_json}\"}}"
            ),
        )
        .expect("write request");
        file
    }

    #[test]
    fn an_envelope_at_its_bound_fits_even_with_every_slash_escaped() {
        let file = request_file(&"\\/".repeat(MAX_XDR_BASE64_BYTES));
        let input = read_request(file.path()).expect("within the request bound");
        assert_eq!(input.envelope_xdr_base64.len(), MAX_XDR_BASE64_BYTES);
        assert!(input.envelope_xdr_base64.bytes().all(|byte| byte == b'/'));
    }

    #[test]
    fn a_request_over_the_bound_is_refused_before_it_is_parsed() {
        let file = tempfile::NamedTempFile::new().expect("temporary request");
        // Not JSON at all: a parse would fail differently.
        std::fs::write(file.path(), vec![b'x'; MAX_REQUEST_BYTES + 1]).expect("write request");
        let error = read_request(file.path()).unwrap_err().to_string();
        assert!(error.starts_with("E_RESOURCE_LIMIT: "), "{error}");
        // Control: at the bound the file is parsed, and refused as JSON instead.
        std::fs::write(file.path(), vec![b'x'; MAX_REQUEST_BYTES]).expect("write request");
        let error = read_request(file.path()).unwrap_err().to_string();
        assert!(error.contains("not a capture-target request"), "{error}");
    }
}
