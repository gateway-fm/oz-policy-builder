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

/// Room for the envelope at its bound even when every character is written as a two-byte JSON
/// escape, plus the request's other fields. Over it, the file is refused before it is parsed.
const MAX_REQUEST_BYTES: usize = 2 * MAX_XDR_BASE64_BYTES + 64 * 1024;

pub fn run(request: &Path, rpc_sources: &Path) -> Result<()> {
    let input = read_request(request)?;
    let sources = std::fs::read_to_string(rpc_sources)
        .with_context(|| format!("reading {}", rpc_sources.display()))?;
    let sources = ozpb_toolkit::rpc_sources_from_json(&sources)?;
    let source = ozpb_toolkit::resolve_rpc_source(&sources, &input.rpc_source, &input.network_id)?;
    let capture = capture_native_target(
        &HttpTransport::new(source.rpc_url.clone()),
        &source.network_passphrase,
        &input.envelope_xdr_base64,
    );
    print_json(&ozpb_toolkit::capture_target_output(capture)?)
}

/// The request, read under a bound. A parse error reports where, never what: the JSON parser's
/// own message can quote the document, and the document is the envelope.
fn read_request(path: &Path) -> Result<CaptureTargetInput> {
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
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "parsing {}: not a capture-target request ({:?} error at line {} column {}; detail \
             withheld because the request carries a confidential envelope)",
            path.display(),
            error.classify(),
            error.line(),
            error.column()
        )
    })
}
