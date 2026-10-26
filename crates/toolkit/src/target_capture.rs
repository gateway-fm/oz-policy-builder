//! The wire form of one native target capture. Acquisition is the shell's job: the CLI and the
//! MCP server each resolve the operator's RPC source, run
//! `ozpb_source_rpc::capture_native_target` through their own transport and hand the result
//! here, so both report the same capture and refuse with the same codes.
//!
//! The capture is the execution runtime's input, unchanged. Errors carry no endpoint text and
//! never the envelope: `capture_native_target` withholds endpoint-controlled detail, and its
//! own refusals are fixed descriptions.

use ozpb_api_types::{CaptureTargetOutput, ErrorCode as EC, ToolError};
use ozpb_domain::TargetCapture;
use ozpb_source_rpc::RpcError;

/// Resolve the configured source without echoing any request field. Even a source name can
/// carry a copied confidential envelope; keep the refusal category but discard its detail.
pub fn resolve_capture_rpc_source<'a>(
    sources: &'a std::collections::BTreeMap<String, crate::RpcSource>,
    name: &str,
    network_id: &str,
) -> Result<&'a crate::RpcSource, ToolError> {
    crate::resolve_rpc_source(sources, name, network_id).map_err(|error| {
        ToolError::new(
            error.code,
            "capture-target RPC source refused; request details withheld",
        )
    })
}

/// The capture as the tool's output, or the refusal under its stable code: the caller's
/// envelope as an input code (`E_RESOURCE_LIMIT`, `E_ENVELOPE_PARSE`, `E_UNSUPPORTED_ENVELOPE`,
/// the last for any call other than a native SAC exact-amount transfer), a source on another
/// network as `E_NETWORK_MISMATCH`, and everything the endpoint caused as `E_RPC`.
pub fn capture_target_output(
    capture: Result<TargetCapture, RpcError>,
) -> Result<CaptureTargetOutput, ToolError> {
    let error = match capture {
        Ok(capture) => return Ok(CaptureTargetOutput(capture)),
        Err(error) => error,
    };
    let code = match error {
        RpcError::EnvelopeTooLarge(_) => EC::EResourceLimit,
        RpcError::EnvelopeParse(_) => EC::EEnvelopeParse,
        RpcError::UnsupportedEnvelope(_) => EC::EUnsupportedEnvelope,
        RpcError::NetworkMismatch { .. } => EC::ENetworkMismatch,
        _ => EC::ERpc,
    };
    // The message is the adapter's, which already leads with the same code, as
    // `preflight_transaction`'s refusals do.
    Err(ToolError::new(code, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_refusal_keeps_its_stable_code() {
        for (error, code) in [
            (RpcError::EnvelopeTooLarge("big".into()), EC::EResourceLimit),
            (RpcError::EnvelopeParse("bad".into()), EC::EEnvelopeParse),
            (
                RpcError::UnsupportedEnvelope("approve".into()),
                EC::EUnsupportedEnvelope,
            ),
            (
                RpcError::NetworkMismatch {
                    expected: "Test SDF Network ; September 2015".into(),
                    actual: "withheld".into(),
                },
                EC::ENetworkMismatch,
            ),
            (RpcError::Malformed("refused".into()), EC::ERpc),
            (RpcError::Rpc("withheld".into()), EC::ERpc),
            (RpcError::Transport("withheld".into()), EC::ERpc),
        ] {
            let message = error.to_string();
            let refused = capture_target_output(Err(error)).unwrap_err();
            assert_eq!(refused.code, code, "{message}");
            // The message is the adapter's, which already names the same code.
            assert_eq!(refused.message, message);
            assert!(message.starts_with(code.as_str()), "{message}");
        }
    }
}
