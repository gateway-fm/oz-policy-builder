//! Network-read wrapper for the live authority check.
//!
//! The endpoint is the operator's: the request names a configured source, and a hosted
//! server additionally requires that source's URL to be on its allowlist. The registry trust
//! is the operator's too. The answer is advisory to whoever asked over MCP: the wallet that
//! holds the owner key recomputes it and decides.

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use ozpb_api_types::{
    CheckPolicyCallSurfaceInput, CheckPolicyCallSurfaceOutput, ErrorCode,
    PrepareInstallIntentInput, PrepareInstallIntentOutput, ToolError,
};
use ozpb_source_rpc::{scan_authority_state, HttpTransport};

use crate::{internal_tool_err, tool_err, PolicyBuilderServer};

/// How long a caller waits for the read itself, on top of one build timeout per spec rule with
/// a generated policy (each is rebuilt to be recognized).
const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// Server-side ceilings on the signed scan bounds. On testnet the public development root can
/// sign any bounds, so a caller could otherwise set the operator's RPC load.
fn capped(bounds: ozpb_source_rpc::AccountScanBounds) -> ozpb_source_rpc::AccountScanBounds {
    ozpb_source_rpc::AccountScanBounds {
        max_scan_ids: bounds.max_scan_ids.min(1_000),
        max_rpc_batches: bounds.max_rpc_batches.min(32),
        max_transitive_entries: bounds.max_transitive_entries.min(1_000),
        max_attempts: bounds.max_attempts.min(2),
    }
}

#[tool_router(router = authority_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    /// Read who can change the account or reset the policies being installed.
    #[tool(
        name = "check_policy_call_surface",
        description = "Advisory, state-dependent network read through an operator-configured \
                       RPC source. For one spec rule about to be installed, lists every live \
                       rule that can change the account or reset the bound policies, each with \
                       exactly who must sign (authority_list), plus refusals (authority already \
                       unacceptable, or shapes this version does not support), unresolved \
                       evidence gaps, other rules on the target, rules for other contracts that \
                       were not analysed, and an authority_commitment over the state and the \
                       exact install arguments. It never says an account is safe and never \
                       decides who the owners are: only the wallet that holds the owner key can, \
                       after recomputing this itself. Tell the user to confirm it there. \
                       `summary` is the plain-words reading. May rebuild generated policies to \
                       recognize them before reading.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn check_policy_call_surface(
        &self,
        Parameters(input): Parameters<CheckPolicyCallSurfaceInput>,
    ) -> Result<Json<CheckPolicyCallSurfaceOutput>, CallToolResult> {
        let (trust, source, rpc_url, deadline, slot) = self.authority_setup(&input, 0)?;
        let build_config = self.build_config.clone();
        let work = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let plan = ozpb_toolkit::plan_call_surface_read(&input, &trust, &build_config)?;
            let scan = read(&plan, &source, rpc_url)?;
            ozpb_toolkit::finish_call_surface_check(&plan, &input.rpc_source, &scan)
        });
        Ok(Json(finish(work, deadline).await?))
    }

    /// The exact install arguments, only for an answer that clears.
    #[tool(
        name = "prepare_install_intent",
        description = "Runs check_policy_call_surface itself (same request, same operator-configured \
                       RPC source) and, only when it returns no refusal and nothing unresolved, \
                       returns the exact add_context_rule arguments derived from the grant its \
                       authority_commitment covers, with that answer attached. A refusal or an \
                       unresolved item is an error carrying every finding. Never says an account \
                       is safe, never \
                       assembles, signs or submits: the user's wallet recomputes the check, \
                       matches every listed owner to the user's own keys or trusted identities, \
                       and asks the user. May rebuild generated policies.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn prepare_install_intent(
        &self,
        Parameters(input): Parameters<PrepareInstallIntentInput>,
    ) -> Result<Json<PrepareInstallIntentOutput>, CallToolResult> {
        let (trust, source, rpc_url, deadline, slot) = self.authority_setup(&input, 0)?;
        let build_config = self.build_config.clone();
        let work = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let plan = ozpb_toolkit::plan_install_intent_read(&input, &trust, &build_config)?;
            let scan = read(&plan, &source, rpc_url)?;
            ozpb_toolkit::prepare_install_intent_from_scan(&plan, &input.rpc_source, &scan)
        });
        Ok(Json(finish(work, deadline).await?))
    }
}

type Setup = (
    ozpb_toolkit::RegistryTrust,
    ozpb_toolkit::RpcSource,
    String,
    std::time::Duration,
    Option<tokio::sync::OwnedSemaphorePermit>,
);

impl PolicyBuilderServer {
    /// What both authority tools need before any work: pinned trust, the configured source
    /// (resolved first, so an unknown name or another network fails before any build or
    /// read), its allowlisted URL, a deadline that leaves room for the builds, and on a hosted
    /// server a work slot.
    pub(crate) fn authority_setup(
        &self,
        input: &CheckPolicyCallSurfaceInput,
        additional_builds: u32,
    ) -> Result<Setup, CallToolResult> {
        let trust = self.registry_trust.clone().ok_or_else(|| {
            tool_err(ToolError::new(
                ErrorCode::ERegistryEmpty,
                "this server has no pinned registry trust configured",
            ))
        })?;
        let source = ozpb_toolkit::resolve_rpc_source(
            &self.rpc_sources,
            &input.rpc_source,
            &input.network_id,
        )
        .map_err(tool_err)?
        .clone();
        let rpc_url = self.authorized_rpc_url(&source.rpc_url).map_err(tool_err)?;
        let generated_rules = input
            .binding_set
            .bindings
            .iter()
            .filter(|binding| {
                matches!(
                    binding.recognition,
                    ozpb_api_types::PolicyRecognition::VerifiedGeneratedManifest { .. }
                )
            })
            .map(|binding| binding.rule_index)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let deadline = self
            .build_config
            .timeout
            .saturating_mul(
                u32::try_from(generated_rules)
                    .unwrap_or(u32::MAX)
                    .saturating_add(additional_builds),
            )
            .saturating_add(READ_DEADLINE);
        let slot = match &self.authority_slots {
            Some(slots) => Some(slots.clone().try_acquire_owned().map_err(|_| {
                tool_err(ToolError::new(
                    ErrorCode::EResourceLimit,
                    "another authority read is running on this server; retry shortly",
                ))
            })?),
            None => None,
        };
        Ok((trust, source, rpc_url, deadline, slot))
    }
}

/// The scan itself, within the server's caps on the signed bounds.
fn read(
    plan: &ozpb_toolkit::CallSurfaceReadPlan,
    source: &ozpb_toolkit::RpcSource,
    rpc_url: String,
) -> Result<ozpb_source_rpc::AccountStateScan, ToolError> {
    let transport = HttpTransport::new(rpc_url);
    scan_authority_state(
        &transport,
        &source.network_passphrase,
        &plan.account_address,
        &plan.contract_addresses,
        &plan.classic_addresses,
        capped(plan.bounds),
    )
    .map_err(|error| ozpb_toolkit::scan_tool_error(&error))
}

/// Wait for blocking work up to the deadline. A blocking read cannot be cancelled: the slot
/// travels with the work and is released when it ends, not when the caller stops waiting.
async fn finish<T: Send + 'static>(
    work: tokio::task::JoinHandle<Result<T, ToolError>>,
    deadline: std::time::Duration,
) -> Result<T, CallToolResult> {
    tokio::time::timeout(deadline, work)
        .await
        .map_err(|_| {
            tool_err(ToolError::new(
                ErrorCode::EResourceLimit,
                format!(
                    "the authority read did not finish within {} s (builds included)",
                    deadline.as_secs()
                ),
            ))
        })?
        .map_err(internal_tool_err)?
        .map_err(tool_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};

    #[test]
    fn endpoint_controlled_errors_are_redacted_before_mcp_serialization() {
        const SECRET: &str = "operator-endpoint-token";
        for (response, expected_code) in [
            (
                serde_json::json!({"jsonrpc":"2.0", "id":1,
                "error":{"code":-32000, "message":SECRET, "data":{"url":SECRET}}}),
                ErrorCode::ERpc,
            ),
            (
                serde_json::json!({"jsonrpc":"2.0", "id":SECRET, "result":{}}),
                ErrorCode::ERpc,
            ),
            (
                serde_json::json!({"jsonrpc":"2.0", "id":1,
                "result":{"passphrase":SECRET, "protocolVersion":29}}),
                ErrorCode::ENetworkMismatch,
            ),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; length]).unwrap();
                drop(reader);
                let body = response.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            });
            let raw = scan_authority_state(
                &HttpTransport::new(endpoint),
                ozpb_domain::TESTNET_PASSPHRASE,
                "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526",
                &[],
                &[],
                Default::default(),
            )
            .unwrap_err();
            server.join().unwrap();
            assert!(
                raw.to_string().contains(SECRET),
                "fixture did not exercise endpoint text: {raw}"
            );
            let error = ozpb_toolkit::scan_tool_error(&raw);
            assert_eq!(error.code, expected_code);
            let wire = serde_json::to_string(&tool_err(error)).unwrap();
            assert!(!wire.contains(SECRET), "{wire}");
            assert!(wire.contains("endpoint detail withheld"));
        }
    }
}
