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
    CheckPolicyCallSurfaceInput, CheckPolicyCallSurfaceOutput, ErrorCode, ToolError,
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
        let trust = self.registry_trust.clone().ok_or_else(|| {
            tool_err(ToolError::new(
                ErrorCode::ERegistryEmpty,
                "this server has no pinned registry trust configured",
            ))
        })?;
        // The source first: an unknown name, or one for another network, fails before any
        // build or read.
        let source = ozpb_toolkit::resolve_rpc_source(
            &self.rpc_sources,
            &input.rpc_source,
            &input.network_id,
        )
        .map_err(tool_err)?
        .clone();
        let rpc_url = self.authorized_rpc_url(&source.rpc_url).map_err(tool_err)?;
        let build_config = self.build_config.clone();
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
        let deadline = build_config
            .timeout
            .saturating_mul(u32::try_from(generated_rules).unwrap_or(u32::MAX))
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
        // A blocking read cannot be cancelled. The slot travels with the work and is released
        // when it ends, not when the caller stops waiting; the server caps the scan bounds.
        let work = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let plan = ozpb_toolkit::plan_call_surface_read(&input, &trust, &build_config)?;
            let transport = HttpTransport::new(rpc_url);
            let scan = scan_authority_state(
                &transport,
                &source.network_passphrase,
                &plan.account_address,
                &plan.contract_addresses,
                &plan.classic_addresses,
                capped(plan.bounds),
            )
            .map_err(|error| ozpb_toolkit::scan_tool_error(&error))?;
            ozpb_toolkit::finish_call_surface_check(&plan, &input.rpc_source, &scan)
        });
        let output = tokio::time::timeout(deadline, work)
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
            .map_err(tool_err)?;
        Ok(Json(output))
    }
}
