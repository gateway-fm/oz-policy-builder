//! Network-read wrapper for one authorization-enforcing transaction simulation.

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use ozpb_api_types::{PreflightTransactionInput, PreflightTransactionOutput};
use ozpb_source_rpc::HttpTransport;

use crate::{internal_tool_err, rpc_tool_err, tool_err, PolicyBuilderServer};

#[tool_router(router = preflight_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    /// Simulate one exact envelope with RPC authorization enforcement. The endpoint's
    /// result is a state-dependent trial, not a durable policy or installation verdict.
    #[tool(
        name = "preflight_transaction",
        description = "Simulate one exact envelope, including any intended authorization \
                       entries, through Stellar RPC with authorization enforced. \
                       Returns the endpoint-reported outcome \
                       (simulated_success, simulation_failed, restoration_required, or \
                       declared_resources_insufficient with the under-declared resources) \
                       and ledger for that exact envelope. State-dependent; writes are \
                       discarded. Does not identify an installed policy or submit a transaction."
    )]
    async fn preflight_transaction(
        &self,
        Parameters(input): Parameters<PreflightTransactionInput>,
    ) -> Result<Json<PreflightTransactionOutput>, CallToolResult> {
        let rpc_url = self.authorized_rpc_url(&input.rpc_url).map_err(tool_err)?;
        let observation = tokio::task::spawn_blocking(move || {
            let transport = HttpTransport::new(rpc_url);
            ozpb_source_rpc::preflight_transaction(
                &transport,
                &input.network_passphrase,
                &input.envelope_xdr_base64,
            )
            .map_err(rpc_tool_err)
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(ozpb_toolkit::preflight_transaction_output(
            observation,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RpcEndpointPolicy;

    #[tokio::test]
    async fn hosted_preflight_rejects_an_endpoint_outside_the_allowlist() {
        let policy = RpcEndpointPolicy::from_csv("https://rpc.allowed.example")
            .expect("valid operator allowlist");
        let server =
            PolicyBuilderServer::new(None, Some(policy), ozpb_toolkit::BuildConfig::default());
        let error = server
            .preflight_transaction(Parameters(PreflightTransactionInput {
                rpc_url: "https://rpc.unapproved.example".to_string(),
                network_passphrase: "Test SDF Network ; September 2015".to_string(),
                envelope_xdr_base64: "not-base64".to_string(),
            }))
            .await;
        let error = match error {
            Ok(_) => panic!("hosted endpoint policy must run before RPC acquisition"),
            Err(error) => error,
        };
        let wire = serde_json::to_value(error).expect("tool error JSON");
        assert_eq!(wire["structuredContent"]["code"], "E_RPC", "{wire}");
        assert!(
            wire["structuredContent"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("allowlist")),
            "{wire}"
        );
    }
}
