//! MCP wrappers for reference evidence and generated-artifact verification.
//!
//! The reference suite covers the pure evaluator layer only. Artifact verification
//! reproduces generated files and Wasm and reports its dimensions separately; neither
//! operation performs a live network preflight.

use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};

use ozpb_api_types::{ReferenceSuiteInput, ReferenceSuiteOutput, VerifyInput, VerifyOutput};

use crate::{internal_tool_err, tool_err, PolicyBuilderServer};

#[tool_router(router = verification_tool_router, vis = "pub(crate)")]
impl PolicyBuilderServer {
    /// Run the pure reference evaluator over a constraint-derived permit/deny suite.
    #[tool(
        name = "reference_suite",
        description = "Evaluate a PolicySpec with the layer-1 reference suite and return \
                       labeled permit/deny evidence and coverage. Pure; does not run \
                       contract integration or live preflight."
    )]
    async fn reference_suite(
        &self,
        Parameters(input): Parameters<ReferenceSuiteInput>,
    ) -> Result<Json<ReferenceSuiteOutput>, CallToolResult> {
        let out = ozpb_toolkit::reference_suite(&input).map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Reproduce the selected rule's generated artifact and report each dimension.
    #[tool(
        name = "verify",
        description = "Verify generated non-lock files, Wasm and BuildManifest against a \
                       PolicySpec rule, and report offline behavior separately. \
                       Resource-consuming; live preflight remains separate."
    )]
    async fn verify(
        &self,
        Parameters(input): Parameters<VerifyInput>,
    ) -> Result<Json<VerifyOutput>, CallToolResult> {
        let build = self.build_config.clone();
        let out = tokio::task::spawn_blocking(move || {
            ozpb_toolkit::verify_with_build_config(&input, &build)
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(out))
    }
}
