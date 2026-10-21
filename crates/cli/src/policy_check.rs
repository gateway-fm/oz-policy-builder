//! Operator-configured live prediction; no signing, submission, or caller-supplied state.

use crate::{authority::AuthorityArgs, print_json};
use anyhow::{Context, Result};
use ozpb_api_types::CheckAgainstPolicyInput;
use ozpb_source_rpc::{capture_policy_state, HttpTransport};

pub fn check(args: AuthorityArgs) -> Result<()> {
    use std::io::Read;
    let file = std::fs::File::open(&args.request).context("opening policy-check request")?;
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .context("reading policy-check request")?;
    anyhow::ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "policy-check request exceeds 4 MiB"
    );
    let input: CheckAgainstPolicyInput =
        serde_json::from_slice(&bytes).context("parsing policy-check request")?;
    let sources =
        ozpb_toolkit::rpc_sources_from_json(&std::fs::read_to_string(&args.rpc_sources)?)?;
    let source = ozpb_toolkit::resolve_rpc_source(&sources, &input.rpc_source, &input.network_id)?;
    let trust = ozpb_toolkit::registry_trust_from_roots_json(
        &std::fs::read_to_string(&args.registry_roots)?,
        args.registry_min_version,
    )?;
    let plan = match ozpb_toolkit::plan_policy_check_read(&input, &trust, &args.build_config) {
        Ok(plan) => plan,
        Err(error) => return print_json(&ozpb_toolkit::policy_check_unavailable(error)?),
    };
    let capture = capture_policy_state(
        &HttpTransport::new(source.rpc_url.clone()),
        &source.network_passphrase,
        &plan.account_address,
        plan.installed_context_rule_id,
        &plan.contract_addresses,
        &plan.additional_keys,
    )
    .map_err(|_| {
        ozpb_api_types::ToolError::new(
            ozpb_api_types::ErrorCode::ERpc,
            "policy state could not be acquired coherently; endpoint details withheld",
        )
    })?;
    print_json(&ozpb_toolkit::finish_policy_check(&plan, &capture)?)
}
