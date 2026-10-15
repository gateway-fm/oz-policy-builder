//! CLI shell for the live authority check.
//!
//! The endpoint comes from the operator's RPC source file, never from the request: the
//! request only names a source. The registry trust comes from the pinned roots and floor.

use anyhow::{Context, Result};
use ozpb_api_types::{CheckPolicyCallSurfaceInput, CheckPolicyCallSurfaceOutput};
use ozpb_source_rpc::{scan_authority_state, HttpTransport};
use std::path::PathBuf;

use crate::print_json;

/// Everything the authority commands share.
pub struct AuthorityArgs {
    pub request: PathBuf,
    pub registry_roots: PathBuf,
    pub registry_min_version: u64,
    pub rpc_sources: PathBuf,
    pub build_config: ozpb_toolkit::BuildConfig,
}

/// Run the live check and print the structured answer, or its plain-words reading.
pub fn check(args: AuthorityArgs, text: bool) -> Result<()> {
    let output = run_check(&args)?;
    if text {
        print!("{}", output.summary);
        Ok(())
    } else {
        print_json(&output)
    }
}

pub(crate) fn run_check(args: &AuthorityArgs) -> Result<CheckPolicyCallSurfaceOutput> {
    let input: CheckPolicyCallSurfaceInput = read_json(&args.request)?;
    let roots = std::fs::read_to_string(&args.registry_roots)
        .with_context(|| format!("reading {}", args.registry_roots.display()))?;
    let trust = ozpb_toolkit::registry_trust_from_roots_json(&roots, args.registry_min_version)?;
    let sources = std::fs::read_to_string(&args.rpc_sources)
        .with_context(|| format!("reading {}", args.rpc_sources.display()))?;
    let sources = ozpb_toolkit::rpc_sources_from_json(&sources)?;

    // Resolve the source first: an unknown name or a source for another network fails before
    // any build or read.
    let source = ozpb_toolkit::resolve_rpc_source(&sources, &input.rpc_source, &input.network_id)?;
    let plan = ozpb_toolkit::plan_call_surface_read(&input, &trust, &args.build_config)?;
    let transport = HttpTransport::new(source.rpc_url.clone());
    let scan = scan_authority_state(
        &transport,
        &source.network_passphrase,
        &plan.account_address,
        &plan.contract_addresses,
        &plan.classic_addresses,
        plan.bounds,
    )
    .map_err(|error| ozpb_toolkit::scan_tool_error(&error))?;
    Ok(ozpb_toolkit::finish_call_surface_check(
        &plan,
        &input.rpc_source,
        &scan,
    )?)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}
