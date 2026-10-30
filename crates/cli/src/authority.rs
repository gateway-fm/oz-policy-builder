//! CLI shell for the live authority check and the install intent built on it.
//!
//! The endpoint comes from the operator's RPC source file, never from the request: the
//! request only names a source. The registry trust comes from the pinned roots and floor.

use anyhow::{Context as _, Result};
use ozpb_api_types::{
    AssembleInstallTransactionInput, CheckPolicyCallSurfaceInput, CheckPolicyCallSurfaceOutput,
    PrepareInstallIntentOutput,
};
use ozpb_source_rpc::{scan_authority_state, AccountStateScan, HttpTransport};
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

/// Operator configuration for read-only monitoring. No signing or exclusion flag exists on
/// the ordinary authority/intent commands.
#[derive(clap::Args, Debug)]
pub struct InstalledGrantArgs {
    #[arg(long)]
    request: PathBuf,
    #[arg(long, env = "OZPB_REGISTRY_ROOTS_FILE")]
    registry_roots: PathBuf,
    #[arg(long, env = "OZPB_REGISTRY_MIN_VERSION")]
    registry_min_version: u64,
    #[arg(long, env = "OZPB_RPC_SOURCES_FILE")]
    rpc_sources: PathBuf,
    #[command(flatten)]
    build: crate::BuildConfigArgs,
}

pub fn installed_grant(args: InstalledGrantArgs) -> Result<()> {
    let input: ozpb_api_types::CheckInstalledGrantInput = read_json(&args.request)?;
    let args = AuthorityArgs {
        request: args.request,
        registry_roots: args.registry_roots,
        registry_min_version: args.registry_min_version,
        rpc_sources: args.rpc_sources,
        build_config: args.build.resolve()?,
    };
    let session = Session::with_input(&args, input.candidate)?;
    let plan =
        ozpb_toolkit::plan_call_surface_read(&session.input, &session.trust, &args.build_config)?;
    let scan = session.read(&plan)?;
    print_json(&ozpb_toolkit::check_installed_grant_from_scan(
        &plan,
        &session.input.rpc_source,
        &scan,
        &input.installed_rule,
    )?)
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

/// Run the check and, only when it clears, print the exact `add_context_rule` arguments with
/// the answer they were checked against. A refusal or an unresolved item
/// exits non-zero with every finding.
pub fn intent(args: AuthorityArgs) -> Result<()> {
    let output = run_intent(&args)?;
    print_json(&output)
}

pub fn assemble(args: AuthorityArgs) -> Result<()> {
    let input: AssembleInstallTransactionInput = read_json(&args.request)?;
    let session = Session::with_input(&args, input.intent_request.clone())?;
    let plan =
        ozpb_toolkit::plan_install_intent_read(&session.input, &session.trust, &args.build_config)?;
    let scan = session.read(&plan)?;
    let intent =
        ozpb_toolkit::prepare_install_intent_from_scan(&plan, &session.input.rpc_source, &scan)?;
    let request = ozpb_toolkit::install_assembly_request(&input, &intent)?;
    let observation = ozpb_source_rpc::assemble_install_transaction(
        &HttpTransport::new(session.source.rpc_url.clone()),
        &session.source.network_passphrase,
        &request,
    )?;
    print_json(&ozpb_toolkit::install_assembly_output(
        &input,
        intent,
        observation,
    )?)
}

pub(crate) fn run_check(args: &AuthorityArgs) -> Result<CheckPolicyCallSurfaceOutput> {
    let session = Session::load(args)?;
    let plan =
        ozpb_toolkit::plan_call_surface_read(&session.input, &session.trust, &args.build_config)?;
    let scan = session.read(&plan)?;
    Ok(ozpb_toolkit::finish_call_surface_check(
        &plan,
        &session.input.rpc_source,
        &scan,
    )?)
}

pub(crate) fn run_intent(args: &AuthorityArgs) -> Result<PrepareInstallIntentOutput> {
    let session = Session::load(args)?;
    let plan =
        ozpb_toolkit::plan_install_intent_read(&session.input, &session.trust, &args.build_config)?;
    let scan = session.read(&plan)?;
    Ok(ozpb_toolkit::prepare_install_intent_from_scan(
        &plan,
        &session.input.rpc_source,
        &scan,
    )?)
}

struct Session {
    input: CheckPolicyCallSurfaceInput,
    trust: ozpb_toolkit::RegistryTrust,
    source: ozpb_toolkit::RpcSource,
}

impl Session {
    /// Read the request and the operator's configuration. The source is resolved first, so an
    /// unknown name or a source for another network fails before any build or read.
    fn load(args: &AuthorityArgs) -> Result<Self> {
        let input: CheckPolicyCallSurfaceInput = read_json(&args.request)?;
        Self::with_input(args, input)
    }

    fn with_input(args: &AuthorityArgs, input: CheckPolicyCallSurfaceInput) -> Result<Self> {
        let roots = std::fs::read_to_string(&args.registry_roots)
            .with_context(|| format!("reading {}", args.registry_roots.display()))?;
        let trust =
            ozpb_toolkit::registry_trust_from_roots_json(&roots, args.registry_min_version)?;
        let sources = std::fs::read_to_string(&args.rpc_sources)
            .with_context(|| format!("reading {}", args.rpc_sources.display()))?;
        let sources = ozpb_toolkit::rpc_sources_from_json(&sources)?;
        let source =
            ozpb_toolkit::resolve_rpc_source(&sources, &input.rpc_source, &input.network_id)?
                .clone();
        Ok(Self {
            input,
            trust,
            source,
        })
    }

    fn read(&self, plan: &ozpb_toolkit::CallSurfaceReadPlan) -> Result<AccountStateScan> {
        let transport = HttpTransport::new(self.source.rpc_url.clone());
        Ok(scan_authority_state(
            &transport,
            &self.source.network_passphrase,
            &plan.account_address,
            &plan.contract_addresses,
            &plan.classic_addresses,
            plan.bounds,
        )
        .map_err(|error| ozpb_toolkit::scan_tool_error(&error))?)
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}
