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
    /// The `authority_commitment` the installation was approved against (the verdict of the
    /// install intent it was built from; the wallet records it with the installation), as 64
    /// lowercase hex. With it, the exit status says what the observation found. Without it, any
    /// observation exits 0 and the caller compares it with its record. Needs --min-ledger.
    #[arg(long, value_parser = recorded_commitment, requires = "min_ledger")]
    recorded_authority_commitment: Option<String>,
    /// The oldest ledger a scheduled run accepts an observation of: the installation's ledger on
    /// the first run, then one past the `observed_ledger` of the last run that exited 0, never
    /// lowered. An older observation exits 4, so an endpoint stuck on an old ledger is not read
    /// as unchanged. Needs --recorded-authority-commitment.
    #[arg(long, requires = "recorded_authority_commitment")]
    min_ledger: Option<u32>,
    #[command(flatten)]
    build: crate::BuildConfigArgs,
}

/// A scheduled run's exit statuses (`--recorded-authority-commitment`); a failure before any
/// read exits 1 like every other command.
const EXIT_CHANGED: i32 = 3;
const EXIT_NO_ANSWER: i32 = 4;
const EXIT_INACTIVE: i32 = 5;

fn recorded_commitment(value: &str) -> std::result::Result<String, String> {
    ozpb_domain::Hash32::from_hex(value)
        .ok()
        .filter(|parsed| parsed.to_hex() == value)
        .map(|_| value.to_string())
        .ok_or_else(|| "an authority commitment is 32 bytes of lowercase hex".to_string())
}

pub fn installed_grant(args: InstalledGrantArgs) -> Result<()> {
    let input: ozpb_api_types::CheckInstalledGrantInput = read_json(&args.request)?;
    let scheduled = args.recorded_authority_commitment.zip(args.min_ledger);
    let args = AuthorityArgs {
        request: args.request,
        registry_roots: args.registry_roots,
        registry_min_version: args.registry_min_version,
        rpc_sources: args.rpc_sources,
        build_config: args.build.resolve()?,
    };
    // Up to the plan nothing reads the ledger: a failure here is the configuration's, exit 1.
    let session = Session::with_input(&args, input.candidate)?;
    let plan =
        ozpb_toolkit::plan_call_surface_read(&session.input, &session.trust, &args.build_config)?;
    let observed = session.read(&plan).and_then(|scan| {
        Ok(ozpb_toolkit::check_installed_grant_from_scan(
            &plan,
            &session.input.rpc_source,
            &scan,
            &input.installed_rule,
        )?)
    });
    let Some((recorded, min_ledger)) = scheduled else {
        return print_json(&observed?);
    };
    let code = scheduled_exit(&observed, &recorded, min_ledger);
    match &observed {
        Ok(output) => {
            print_json(output)?;
            if output.observed_ledger < min_ledger {
                eprintln!(
                    "Error: the observation is of ledger {}, older than --min-ledger {min_ledger}: \
                     the endpoint is behind or stuck",
                    output.observed_ledger
                );
            }
        }
        Err(error) => eprintln!("Error: {error:?}"),
    }
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// What a scheduled run exits with once the configuration has loaded. A read or check that
/// refused to answer (incomplete or archived state, code other than the recognized code, an
/// endpoint failure) leaves the grant's state unknown, which is never unchanged.
fn scheduled_exit(
    observed: &Result<ozpb_api_types::CheckInstalledGrantOutput>,
    recorded: &str,
    min_ledger: u32,
) -> i32 {
    match observed {
        Err(_) => EXIT_NO_ANSWER,
        Ok(output) => exit_status(ozpb_toolkit::compare_installed_grant(
            output, recorded, min_ledger,
        )),
    }
}

fn exit_status(found: ozpb_toolkit::InstalledGrantComparison) -> i32 {
    use ozpb_toolkit::InstalledGrantComparison as Found;
    match found {
        Found::Unchanged => 0,
        Found::Changed => EXIT_CHANGED,
        Found::Inactive => EXIT_INACTIVE,
        Found::Stale => EXIT_NO_ANSWER,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// No answer is never unchanged, and a changed rule is changed whatever was recorded. The
    /// comparison itself is the toolkit's (`installed_grant::tests`).
    #[test]
    fn a_scheduled_run_without_an_answer_or_with_a_changed_rule_alerts() {
        let recorded = "ab".repeat(32);
        let refused = Err(anyhow::anyhow!(
            "E_INCOMPLETE_ACCOUNT_STATE: archived entry"
        ));
        assert_eq!(scheduled_exit(&refused, &recorded, 0), EXIT_NO_ANSWER);
        let changed = ozpb_api_types::CheckInstalledGrantOutput {
            schema: "ozpb:installed-grant-observation:v1".into(),
            installed_rule_id: 1,
            status: "changed".into(),
            reason: Some("later_rule_allocation_or_changed_next_id".into()),
            projection: String::new(),
            observed_ledger: 1,
            actual_account_state_digest: "00".repeat(32),
            actual_raw_entry_digest: "00".repeat(32),
            projected_authority: None,
        };
        let changed = Ok(changed);
        assert_eq!(scheduled_exit(&changed, &recorded, 1), EXIT_CHANGED);
        // Older than the floor is no answer, whatever it shows.
        assert_eq!(scheduled_exit(&changed, &recorded, 2), EXIT_NO_ANSWER);
        use ozpb_toolkit::InstalledGrantComparison as Found;
        assert_eq!(
            [
                Found::Unchanged,
                Found::Changed,
                Found::Inactive,
                Found::Stale
            ]
            .map(exit_status),
            [0, EXIT_CHANGED, EXIT_INACTIVE, EXIT_NO_ANSWER]
        );
        assert!([EXIT_CHANGED, EXIT_NO_ANSWER, EXIT_INACTIVE]
            .iter()
            .all(|code| ![0, 1, 2].contains(code)));
    }
}
