//! `ozpb` — the human-oriented shell over the same toolkit library the MCP server uses
//! (architecture §4.11: one core, multiple shells). Subcommands mirror the MCP tools.
//!
//! Everything reads/writes JSON on stdio so the steps compose in a pipeline:
//!   ozpb record --tx-hash … --rpc-url … --network … > rec.json
//!   ozpb synthesize --bundle rec.json --decisions d.json --account a.json … > spec.json
//!   ozpb generate --spec spec.json --rule 0 --out ./generated
//!   ozpb evaluate --spec spec.json --context c.json --invocation i.json

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use ozpb_api_types::{
    EvaluateSpecInput, GenerateCodeInput, RecordOutput, SynthesizeInput, SynthesizeOutput,
};
use ozpb_recorder_core::RecordOptions;
use ozpb_source_bundle::import_json;
use ozpb_source_rpc::{get_transaction, simulate_transaction, HttpTransport};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ozpb", version, about = "OZ Accounts Policy Builder CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Operator-side build settings, shared by every subcommand that compiles a policy.
///
/// These are deliberately *not* part of the MCP wire contract: a caller-chosen timeout is
/// resource exhaustion and a caller-chosen builder path is arbitrary execution, so they stay
/// on the operator side. The env fallbacks are the same keys the MCP server reads, so both
/// shells are configured identically.
#[derive(Args, Clone, Debug)]
struct BuildConfigArgs {
    /// Wall-clock limit for one policy build, in seconds.
    #[arg(long, env = ozpb_toolkit::ENV_BUILD_TIMEOUT_SECS)]
    build_timeout_secs: Option<u64>,
    /// Persistent compilation cache. Omitted uses a shared default; a cold cache means every
    /// build recompiles the whole dependency tree.
    #[arg(long, env = ozpb_toolkit::ENV_BUILD_CACHE_DIR)]
    build_cache_dir: Option<PathBuf>,
    /// Compiler parallelism (`CARGO_BUILD_JOBS`). Does not affect output bytes.
    #[arg(long, env = ozpb_toolkit::ENV_BUILD_JOBS)]
    build_jobs: Option<u32>,
    /// Path to the `stellar` CLI used for `stellar contract build`.
    #[arg(long, env = ozpb_toolkit::ENV_STELLAR_BINARY)]
    stellar_binary: Option<PathBuf>,
}

impl BuildConfigArgs {
    /// Note there is no flag for the builder kind: the hermetic stub emits unattestable wasm
    /// and must never be selectable by configuration.
    fn resolve(&self) -> Result<ozpb_toolkit::BuildConfig> {
        let mut config = ozpb_toolkit::BuildConfig::default();
        if let Some(seconds) = self.build_timeout_secs {
            config.timeout = std::time::Duration::from_secs(seconds);
        }
        if let Some(jobs) = self.build_jobs {
            config.jobs = jobs;
        }
        if let Some(dir) = &self.build_cache_dir {
            config.target_dir = Some(dir.clone());
        }
        if let Some(binary) = &self.stellar_binary {
            config.stellar_binary = binary.clone();
        }
        // The bounds live in one place, so a flag cannot accept what the matching env var
        // would reject. A hand-rolled check here would silently omit the ceilings.
        config.validated().map_err(anyhow::Error::from)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Record an executed transaction by hash (network read).
    Record {
        #[arg(long)]
        tx_hash: String,
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        operation_index: Option<u32>,
        #[arg(long, default_value_t = false)]
        allow_failed: bool,
    },
    /// Record a simulated unsigned envelope (network read; record mode).
    Simulate {
        #[arg(long)]
        envelope_xdr: String,
        #[arg(long)]
        rpc_url: String,
        #[arg(long)]
        network: String,
    },
    /// Record from an imported raw-XDR evidence bundle (offline; self_supplied at most —
    /// incomplete without the transaction result XDR).
    Import {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Synthesize a PolicySpec (pure).
    Synthesize {
        /// One or more RecordingBundle JSON files.
        #[arg(long = "bundle", required = true)]
        bundles: Vec<PathBuf>,
        #[arg(long)]
        selected_authorizer: String,
        #[arg(long)]
        account: PathBuf,
        /// Signed registry snapshot JSON.
        #[arg(long)]
        signed_registry: PathBuf,
        /// Out-of-band threshold root policy JSON file (threshold, signer-id -> key map,
        /// and optional durable transparency checkpoint).
        #[arg(long, env = "OZPB_REGISTRY_ROOTS_FILE")]
        registry_roots: PathBuf,
        /// Persisted minimum accepted snapshot version (anti-rollback floor).
        #[arg(long, env = "OZPB_REGISTRY_MIN_VERSION")]
        registry_min_version: u64,
        #[arg(long)]
        decisions: PathBuf,
        #[arg(long)]
        spending_limit_capability: Option<String>,
        #[arg(long)]
        template_family: String,
    },
    /// Evaluate an invocation against a spec via the reference evaluator (pure).
    Evaluate {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        invocation: PathBuf,
    },
    /// Generate and build the immutable policy artifact (never deploys or signs).
    Generate {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value_t = 0)]
        rule: usize,
        /// Directory to write the generated crate into.
        #[arg(long)]
        out: Option<PathBuf>,
        #[command(flatten)]
        build: BuildConfigArgs,
    },
    /// Write the development registry trust files (signed snapshot + root policy).
    ///
    /// The pipeline cannot run without them, and they are derived from the code — emitting
    /// them beats committing copies that drift from `registry::dev`. The root key is a
    /// development key derived from a fixed string: it makes the demo reproducible by anyone
    /// and is unusable as a production governance root, by design.
    DevRegistry {
        /// Directory to write `registry.signed.json` and `registry-roots.json` into.
        #[arg(long, default_value = "docs/examples")]
        out: PathBuf,
    },
}

fn read_json(path: &PathBuf) -> Result<serde_json::Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Record {
            tx_hash,
            rpc_url,
            network,
            operation_index,
            allow_failed,
        } => {
            let transport = HttpTransport::new(rpc_url);
            let snapshot = get_transaction(&transport, &network, &tx_hash)?;
            let out = record(
                &snapshot,
                RecordOptions {
                    operation_index,
                    allow_failed,
                },
            )?;
            print_json(&out)?;
        }
        Command::Simulate {
            envelope_xdr,
            rpc_url,
            network,
        } => {
            let transport = HttpTransport::new(rpc_url);
            let snapshot = simulate_transaction(&transport, &network, &envelope_xdr)?;
            let out = record(&snapshot, RecordOptions::default())?;
            print_json(&out)?;
        }
        Command::Import { bundle } => {
            let text = std::fs::read_to_string(&bundle)
                .with_context(|| format!("reading {}", bundle.display()))?;
            let snapshot = import_json(&text)?;
            let out = record(&snapshot, RecordOptions::default())?;
            print_json(&out)?;
        }
        Command::Synthesize {
            bundles,
            selected_authorizer,
            account,
            signed_registry,
            registry_roots,
            registry_min_version,
            decisions,
            spending_limit_capability,
            template_family,
        } => {
            let bundle_values: Vec<serde_json::Value> =
                bundles.iter().map(read_json).collect::<Result<_>>()?;
            // Each recorded output has a `bundle` field; accept either the full record
            // output or a bare bundle.
            let bundle_values = bundle_values
                .into_iter()
                .map(|v| v.get("bundle").cloned().unwrap_or(v))
                .collect();
            let input = SynthesizeInput {
                bundles: bundle_values,
                selected_authorizer,
                account: read_json(&account)?,
                signed_registry_snapshot: read_json(&signed_registry)?,
                decisions: read_json(&decisions)?,
                spending_limit_capability,
                template_family,
            };
            let roots_json = std::fs::read_to_string(&registry_roots)
                .with_context(|| format!("reading {}", registry_roots.display()))?;
            let registry_trust =
                ozpb_toolkit::registry_trust_from_roots_json(&roots_json, registry_min_version)?;
            let out: SynthesizeOutput = ozpb_toolkit::synthesize_policy(&input, &registry_trust)
                .map_err(anyhow::Error::from)?;
            print_json(&out)?;
        }
        Command::Evaluate {
            spec,
            context,
            invocation,
        } => {
            let input = EvaluateSpecInput {
                spec: read_json(&spec)?,
                context: read_json(&context)?,
                invocation: read_json(&invocation)?,
            };
            let out = ozpb_toolkit::evaluate_spec(&input).map_err(anyhow::Error::from)?;
            print_json(&out)?;
        }
        Command::Generate {
            spec,
            rule,
            out,
            build,
        } => {
            let input = GenerateCodeInput {
                spec: read_json(&spec)?,
                rule_index: rule,
            };
            let generated =
                ozpb_toolkit::generate_code_with_build_config(&input, &build.resolve()?)
                    .map_err(anyhow::Error::from)?;
            if let Some(dir) = out {
                for (rel, content) in &generated.files {
                    let path = dir.join(rel);
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&path, content)?;
                }
                let wasm = base64::engine::general_purpose::STANDARD
                    .decode(&generated.wasm_base64)
                    .context("decoding generated Wasm")?;
                let wasm_name = format!("{}.wasm", generated.crate_name.replace('-', "_"));
                std::fs::write(dir.join(wasm_name), wasm)?;
                std::fs::write(
                    dir.join("build-manifest.json"),
                    serde_json::to_vec_pretty(&generated.build_manifest)?,
                )?;
                eprintln!(
                    "wrote crate '{}' ({} files), Wasm {}, and BuildManifest {} to {}",
                    generated.crate_name,
                    generated.files.len(),
                    generated.wasm_hash,
                    generated.build_manifest_hash,
                    dir.display(),
                );
            } else {
                print_json(&generated)?;
            }
        }
        Command::DevRegistry { out } => {
            std::fs::create_dir_all(&out)?;
            let (snapshot_json, roots_json) = ozpb_registry::dev::dev_trust_files(
                ozpb_domain::NetworkId::from_passphrase(ozpb_domain::TESTNET_PASSPHRASE),
                1,
            )
            .map_err(|e| anyhow::anyhow!("building the development trust files: {e}"))?;
            let snapshot_path = out.join("registry.signed.json");
            let roots_path = out.join("registry-roots.json");
            std::fs::write(&snapshot_path, snapshot_json)?;
            std::fs::write(&roots_path, roots_json)?;
            eprintln!(
                "wrote {} and {}",
                snapshot_path.display(),
                roots_path.display()
            );
            eprintln!("root key is a DEVELOPMENT key — not usable as a production governance root");
        }
    }
    Ok(())
}

fn record(
    snapshot: &ozpb_recorder_core::EvidenceSnapshot,
    options: RecordOptions,
) -> Result<RecordOutput> {
    ozpb_toolkit::record_snapshot(snapshot, options).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> BuildConfigArgs {
        BuildConfigArgs {
            build_timeout_secs: None,
            build_cache_dir: None,
            build_jobs: None,
            stellar_binary: None,
        }
    }

    #[test]
    fn build_flags_can_never_select_the_unattestable_stub_builder() {
        let resolved = BuildConfigArgs {
            build_timeout_secs: Some(30),
            build_cache_dir: Some(PathBuf::from("/operator/cache")),
            build_jobs: Some(2),
            stellar_binary: Some(PathBuf::from("/opt/bin/stellar")),
        }
        .resolve()
        .unwrap();
        // Compared through Debug so the facade need not re-export the stub variant at all.
        assert_eq!(
            format!("{:?}", resolved.builder),
            "Local",
            "the hermetic stub emits unattestable wasm and must not be configurable"
        );
    }

    #[test]
    fn build_flags_are_applied_and_nonsense_is_rejected() {
        let resolved = BuildConfigArgs {
            build_timeout_secs: Some(300),
            build_jobs: Some(4),
            ..args()
        }
        .resolve()
        .unwrap();
        assert_eq!(resolved.timeout, std::time::Duration::from_secs(300));
        assert_eq!(resolved.jobs, 4);

        for bad in [
            BuildConfigArgs {
                build_timeout_secs: Some(0),
                ..args()
            },
            BuildConfigArgs {
                build_jobs: Some(0),
                ..args()
            },
        ] {
            assert!(
                bad.resolve().is_err(),
                "a zero bound must fail closed, not disable the bound"
            );
        }
    }

    #[test]
    fn the_documented_build_flags_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "ozpb",
            "generate",
            "--spec",
            "spec.json",
            "--build-timeout-secs",
            "42",
            "--build-jobs",
            "2",
            "--build-cache-dir",
            "/tmp/cache",
            "--stellar-binary",
            "/opt/bin/stellar",
        ])
        .expect("build flags must be accepted by `ozpb generate`");
        match cli.command {
            Command::Generate { build, .. } => {
                assert_eq!(build.build_timeout_secs, Some(42));
                assert_eq!(build.build_jobs, Some(2));
            }
            _ => panic!("expected the Generate subcommand"),
        }
    }
}
