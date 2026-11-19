//! `ozpb registry …`: the file-handling shell over `ozpb_registry::governance`, for registry
//! custodians and for consumers that monitor a published registry. Every decision is made in the
//! library; this module reads and writes files, and maps a monitoring status to an exit code.
//! `docs/REGISTRY-GOVERNANCE.md` is the procedure these commands serve.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use ozpb_domain::{Hash32, NetworkId};
use ozpb_registry::governance::{self, ChangeSet, DetachedSignature, MonitorStatus};
use ozpb_registry::{snapshot_root, RegistryCheckpoint, RegistrySnapshot, SignedSnapshot};
use std::path::{Path, PathBuf};

use crate::print_json;

#[derive(Subcommand)]
pub enum Command {
    /// Generate a custodian Ed25519 key into a new 0600 file and print its public key. The file
    /// is never overwritten and the secret is never printed.
    Keygen {
        /// The new key file (must not exist).
        #[arg(long)]
        out: PathBuf,
        /// The id the key will be pinned under, echoed for the roots file.
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Build the unsigned successor of a published snapshot from a declared change set, refusing
    /// anything a consumer's load would refuse.
    Successor {
        /// The published signed snapshot this one succeeds.
        #[arg(long)]
        parent: PathBuf,
        /// `registry-change/v1` JSON: new validity interval, added or replaced entries, new
        /// revocations.
        #[arg(long)]
        changes: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
        /// Trusted current time (Unix seconds); defaults to the system clock.
        #[arg(long)]
        at: Option<i64>,
        /// The unsigned successor to write (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the canonical root of an unsigned snapshot, or sign it into a detached signature
    /// with a 0600 key file or an Ed25519 signature produced elsewhere over that root.
    Sign(SignArgs),
    /// Assemble detached signatures into a signed snapshot, checking each against the pinned
    /// root policy and the threshold.
    Combine {
        /// The unsigned snapshot every signature covers.
        #[arg(long)]
        snapshot: PathBuf,
        /// A detached signature file; repeat for each custodian.
        #[arg(long = "signature", required = true)]
        signatures: Vec<PathBuf>,
        /// The pinned root policy JSON.
        #[arg(long)]
        registry_roots: PathBuf,
        /// The signed snapshot to write (must not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Load-verify a signed snapshot, or replay a published log from genesis, under the pinned
    /// roots and network; print the checkpoint a consumer persists. The gate before distribution.
    Verify(VerifyArgs),
    /// Compare a consumer's checkpoint with the published log: newer version, validity expiry,
    /// revocations of watched Wasm hashes. Prints JSON; the exit status is for cron: 0 current,
    /// 3 newer version, 4 expiring within the window, 5 expired, 6 a watched hash revoked, and
    /// 1 when the published log cannot be verified against the checkpoint.
    Monitor(MonitorArgs),
}

#[derive(Args)]
pub struct TrustArgs {
    /// Pinned root policy JSON, as consumers configure it: {"threshold", "keys": {id: hex}}.
    #[arg(long)]
    registry_roots: PathBuf,
    /// Network passphrase the registry is for.
    #[arg(long)]
    network: String,
}

#[derive(Args)]
pub struct SignArgs {
    /// The unsigned snapshot (`RegistrySnapshot` JSON).
    #[arg(long)]
    snapshot: PathBuf,
    /// Print the root to sign and what it commits to, and sign nothing.
    #[arg(long, conflicts_with_all = ["key_id", "key_file", "public_key", "signature", "out"])]
    print_root: bool,
    /// The id the signing key is pinned under.
    #[arg(long)]
    key_id: Option<String>,
    /// A 0600 file holding the custodian's Stellar secret seed (`S…`).
    #[arg(long, conflicts_with_all = ["public_key", "signature"])]
    key_file: Option<PathBuf>,
    /// Hex Ed25519 public key of a signature produced elsewhere.
    #[arg(long, requires = "signature")]
    public_key: Option<String>,
    /// Hex Ed25519 signature over the 32 bytes of the printed root, produced elsewhere.
    #[arg(long, requires = "public_key")]
    signature: Option<String>,
    /// The detached signature to write (must not exist).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// One signed snapshot.
    #[arg(long, conflicts_with = "replay", required_unless_present = "replay")]
    signed: Option<PathBuf>,
    /// A published log directory: `v0001.signed.json`, `v0002.signed.json`, … from genesis.
    #[arg(long)]
    replay: Option<PathBuf>,
    #[command(flatten)]
    trust: TrustArgs,
    /// With --signed: a persisted checkpoint (as this command prints) the snapshot must match or
    /// directly extend. Without one, the roots file's own checkpoint applies, if it has one.
    #[arg(long, conflicts_with = "replay")]
    checkpoint: Option<PathBuf>,
    /// With --signed and no checkpoint: the minimum acceptable version.
    #[arg(long, conflicts_with = "replay", default_value_t = 0)]
    min_version: u64,
    /// Trusted current time (Unix seconds); defaults to the system clock.
    #[arg(long)]
    at: Option<i64>,
}

#[derive(Args)]
pub struct MonitorArgs {
    /// The consumer's persisted checkpoint; defaults to the roots file's own checkpoint.
    #[arg(long)]
    checkpoint: Option<PathBuf>,
    /// The published head (one signed snapshot) or the published log directory.
    #[arg(long)]
    published: PathBuf,
    #[command(flatten)]
    trust: TrustArgs,
    /// Report expiry this many days ahead.
    #[arg(long, default_value_t = 14)]
    expiry_window_days: u32,
    /// A Wasm hash the consumer relies on (an installed account, policy or verifier); repeat.
    #[arg(long = "wasm-hash")]
    wasm_hashes: Vec<String>,
    /// Trusted current time (Unix seconds); defaults to the system clock.
    #[arg(long)]
    at: Option<i64>,
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Keygen { out, key_id } => keygen(&out, key_id),
        Command::Successor {
            parent,
            changes,
            trust,
            at,
            out,
        } => {
            let (roots, network) = trust.load()?;
            let parent: SignedSnapshot = read_json(&parent)?;
            let changes: ChangeSet = read_json(&changes)?;
            let next = governance::successor(roots, network, &parent, &changes, now(at)?)?;
            write_new(&out, &next)?;
            print_json(&root_summary(&next)?)
        }
        Command::Sign(args) => sign(args),
        Command::Combine {
            snapshot,
            signatures,
            registry_roots,
            out,
        } => {
            let roots = load_roots(&registry_roots)?.root_policy;
            let snapshot: RegistrySnapshot = read_json(&snapshot)?;
            let detached = signatures
                .iter()
                .map(|path| read_json::<DetachedSignature>(path))
                .collect::<Result<Vec<_>>>()?;
            let signed = governance::combine(&roots, snapshot, &detached)?;
            write_new(&out, &signed)?;
            print_json(&serde_json::json!({
                "version": signed.snapshot.version.to_string(),
                "root": snapshot_root(&signed.snapshot)?,
                "signers": signed.signatures.keys().collect::<Vec<_>>(),
            }))
        }
        Command::Verify(args) => verify(args),
        Command::Monitor(args) => monitor(args),
    }
}

impl TrustArgs {
    fn load(&self) -> Result<(ozpb_registry::RootPolicy, NetworkId)> {
        Ok((
            load_roots(&self.registry_roots)?.root_policy,
            NetworkId::from_passphrase(&self.network),
        ))
    }
}

fn keygen(out: &Path, key_id: Option<String>) -> Result<()> {
    let public = crate::key_file::generate_key_file(out)
        .with_context(|| format!("creating the new key file {}", out.display()))?;
    let mut printed = serde_json::json!({"public_key": hex::encode(public.to_bytes())});
    if let Some(id) = key_id {
        printed["key_id"] = id.into();
    }
    print_json(&printed)
}

fn sign(args: SignArgs) -> Result<()> {
    let snapshot: RegistrySnapshot = read_json(&args.snapshot)?;
    if args.print_root {
        return print_json(&root_summary(&snapshot)?);
    }
    let (Some(key_id), Some(out)) = (args.key_id, args.out) else {
        bail!("signing needs --key-id and --out (or --print-root to only print the root)");
    };
    let detached = match (args.key_file, args.public_key, args.signature) {
        (Some(key_file), None, None) => {
            let key = crate::key_file::read_signing_key(&key_file)
                .map_err(|error| anyhow!("{}: {error}", key_file.display()))?;
            governance::sign_detached(&key_id, &key, &snapshot)?
        }
        (None, Some(public_key), Some(signature)) => {
            let public_key: [u8; 32] = hex::decode(public_key.trim())
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| anyhow!("--public-key must be 32 bytes of hex"))?;
            governance::external_signature(&key_id, &public_key, &signature, &snapshot)?
        }
        _ => bail!("sign with either --key-file, or --public-key and --signature"),
    };
    write_new(&out, &detached)?;
    print_json(&serde_json::json!({"key_id": detached.key_id, "root": detached.root}))
}

fn verify(args: VerifyArgs) -> Result<()> {
    let config = load_roots(&args.trust.registry_roots)?;
    let network = NetworkId::from_passphrase(&args.trust.network);
    let now = now(args.at)?;
    if let Some(directory) = args.replay {
        let chain = read_log(&directory)?;
        return print_json(&governance::replay(
            config.root_policy,
            network,
            &chain,
            now,
        )?);
    }
    let path = args
        .signed
        .ok_or_else(|| anyhow!("verify needs --signed or --replay"))?;
    let signed: SignedSnapshot = read_json(&path)?;
    let checkpoint = match args.checkpoint {
        Some(path) => Some(read_json::<RegistryCheckpoint>(&path)?),
        None => config.checkpoint,
    };
    let mut registry = match checkpoint {
        Some(checkpoint) => ozpb_registry::Registry::with_pinned_roots_for_network_at_checkpoint(
            config.root_policy,
            network,
            checkpoint,
        ),
        None => ozpb_registry::Registry::with_pinned_roots_for_network_at_version(
            config.root_policy,
            network,
            args.min_version,
        ),
    }?;
    registry.load_at(&signed, now)?;
    print_json(&registry.checkpoint()?)
}

fn monitor(args: MonitorArgs) -> Result<()> {
    let config = load_roots(&args.trust.registry_roots)?;
    let checkpoint = match &args.checkpoint {
        Some(path) => read_json::<RegistryCheckpoint>(path)?,
        None => config.checkpoint.ok_or_else(|| {
            anyhow!("monitoring needs --checkpoint or a checkpoint in the roots file")
        })?,
    };
    let published = if args.published.is_dir() {
        read_log(&args.published)?
    } else {
        vec![read_json::<SignedSnapshot>(&args.published)?]
    };
    let watched = args
        .wasm_hashes
        .iter()
        .map(|hash| {
            Hash32::from_hex(hash)
                .ok()
                .filter(|parsed| parsed.to_hex() == *hash)
                .ok_or_else(|| anyhow!("--wasm-hash {hash:?} is not 32 bytes of lowercase hex"))
        })
        .collect::<Result<Vec<_>>>()?;
    let report = governance::monitor(
        config.root_policy,
        NetworkId::from_passphrase(&args.trust.network),
        checkpoint,
        &published,
        now(args.at)?,
        i64::from(args.expiry_window_days) * 86_400,
        &watched,
    )?;
    print_json(&report)?;
    let code = match report.status {
        MonitorStatus::Current => 0,
        MonitorStatus::NewerVersion => 3,
        MonitorStatus::ExpiresSoon => 4,
        MonitorStatus::Expired => 5,
        MonitorStatus::Revoked => 6,
    };
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// What a custodian checks before signing: the root and the fields it commits to that decide
/// where and when the snapshot is trusted.
fn root_summary(snapshot: &RegistrySnapshot) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "root": snapshot_root(snapshot)?,
        "network_id": snapshot.network_id,
        "version": snapshot.version.to_string(),
        "log_index": snapshot.log_index.to_string(),
        "previous_root": snapshot.previous_root,
        "valid_from_unix": snapshot.valid_from_unix.to_string(),
        "expires_at_unix": snapshot.expires_at_unix.to_string(),
        "revocations": snapshot.revocations.keys().collect::<Vec<_>>(),
    }))
}

/// The published log: every `vNNNN.signed.json` in the directory, in version order, each file's
/// number matching the version it holds. Other files (the roots file, drafts, a README) are not
/// part of the log.
fn read_log(directory: &Path) -> Result<Vec<SignedSnapshot>> {
    let mut entries = Vec::new();
    for entry in
        std::fs::read_dir(directory).with_context(|| format!("reading {}", directory.display()))?
    {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(number) = name
            .strip_prefix('v')
            .and_then(|rest| rest.strip_suffix(".signed.json"))
        else {
            continue;
        };
        if number.len() < 4 || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("{name}: a published version file is named v<4+ digits>.signed.json");
        }
        let version: u64 = number.parse().with_context(|| name.to_string())?;
        entries.push((version, path));
    }
    entries.sort();
    if entries.is_empty() {
        bail!(
            "{} holds no signed snapshot (v0001.signed.json, …)",
            directory.display()
        );
    }
    entries
        .into_iter()
        .map(|(version, path)| {
            let signed: SignedSnapshot = read_json(&path)?;
            if signed.snapshot.version != version {
                bail!(
                    "{} holds version {}, not the version its name says",
                    path.display(),
                    signed.snapshot.version
                );
            }
            Ok(signed)
        })
        .collect()
}

fn load_roots(path: &Path) -> Result<ozpb_toolkit::RegistryTrust> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(ozpb_toolkit::registry_trust_from_roots_json(&text, 0)?)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Write a new file, never replacing one: a published version or a signature is not something
/// a later command should overwrite by accident.
fn write_new(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    file.write_all((serde_json::to_string_pretty(value)? + "\n").as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

fn now(at: Option<i64>) -> Result<i64> {
    match at {
        Some(at) => Ok(at),
        None => Ok(i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?),
    }
}
