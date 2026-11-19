//! `ozpb registry`, end to end through the real binary: a production-shaped (non-development)
//! testnet registry run by three throwaway custodians with a 2-of-3 policy — key generation, a
//! genesis and a successor each signed by a different pair (one signature produced outside the
//! CLI, as a hardware key would), combination, verification and replay of the published log,
//! monitoring from an older checkpoint — and then a toolkit operation, `ozpb synthesize`, that
//! accepts the replayed head as pinned trust and stamps its root into the spec. The genesis is the
//! committed mainnet draft keyed to testnet, so the rehearsal signs the entries mainnet would.

use ozpb_registry::{RegistryCheckpoint, RegistrySnapshot, SignedSnapshot};
use std::path::{Path, PathBuf};
use std::process::Output;

const TESTNET: &str = "Test SDF Network ; September 2015";

fn ozpb<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    std::process::Command::new(env!("CARGO_BIN_EXE_ozpb"))
        .args(args)
        .output()
        .expect("run CLI")
}

fn ok(output: Output, what: &str) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{what}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{what} printed no JSON ({error}): {output:?}"))
}

fn refused(output: &Output, what: &str, code: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{what} must fail");
    assert!(
        stderr.contains(code),
        "{what}: expected {code}, got {stderr}"
    );
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn write_json(path: &Path, value: &impl serde::Serialize) {
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const MAINNET: &str = "Public Global Stellar Network ; September 2015";

/// The rehearsal genesis: the committed mainnet draft, unchanged but for the two things a
/// rehearsal must change — it is keyed to testnet, and valid from an hour ago for thirty days
/// rather than the draft's placeholder interval.
fn genesis() -> RegistrySnapshot {
    let mut snapshot: RegistrySnapshot = read(&repo().join("registry/mainnet/v0001.draft.json"));
    snapshot.network_id = ozpb_domain::NetworkId::from_passphrase(TESTNET);
    snapshot.valid_from_unix = now() - 3_600;
    snapshot.expires_at_unix = now() + 30 * 86_400;
    snapshot
}

struct Custodians {
    dir: tempfile::TempDir,
}

impl Custodians {
    fn key(&self, id: &str) -> PathBuf {
        self.dir.path().join(format!("{id}.key"))
    }

    /// Sign `snapshot` with the custodian's key file, into a detached signature.
    fn sign(&self, snapshot: &Path, id: &str, out: &Path) {
        ok(
            ozpb([
                "registry".as_ref(),
                "sign".as_ref(),
                "--snapshot".as_ref(),
                snapshot.as_os_str(),
                "--key-id".as_ref(),
                id.as_ref(),
                "--key-file".as_ref(),
                self.key(id).as_os_str(),
                "--out".as_ref(),
                out.as_os_str(),
            ]),
            "sign",
        );
    }

    /// Sign the printed root outside the CLI, as a device holding the key would, and hand the
    /// signature in by hex.
    fn sign_externally(&self, snapshot: &Path, id: &str, out: &Path) {
        use ed25519_dalek::Signer;
        let printed = ok(
            ozpb([
                "registry".as_ref(),
                "sign".as_ref(),
                "--snapshot".as_ref(),
                snapshot.as_os_str(),
                "--print-root".as_ref(),
            ]),
            "print root",
        );
        let root = hex::decode(printed["root"].as_str().unwrap()).unwrap();
        let seed = std::fs::read_to_string(self.key(id)).unwrap();
        let seed = stellar_strkey::ed25519::PrivateKey::from_string(seed.trim()).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&seed.0);
        let signature = hex::encode(key.sign(&root).to_bytes());
        let public = hex::encode(key.verifying_key().to_bytes());
        ok(
            ozpb([
                "registry",
                "sign",
                "--snapshot",
                snapshot.to_str().unwrap(),
                "--key-id",
                id,
                "--public-key",
                &public,
                "--signature",
                &signature,
                "--out",
                out.to_str().unwrap(),
            ]),
            "external signature",
        );
    }
}

fn combine(unsigned: &Path, signatures: &[&Path], roots: &Path, out: &Path) -> Output {
    let mut args = vec![
        "registry".into(),
        "combine".into(),
        "--snapshot".into(),
        unsigned.as_os_str().to_owned(),
        "--registry-roots".into(),
        roots.as_os_str().to_owned(),
        "--out".into(),
        out.as_os_str().to_owned(),
    ];
    for signature in signatures {
        args.push("--signature".into());
        args.push(signature.as_os_str().to_owned());
    }
    ozpb::<_, std::ffi::OsString>(args)
}

#[test]
fn a_production_shaped_testnet_registry_runs_end_to_end() {
    let custodians = Custodians {
        dir: tempfile::tempdir().unwrap(),
    };
    let work = tempfile::tempdir().unwrap();
    let published = work.path().join("registry/testnet");
    std::fs::create_dir_all(&published).unwrap();

    // 1. Key ceremony: three custodians, each with a new private key file.
    let mut keys = serde_json::Map::new();
    for id in ["custodian-a", "custodian-b", "custodian-c"] {
        let printed = ok(
            ozpb([
                "registry".as_ref(),
                "keygen".as_ref(),
                "--out".as_ref(),
                custodians.key(id).as_os_str(),
                "--key-id".as_ref(),
                id.as_ref(),
            ]),
            "keygen",
        );
        assert_eq!(printed["key_id"], id);
        let public = printed["public_key"].as_str().unwrap().to_string();
        assert_eq!(public.len(), 64);
        // The secret is in the file and nowhere in what was printed.
        let secret = std::fs::read_to_string(custodians.key(id)).unwrap();
        assert!(secret.starts_with('S'));
        assert!(!printed.to_string().contains(secret.trim()));
        keys.insert(id.to_string(), public.into());
    }
    let again = ozpb([
        "registry".as_ref(),
        "keygen".as_ref(),
        "--out".as_ref(),
        custodians.key("custodian-a").as_os_str(),
    ]);
    assert!(!again.status.success(), "keygen must never replace a key");
    let roots = published.join("roots.json");
    write_json(&roots, &serde_json::json!({"threshold": 2, "keys": keys}));

    // 2. Genesis, signed by a and by c's device.
    let draft = work.path().join("v0001.unsigned.json");
    write_json(&draft, &genesis());
    let printed = ok(
        ozpb([
            "registry".as_ref(),
            "sign".as_ref(),
            "--snapshot".as_ref(),
            draft.as_os_str(),
            "--print-root".as_ref(),
        ]),
        "print root",
    );
    assert_eq!(printed["version"], "1");
    let sig_a = work.path().join("v0001.custodian-a.sig.json");
    let sig_c = work.path().join("v0001.custodian-c.sig.json");
    custodians.sign(&draft, "custodian-a", &sig_a);
    custodians.sign_externally(&draft, "custodian-c", &sig_c);

    // A key file anyone else can read is refused, and says nothing of its contents.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loose = custodians.dir.path().join("loose.key");
        std::fs::copy(custodians.key("custodian-b"), &loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        let output = ozpb([
            "registry".as_ref(),
            "sign".as_ref(),
            "--snapshot".as_ref(),
            draft.as_os_str(),
            "--key-id".as_ref(),
            "custodian-b".as_ref(),
            "--key-file".as_ref(),
            loose.as_os_str(),
            "--out".as_ref(),
            work.path().join("loose.sig.json").as_os_str(),
        ]);
        refused(&output, "sign with a 0644 key", "mode 0600");
        let secret = std::fs::read_to_string(&loose).unwrap();
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret.trim()));
    }

    // One signature is not a quorum.
    refused(
        &combine(&draft, &[&sig_a], &roots, &work.path().join("short.json")),
        "combine below threshold",
        "E_REGISTRY_SIGNATURE",
    );
    let v1 = published.join("v0001.signed.json");
    ok(
        combine(&draft, &[&sig_a, &sig_c], &roots, &v1),
        "combine v1",
    );

    // 3. The gate before distribution.
    let checkpoint_v1 = ok(
        ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--signed".as_ref(),
            v1.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
        ]),
        "verify v1",
    );
    assert_eq!(checkpoint_v1["version"], "1");
    let checkpoint_v1_path = work.path().join("checkpoint-v1.json");
    write_json(&checkpoint_v1_path, &checkpoint_v1);
    refused(
        &ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--signed".as_ref(),
            v1.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            MAINNET.as_ref(),
        ]),
        "verify for another network",
        "E_REGISTRY_NETWORK",
    );

    // 4. A successor: a revocation and a new validity interval, signed by b and c.
    let revoked = "ab".repeat(32);
    let changes = work.path().join("changes.json");
    write_json(
        &changes,
        &serde_json::json!({
            "schema": "registry-change/v1",
            "valid_from_unix": now() - 60,
            "expires_at_unix": now() + 60 * 86_400,
            "revocations": {format!("policy/{revoked}"): "rehearsal revocation"},
        }),
    );
    let unsigned = work.path().join("v0002.unsigned.json");
    let printed = ok(
        ozpb([
            "registry".as_ref(),
            "successor".as_ref(),
            "--parent".as_ref(),
            v1.as_os_str(),
            "--changes".as_ref(),
            changes.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
            "--out".as_ref(),
            unsigned.as_os_str(),
        ]),
        "successor",
    );
    assert_eq!(printed["version"], "2");
    let next: RegistrySnapshot = read(&unsigned);
    assert_eq!(next.previous_root.unwrap().to_hex(), checkpoint_v1["root"]);
    let sig_b = work.path().join("v0002.custodian-b.sig.json");
    let sig_c2 = work.path().join("v0002.custodian-c.sig.json");
    custodians.sign(&unsigned, "custodian-b", &sig_b);
    custodians.sign_externally(&unsigned, "custodian-c", &sig_c2);
    // A signature over version 1 does not count toward version 2.
    refused(
        &combine(
            &unsigned,
            &[&sig_b, &sig_a],
            &roots,
            &work.path().join("mixed.json"),
        ),
        "combine with a stale signature",
        "E_REGISTRY_SIGNATURE",
    );
    let v2 = published.join("v0002.signed.json");
    ok(
        combine(&unsigned, &[&sig_b, &sig_c2], &roots, &v2),
        "combine v2",
    );

    // 5. Replay the published log from genesis; the head is what consumers pin.
    let head = ok(
        ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--replay".as_ref(),
            published.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
        ]),
        "replay",
    );
    let head: RegistryCheckpoint = serde_json::from_value(head).unwrap();
    assert_eq!(head.version, 2);
    let signed_v2: SignedSnapshot = read(&v2);
    assert_eq!(
        head.root,
        ozpb_registry::snapshot_root(&signed_v2.snapshot).unwrap()
    );

    // 6. A consumer still at version 1 learns of version 2 and of the revocation it watches.
    let monitor = |checkpoint: &Path, extra: &[&str]| {
        let mut args: Vec<String> = [
            "registry",
            "monitor",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--published",
            published.to_str().unwrap(),
            "--registry-roots",
            roots.to_str().unwrap(),
            "--network",
            TESTNET,
        ]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
        args.extend(extra.iter().map(|arg| arg.to_string()));
        ozpb(args)
    };
    let output = monitor(&checkpoint_v1_path, &["--wasm-hash", &revoked]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "revoked");
    assert_eq!(report["revoked"][0]["reason"], "rehearsal revocation");
    let output = monitor(&checkpoint_v1_path, &[]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let head_path = work.path().join("checkpoint-v2.json");
    write_json(&head_path, &head);
    let output = monitor(&head_path, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let output = monitor(&head_path, &["--expiry-window-days", "90"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");

    // 7. A toolkit operation trusts the replayed head under the custodians' roots: a testnet
    //    recording of the 0.7.3 account synthesizes, and the spec pins the head's root.
    use ozpb_synthesizer::fixtures;
    let recording = work.path().join("recording.json");
    write_json(&recording, &fixtures::golden_bundle());
    let account = work.path().join("account.json");
    write_json(&account, &fixtures::golden_input().account);
    let decisions = work.path().join("decisions.json");
    write_json(&decisions, &fixtures::golden_decisions());
    let synthesize = |signed: &Path| {
        ozpb([
            "synthesize".as_ref(),
            "--bundle".as_ref(),
            recording.as_os_str(),
            "--selected-authorizer".as_ref(),
            fixtures::golden_account_strkey().as_ref(),
            "--account".as_ref(),
            account.as_os_str(),
            "--signed-registry".as_ref(),
            signed.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--registry-min-version".as_ref(),
            "2".as_ref(),
            "--decisions".as_ref(),
            decisions.as_os_str(),
            "--spending-limit-capability".as_ref(),
            "pinned".as_ref(),
            "--template-family".as_ref(),
            "policy-templates/scope@1".as_ref(),
        ])
    };
    let synthesized = ok(synthesize(&v2), "synthesize");
    assert_eq!(synthesized["spec"]["registry_snapshot"], head.root.to_hex());
    // And the floor the head sets refuses version 1 from now on.
    refused(
        &synthesize(&v1),
        "synthesize under a rolled-back snapshot",
        "E_REGISTRY_ROLLBACK",
    );
}

/// The committed mainnet log is an unsigned draft whose root policy is set at the key ceremony:
/// a custodian can print what they would sign, and nothing verifies until then.
#[test]
fn the_committed_mainnet_log_awaits_its_key_ceremony() {
    let directory = repo().join("registry/mainnet");
    let printed = ok(
        ozpb([
            "registry".as_ref(),
            "sign".as_ref(),
            "--snapshot".as_ref(),
            directory.join("v0001.draft.json").as_os_str(),
            "--print-root".as_ref(),
        ]),
        "print the draft's root",
    );
    assert_eq!(printed["version"], "1");
    assert_eq!(
        printed["network_id"],
        ozpb_domain::NetworkId::from_passphrase(MAINNET).0.to_hex()
    );
    // The placeholder root policy holds no key, so it can verify nothing.
    refused(
        &ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--replay".as_ref(),
            directory.as_os_str(),
            "--registry-roots".as_ref(),
            directory.join("roots.json").as_os_str(),
            "--network".as_ref(),
            MAINNET.as_ref(),
        ]),
        "replay under the placeholder roots",
        "E_REGISTRY_ROOT_POLICY",
    );
    // And under any real roots there is no signed version to replay yet.
    let work = tempfile::tempdir().unwrap();
    let key = work.path().join("throwaway.key");
    let printed = ok(
        ozpb([
            "registry".as_ref(),
            "keygen".as_ref(),
            "--out".as_ref(),
            key.as_os_str(),
        ]),
        "keygen",
    );
    let roots = work.path().join("roots.json");
    write_json(
        &roots,
        &serde_json::json!({"threshold": 1, "keys": {"throwaway": printed["public_key"]}}),
    );
    refused(
        &ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--replay".as_ref(),
            directory.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            MAINNET.as_ref(),
        ]),
        "replay of an unsigned log",
        "no signed snapshot",
    );
}
