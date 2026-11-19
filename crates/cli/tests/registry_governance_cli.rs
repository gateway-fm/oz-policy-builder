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

fn committed_draft() -> RegistrySnapshot {
    read(&repo().join("registry/mainnet/v0001.draft.json"))
}

/// The rehearsal genesis: the committed mainnet draft with what custodians fill in before
/// signing — the pending template review reference and the interval — and keyed to testnet.
fn genesis() -> RegistrySnapshot {
    let mut snapshot = committed_draft();
    snapshot.network_id = ozpb_domain::NetworkId::from_passphrase(TESTNET);
    snapshot.valid_from_unix = now() - 3_600;
    snapshot.expires_at_unix = now() + 30 * 86_400;
    for template in snapshot.templates.values_mut() {
        template.review_reference = "rehearsal: no review is claimed".to_string();
    }
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
    combine_for(TESTNET, unsigned, signatures, roots, out)
}

fn combine_for(
    network: &str,
    unsigned: &Path,
    signatures: &[&Path],
    roots: &Path,
    out: &Path,
) -> Output {
    let mut args = vec![
        "registry".into(),
        "combine".into(),
        "--snapshot".into(),
        unsigned.as_os_str().to_owned(),
        "--registry-roots".into(),
        roots.as_os_str().to_owned(),
        "--network".into(),
        network.into(),
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

    // The draft as committed, with its review reference still pending, is not combined.
    let mut pending = committed_draft();
    pending.network_id = ozpb_domain::NetworkId::from_passphrase(TESTNET);
    pending.valid_from_unix = now() - 3_600;
    pending.expires_at_unix = now() + 30 * 86_400;
    let pending_path = work.path().join("pending.unsigned.json");
    write_json(&pending_path, &pending);
    let pending_a = work.path().join("pending.custodian-a.sig.json");
    let pending_c = work.path().join("pending.custodian-c.sig.json");
    custodians.sign(&pending_path, "custodian-a", &pending_a);
    custodians.sign(&pending_path, "custodian-c", &pending_c);
    refused(
        &combine(
            &pending_path,
            &[&pending_a, &pending_c],
            &roots,
            &work.path().join("pending.signed.json"),
        ),
        "combine a draft with a pending review reference",
        "pending review reference",
    );
    // Signed some other way, it does not pass verify either.
    let key = |id: &str| {
        let seed = std::fs::read_to_string(custodians.key(id)).unwrap();
        let seed = stellar_strkey::ed25519::PrivateKey::from_string(seed.trim()).unwrap();
        ed25519_dalek::SigningKey::from_bytes(&seed.0)
    };
    let signed_pending = ozpb_registry::sign_snapshot_with_roots(
        &[
            ("custodian-a", key("custodian-a")),
            ("custodian-c", key("custodian-c")),
        ]
        .into_iter()
        .map(|(id, key)| (id.to_string(), key))
        .collect(),
        pending,
    )
    .unwrap();
    let signed_pending_path = work.path().join("pending.signed.json");
    write_json(&signed_pending_path, &signed_pending);
    refused(
        &ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--signed".as_ref(),
            signed_pending_path.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
        ]),
        "verify a signed draft with a pending review reference",
        "pending review reference",
    );

    // One signature is not a quorum.
    refused(
        &combine(&draft, &[&sig_a], &roots, &work.path().join("short.json")),
        "combine below threshold",
        "E_REGISTRY_SIGNATURE",
    );
    // Nothing a consumer would refuse reaches the log: signed for testnet, it is not combined as
    // a mainnet snapshot, and no file is written.
    let wrong = published.join("v0001.mainnet.json");
    refused(
        &combine_for(MAINNET, &draft, &[&sig_a, &sig_c], &roots, &wrong),
        "combine for another network",
        "E_REGISTRY_NETWORK",
    );
    assert!(!wrong.exists());
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
    let monitor_log = |checkpoint: &Path, log: &Path, roots: &Path, extra: &[&str]| {
        let mut args: Vec<String> = [
            "registry",
            "monitor",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--published",
            log.to_str().unwrap(),
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
    let monitor =
        |checkpoint: &Path, extra: &[&str]| monitor_log(checkpoint, &published, &roots, extra);
    let output = monitor(&checkpoint_v1_path, &["--wasm-hash", &revoked]);
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["status"], "revoked");
    assert_eq!(report["revoked"][0]["reason"], "rehearsal revocation");
    let output = monitor(&checkpoint_v1_path, &[]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    // A watch item that can never match fails instead of reading "current" forever: a mistyped
    // family or hash the head neither registers nor revokes, and a name that is not a family.
    for (item, expected) in [
        (
            ["--template", "policy-templates/scope@l"],
            "template family \"policy-templates/scope@l\" is neither registered nor revoked",
        ),
        (
            ["--wasm-hash", &"cd".repeat(32)],
            "is neither registered nor revoked",
        ),
        (
            ["--template", "policy templates"],
            "is not a template family name",
        ),
    ] {
        let output = monitor(&checkpoint_v1_path, &item);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        refused(
            &output,
            "monitor a watch item that can never match",
            expected,
        );
    }
    let head_path = work.path().join("checkpoint-v2.json");
    write_json(&head_path, &head);
    let output = monitor(&head_path, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let output = monitor(&head_path, &["--expiry-window-days", "90"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    // The head alone, rather than the log directory, serves when it directly extends the
    // checkpoint.
    let output = monitor_log(&checkpoint_v1_path, &v2, &roots, &[]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    // A published head older than the consumer's checkpoint is not a status but a failure: exit 1.
    let output = monitor_log(&head_path, &v1, &roots, &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    refused(&output, "monitor an older head", "E_REGISTRY_ROLLBACK");

    // 7. A toolkit operation trusts the replayed head under the custodians' roots: a testnet
    //    recording of the 0.7.3 account synthesizes, and the spec pins the head's root.
    use ozpb_synthesizer::fixtures;
    let recording = work.path().join("recording.json");
    write_json(&recording, &fixtures::golden_bundle());
    let account = work.path().join("account.json");
    write_json(&account, &fixtures::golden_input().account);
    let decisions = work.path().join("decisions.json");
    write_json(&decisions, &fixtures::golden_decisions());
    let synthesize_under = |signed: &Path, roots: &Path, floor: &str| {
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
            floor.as_ref(),
            "--decisions".as_ref(),
            decisions.as_os_str(),
            "--spending-limit-capability".as_ref(),
            "pinned".as_ref(),
            "--template-family".as_ref(),
            "policy-templates/scope@1".as_ref(),
        ])
    };
    let synthesize = |signed: &Path| synthesize_under(signed, &roots, "2");
    let synthesized = ok(synthesize(&v2), "synthesize");
    assert_eq!(synthesized["spec"]["registry_snapshot"], head.root.to_hex());
    // And the floor the head sets refuses version 1 from now on.
    refused(
        &synthesize(&v1),
        "synthesize under a rolled-back snapshot",
        "E_REGISTRY_ROLLBACK",
    );

    // 8. Rotation, as a re-pin: three new custodians, a new roots file published together with
    //    version 3 signed under it. Version 3 is built on version 2 under the roots that signed
    //    version 2; consumers replace their roots, keep their checkpoint, and move to version 3.
    let mut rotated_keys = serde_json::Map::new();
    for id in ["custodian-d", "custodian-e", "custodian-f"] {
        let printed = ok(
            ozpb([
                "registry".as_ref(),
                "keygen".as_ref(),
                "--out".as_ref(),
                custodians.key(id).as_os_str(),
            ]),
            "keygen",
        );
        rotated_keys.insert(id.to_string(), printed["public_key"].clone());
    }
    let rotated = work.path().join("roots-rotated.json");
    write_json(
        &rotated,
        &serde_json::json!({"threshold": 2, "keys": rotated_keys}),
    );
    let changes_v3 = work.path().join("changes-v3.json");
    write_json(
        &changes_v3,
        &serde_json::json!({
            "schema": "registry-change/v1",
            "valid_from_unix": now() - 30,
            "expires_at_unix": now() + 90 * 86_400,
        }),
    );
    let unsigned_v3 = work.path().join("v0003.unsigned.json");
    ok(
        ozpb([
            "registry".as_ref(),
            "successor".as_ref(),
            "--parent".as_ref(),
            v2.as_os_str(),
            "--changes".as_ref(),
            changes_v3.as_os_str(),
            "--registry-roots".as_ref(),
            roots.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
            "--out".as_ref(),
            unsigned_v3.as_os_str(),
        ]),
        "successor across the rotation",
    );
    let sig_d = work.path().join("v0003.custodian-d.sig.json");
    let sig_f = work.path().join("v0003.custodian-f.sig.json");
    custodians.sign(&unsigned_v3, "custodian-d", &sig_d);
    custodians.sign_externally(&unsigned_v3, "custodian-f", &sig_f);
    // The old roots cannot combine it; the new ones can.
    refused(
        &combine(
            &unsigned_v3,
            &[&sig_d, &sig_f],
            &roots,
            &work.path().join("old-roots.json"),
        ),
        "combine under the retired roots",
        "E_REGISTRY_SIGNATURE",
    );
    let v3 = published.join("v0003.signed.json");
    ok(
        combine(&unsigned_v3, &[&sig_d, &sig_f], &rotated, &v3),
        "combine v3",
    );
    // A consumer at version 2 that re-pinned follows the log under the new roots.
    let output = monitor_log(&head_path, &published, &rotated, &[]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let checkpoint_v3 = ok(
        ozpb([
            "registry".as_ref(),
            "verify".as_ref(),
            "--signed".as_ref(),
            v3.as_os_str(),
            "--checkpoint".as_ref(),
            head_path.as_os_str(),
            "--registry-roots".as_ref(),
            rotated.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
        ]),
        "verify v3 against the version-2 checkpoint",
    );
    assert_eq!(checkpoint_v3["version"], "3");
    // Its roots file now pins the new keys with its version-2 checkpoint; synthesis takes v3.
    let repinned = work.path().join("roots-repinned.json");
    write_json(
        &repinned,
        &serde_json::json!({"threshold": 2, "keys": rotated_keys, "checkpoint": head}),
    );
    let synthesized = ok(
        synthesize_under(&v3, &repinned, "2"),
        "synthesize after rotation",
    );
    assert_eq!(
        synthesized["spec"]["registry_snapshot"],
        checkpoint_v3["root"]
    );
    // Without the re-pin, the old roots refuse the new version.
    refused(
        &synthesize(&v3),
        "synthesize v3 under the retired roots",
        "E_REGISTRY_SIGNATURE",
    );

    // 9. Revoking the template family reaches every generated policy built from it: a consumer
    //    watching the family hears of it (exit 6), and synthesis refuses the family.
    let family = "policy-templates/scope@1";
    let changes_v4 = work.path().join("changes-v4.json");
    write_json(
        &changes_v4,
        &serde_json::json!({
            "schema": "registry-change/v1",
            "valid_from_unix": now() - 20,
            "expires_at_unix": now() + 90 * 86_400,
            "revocations": {format!("template/{family}"): "rehearsal template revocation"},
        }),
    );
    let unsigned_v4 = work.path().join("v0004.unsigned.json");
    ok(
        ozpb([
            "registry".as_ref(),
            "successor".as_ref(),
            "--parent".as_ref(),
            v3.as_os_str(),
            "--changes".as_ref(),
            changes_v4.as_os_str(),
            "--registry-roots".as_ref(),
            rotated.as_os_str(),
            "--network".as_ref(),
            TESTNET.as_ref(),
            "--out".as_ref(),
            unsigned_v4.as_os_str(),
        ]),
        "successor revoking the template family",
    );
    let sig_d4 = work.path().join("v0004.custodian-d.sig.json");
    let sig_e4 = work.path().join("v0004.custodian-e.sig.json");
    custodians.sign(&unsigned_v4, "custodian-d", &sig_d4);
    custodians.sign(&unsigned_v4, "custodian-e", &sig_e4);
    let v4 = published.join("v0004.signed.json");
    ok(
        combine(&unsigned_v4, &[&sig_d4, &sig_e4], &rotated, &v4),
        "combine v4",
    );
    let checkpoint_v3_path = work.path().join("checkpoint-v3.json");
    write_json(&checkpoint_v3_path, &checkpoint_v3);
    let output = monitor_log(
        &checkpoint_v3_path,
        &published,
        &rotated,
        &["--template", family],
    );
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["revoked"][0]["watched"]["template_family"], family);
    assert_eq!(
        report["revoked"][0]["reason"],
        "rehearsal template revocation"
    );
    // Watching only code, the same consumer would have heard only of a newer version.
    let output = monitor_log(&checkpoint_v3_path, &published, &rotated, &[]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let at_v3 = work.path().join("roots-at-v3.json");
    write_json(
        &at_v3,
        &serde_json::json!({"threshold": 2, "keys": rotated_keys, "checkpoint": checkpoint_v3}),
    );
    refused(
        &synthesize_under(&v4, &at_v3, "3"),
        "synthesize from a revoked template family",
        "E_REGISTRY_REVOKED",
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

/// `--min-version` is a floor whichever checkpoint `verify` checks against. A checkpoint older
/// than the floor — the roots file's own, or one given with `--checkpoint` — is the combination
/// every consumer refuses (`E_REGISTRY_ROLLBACK` before any read), so the gate before distribution
/// refuses it too, instead of ignoring the floor and printing a checkpoint no consumer accepts.
#[test]
fn verify_refuses_a_checkpoint_older_than_the_floor() {
    let examples = repo().join("docs/examples");
    let signed = examples.join("registry.signed.json");
    let roots = examples.join("registry-roots.json");
    let work = tempfile::tempdir().unwrap();
    let verify = |roots: &Path, extra: &[&str]| {
        let mut args: Vec<String> = [
            "registry",
            "verify",
            "--signed",
            signed.to_str().unwrap(),
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
    let checkpoint = ok(verify(&roots, &[]), "verify the development snapshot");
    let version: u64 = checkpoint["version"].as_str().unwrap().parse().unwrap();
    let checkpoint_path = work.path().join("checkpoint.json");
    write_json(&checkpoint_path, &checkpoint);
    let mut pinned: serde_json::Value = read(&roots);
    pinned["checkpoint"] = checkpoint.clone();
    let pinned_path = work.path().join("roots-with-checkpoint.json");
    write_json(&pinned_path, &pinned);

    let above = (version + 1).to_string();
    refused(
        &verify(&pinned_path, &["--min-version", &above]),
        "verify under a roots checkpoint older than the floor",
        "E_REGISTRY_ROLLBACK",
    );
    refused(
        &verify(
            &roots,
            &[
                "--checkpoint",
                checkpoint_path.to_str().unwrap(),
                "--min-version",
                &above,
            ],
        ),
        "verify against a given checkpoint older than the floor",
        "E_REGISTRY_ROLLBACK",
    );
    // Control: at the checkpoint's own version the floor admits it, so the refusals above are the
    // floor's and not the checkpoint's.
    let at = version.to_string();
    assert_eq!(
        ok(
            verify(&pinned_path, &["--min-version", &at]),
            "floor at the checkpoint"
        ),
        checkpoint
    );
}
