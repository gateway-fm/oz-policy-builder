//! The recorder against **verbatim mainnet transactions** — the corpus architecture §8 asks for.
//!
//! `captured-mainnet/<case>/` holds the `result` objects of every call
//! [`get_transaction`] makes for one transaction: `getNetwork`, `getTransaction` (base64), and,
//! when the transaction references contracts, `getLedgerEntries` for their instances. They are
//! what a public mainnet RPC returned (mainnet was on protocol 29, every meta is v4), unedited.
//! `manifest.json` names each case's transaction, ledger and what it covers. All of it is public
//! ledger data; nothing was signed, simulated or submitted to obtain it.
//!
//! Public RPC keeps a transaction for about seven days, so these cannot be fetched again by
//! hash later. `scripts/mainnet-recorder-fixture.py find` picks fresh transactions of the same
//! shapes and `capture` stores them; `capture` on the committed manifest refreshes the same
//! transactions while they are still retained.
//!
//! The assertions are about what each case is *for*, checked against the evidence's own XDR
//! wherever the recorder decodes something, so a re-capture of the same shapes keeps them
//! meaningful. Replaying through the real entry point is the point: a hand-written mock can
//! only confirm our own assumption about the wire (see `rpc_conformance.rs`).

use ozpb_domain::{LedgerSeq, NetworkId, TrustLevel};
use ozpb_recorder_core::{
    record, ArgSummary, AuthorizationRecord, AuthorizedCall, CredentialRecord, EvidenceSnapshot,
    Execution, InvocationNode, MovementKind, ObservedExecutable, RecordError, RecordOptions,
    RecordingBundle,
};
use ozpb_source_bundle::{import_json, ImportedBundle};
use ozpb_source_rpc::{get_transaction, xdr_limits, RpcError, RpcTransport};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use stellar_xdr::{
    FeeBumpTransactionInnerTx, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
    InvokeHostFunctionResult, MuxedAccount, OperationBody, OperationResult, OperationResultTr,
    ReadXdr, ScAddress, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, Transaction, TransactionEnvelope, TransactionMeta, TransactionResult,
    TransactionResultResult, WriteXdr,
};

const MAINNET: &str = "Public Global Stellar Network ; September 2015";
/// Mainnet's protocol when the corpus was captured; testnet was already on 30.
const CAPTURED_PROTOCOL: u32 = 29;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/captured-mainnet")
}

fn read(path: PathBuf) -> Value {
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

struct Entry {
    tx_hash: String,
    ledger: u32,
    status: String,
}

fn manifest() -> BTreeMap<String, Entry> {
    read(corpus().join("manifest.json"))["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            (
                case["case"].as_str().unwrap().to_string(),
                Entry {
                    tx_hash: case["tx_hash"].as_str().unwrap().to_string(),
                    ledger: case["ledger"].as_u64().unwrap() as u32,
                    status: case["status"].as_str().unwrap().to_string(),
                },
            )
        })
        .collect()
}

fn captured(case: &str, method: &str) -> Value {
    read(corpus().join(case).join(format!("{method}.json")))
}

/// Replays one case's captured responses by method, recording which methods were asked for.
struct Replay {
    case: String,
    calls: RefCell<Vec<String>>,
}

impl RpcTransport for Replay {
    fn call(&self, method: &str, _params: Value) -> Result<Value, RpcError> {
        self.calls.borrow_mut().push(method.to_string());
        Ok(captured(&self.case, method))
    }
}

/// The snapshot `get_transaction` acquires for a case, and the calls it made to get it.
fn acquire(case: &str) -> (EvidenceSnapshot, Vec<String>) {
    let replay = Replay {
        case: case.to_string(),
        calls: RefCell::new(Vec::new()),
    };
    let snapshot = get_transaction(&replay, MAINNET, &manifest()[case].tx_hash)
        .unwrap_or_else(|error| panic!("{case}: acquisition refused: {error}"));
    (snapshot, replay.calls.into_inner())
}

/// Record a successful case and check what every executed mainnet recording must carry.
fn recorded(case: &str) -> RecordingBundle {
    let (snapshot, calls) = acquire(case);
    assert_eq!(
        calls,
        ["getNetwork", "getTransaction", "getLedgerEntries"],
        "{case}: the referenced executables must be observed, not skipped"
    );
    let bundle = record(&snapshot, RecordOptions::default())
        .unwrap_or_else(|error| panic!("{case}: recorder refused: {error}"));
    assert_eq!(bundle.trust, TrustLevel::rpc_reported(), "{case}");
    assert_eq!(bundle.execution, Execution::ExecutedSuccess, "{case}");
    assert_eq!(
        bundle.network_id,
        NetworkId::from_passphrase(MAINNET),
        "{case}"
    );
    assert_eq!(
        bundle.ledger,
        Some(LedgerSeq(manifest()[case].ledger)),
        "{case}"
    );
    assert_eq!(
        bundle.operation_index, 0,
        "{case}: a Soroban transaction has one operation"
    );
    assert_eq!(
        bundle.acquisition.as_ref().map(|a| a.protocol_version),
        Some(CAPTURED_PROTOCOL),
        "{case}"
    );
    assert_eq!(
        bundle
            .contract_executables
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        contracts_in_xdr(&envelope(case)),
        "{case}: every contract the invocation and its authorization reach carries its observed \
         executable, and nothing else does"
    );
    assert_eq!(
        bundle.verify().unwrap(),
        bundle.recording_hash().unwrap(),
        "{case}: the recording must rebuild from its own raw evidence"
    );
    // The envelope's authorization entries, each in its place, are what the recording carries.
    let envelope = envelope(case);
    let entries = invocation(&envelope).auth.to_vec();
    assert_eq!(bundle.authorizations.len(), entries.len(), "{case}");
    for (record, entry) in bundle.authorizations.iter().zip(&entries) {
        assert_eq!(record.authorizer, authorizer_of(entry, &envelope), "{case}");
        assert_eq!(record.credential, credential_of(entry), "{case}");
        assert_eq!(
            shape(&record.root),
            xdr_shape(&entry.root_invocation),
            "{case}: the recorded invocation tree must be the authorized one"
        );
        assert!(
            authorized_args_match(&record.root, &entry.root_invocation),
            "{case}: every recorded node must carry the authorized arguments"
        );
    }
    bundle
}

fn envelope(case: &str) -> TransactionEnvelope {
    let text = captured(case, "getTransaction")["envelopeXdr"]
        .as_str()
        .unwrap()
        .to_string();
    TransactionEnvelope::from_xdr_base64(text, xdr_limits()).unwrap()
}

fn inner(envelope: &TransactionEnvelope) -> &Transaction {
    match envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(bump) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = &bump.tx.inner_tx;
            &inner.tx
        }
        TransactionEnvelope::TxV0(_) => panic!("mainnet Soroban evidence is never a V0 envelope"),
    }
}

fn invocation(envelope: &TransactionEnvelope) -> InvokeHostFunctionOp {
    let [operation] = inner(envelope).operations.as_slice() else {
        panic!("a Soroban transaction carries exactly one operation");
    };
    let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
        panic!("the operation is not an InvokeHostFunction");
    };
    invoke.clone()
}

fn invoked(envelope: &TransactionEnvelope) -> InvokeContractArgs {
    let HostFunction::InvokeContract(call) = invocation(envelope).host_function else {
        panic!("the host function is not a contract invocation");
    };
    call
}

fn muxed_strkey(account: &MuxedAccount) -> String {
    let key = match account {
        MuxedAccount::Ed25519(key) => key.0,
        MuxedAccount::MuxedEd25519(muxed) => muxed.ed25519.0,
    };
    format!("{}", stellar_strkey::ed25519::PublicKey(key))
}

fn address_strkey(address: &ScAddress) -> String {
    match address {
        ScAddress::Account(account) => {
            let stellar_xdr::PublicKey::PublicKeyTypeEd25519(key) = &account.0;
            format!("{}", stellar_strkey::ed25519::PublicKey(key.0))
        }
        ScAddress::Contract(contract) => format!("{}", stellar_strkey::Contract(contract.0 .0)),
        other => panic!("no corpus case authorizes as {other:?}"),
    }
}

fn authorizer_of(
    entry: &stellar_xdr::SorobanAuthorizationEntry,
    envelope: &TransactionEnvelope,
) -> String {
    match &entry.credentials {
        SorobanCredentials::SourceAccount => muxed_strkey(&inner(envelope).source_account),
        SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => {
            address_strkey(&c.address)
        }
        SorobanCredentials::AddressWithDelegates(c) => {
            address_strkey(&c.address_credentials.address)
        }
    }
}

/// The credential arm and its policy-relevant fields, read straight from the entry's XDR.
fn credential_of(entry: &stellar_xdr::SorobanAuthorizationEntry) -> CredentialRecord {
    fn delegates(list: &[stellar_xdr::SorobanDelegateSignature]) -> u32 {
        list.iter()
            .map(|d| 1 + delegates(&d.nested_delegates))
            .sum()
    }
    match &entry.credentials {
        SorobanCredentials::SourceAccount => CredentialRecord::SourceAccount,
        SorobanCredentials::Address(c) => CredentialRecord::Address {
            nonce: c.nonce,
            signature_expiration_ledger: c.signature_expiration_ledger,
        },
        SorobanCredentials::AddressV2(c) => CredentialRecord::AddressV2 {
            nonce: c.nonce,
            signature_expiration_ledger: c.signature_expiration_ledger,
        },
        SorobanCredentials::AddressWithDelegates(c) => CredentialRecord::AddressWithDelegates {
            nonce: c.address_credentials.nonce,
            signature_expiration_ledger: c.address_credentials.signature_expiration_ledger,
            delegate_count: delegates(&c.delegates),
        },
    }
}

/// Every contract the invocation and its authorization entries name: the invoked contract,
/// contract authorizers, and every contract call in every authorized tree.
fn contracts_in_xdr(envelope: &TransactionEnvelope) -> BTreeSet<String> {
    fn walk(node: &SorobanAuthorizedInvocation, into: &mut BTreeSet<String>) {
        if let SorobanAuthorizedFunction::ContractFn(call) = &node.function {
            if let ScAddress::Contract(_) = call.contract_address {
                into.insert(address_strkey(&call.contract_address));
            }
        }
        for child in node.sub_invocations.iter() {
            walk(child, into);
        }
    }
    let invoke = invocation(envelope);
    let mut contracts = BTreeSet::new();
    if let HostFunction::InvokeContract(call) = &invoke.host_function {
        contracts.insert(address_strkey(&call.contract_address));
    }
    for entry in invoke.auth.iter() {
        let address = match &entry.credentials {
            SorobanCredentials::SourceAccount => None,
            SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => Some(&c.address),
            SorobanCredentials::AddressWithDelegates(c) => Some(&c.address_credentials.address),
        };
        if let Some(address @ ScAddress::Contract(_)) = address {
            contracts.insert(address_strkey(address));
        }
        walk(&entry.root_invocation, &mut contracts);
    }
    contracts
}

fn call(node: &InvocationNode) -> (&str, &str, &[ArgSummary]) {
    match &node.call {
        AuthorizedCall::Contract {
            contract,
            fn_name,
            args,
        } => (contract, fn_name, args),
        AuthorizedCall::CreateContract => ("", "create_contract", &[]),
    }
}

/// `contract.fn(child, child)` for a recorded tree, comparable with [`xdr_shape`].
fn shape(node: &InvocationNode) -> String {
    let (contract, function, _) = call(node);
    let children: Vec<String> = node.sub_invocations.iter().map(shape).collect();
    format!("{contract}.{function}({})", children.join(","))
}

fn xdr_shape(node: &SorobanAuthorizedInvocation) -> String {
    let head = match &node.function {
        SorobanAuthorizedFunction::ContractFn(args) => format!(
            "{}.{}",
            address_strkey(&args.contract_address),
            args.function_name.to_utf8_string_lossy()
        ),
        _ => ".create_contract".to_string(),
    };
    let children: Vec<String> = node.sub_invocations.iter().map(xdr_shape).collect();
    format!("{head}({})", children.join(","))
}

/// Whether a recorded argument summary says exactly what an XDR value says.
fn summarizes(summary: &ArgSummary, value: &ScVal) -> bool {
    match (summary, value) {
        (ArgSummary::Address(text), ScVal::Address(address)) => *text == address_strkey(address),
        (ArgSummary::I128(n), ScVal::I128(parts)) => {
            *n == (i128::from(parts.hi) << 64) | i128::from(parts.lo)
        }
        (ArgSummary::U64(n), ScVal::U64(m)) => n == m,
        (ArgSummary::U32(n), ScVal::U32(m)) => n == m,
        (ArgSummary::Symbol(text), ScVal::Symbol(symbol)) => *text == symbol.to_utf8_string_lossy(),
        // The recorder types these five kinds; one of them kept only as raw XDR is a regression.
        (
            ArgSummary::Other { .. },
            ScVal::Address(_) | ScVal::I128(_) | ScVal::U64(_) | ScVal::U32(_) | ScVal::Symbol(_),
        ) => false,
        (ArgSummary::Other { xdr_base64 }, value) => {
            *xdr_base64 == value.to_xdr_base64(xdr_limits()).unwrap()
        }
        _ => false,
    }
}

fn args_match(summaries: &[ArgSummary], values: &[ScVal]) -> bool {
    summaries.len() == values.len()
        && summaries
            .iter()
            .zip(values)
            .all(|(summary, value)| summarizes(summary, value))
}

fn authorized_args_match(node: &InvocationNode, xdr: &SorobanAuthorizedInvocation) -> bool {
    let (_, _, args) = call(node);
    let values: &[ScVal] = match &xdr.function {
        SorobanAuthorizedFunction::ContractFn(call) => &call.args,
        _ => &[],
    };
    args_match(args, values)
        && node
            .sub_invocations
            .iter()
            .zip(xdr.sub_invocations.iter())
            .all(|(node, xdr)| authorized_args_match(node, xdr))
}

fn nodes(node: &InvocationNode) -> Vec<&InvocationNode> {
    let mut all = vec![node];
    for child in &node.sub_invocations {
        all.extend(nodes(child));
    }
    all
}

fn expiration(credential: &CredentialRecord) -> Option<u32> {
    match credential {
        CredentialRecord::SourceAccount => None,
        CredentialRecord::Address {
            signature_expiration_ledger,
            ..
        }
        | CredentialRecord::AddressV2 {
            signature_expiration_ledger,
            ..
        }
        | CredentialRecord::AddressWithDelegates {
            signature_expiration_ledger,
            ..
        } => Some(*signature_expiration_ledger),
    }
}

/// The OpenZeppelin delegated-signer shape: a G-account's own entry authorizes another
/// authorizer's `__check_auth`. It is a separate authorization the recording keeps, and never
/// the account the grant is for.
fn delegates_to_check_auth(bundle: &RecordingBundle) -> Vec<(&str, &str)> {
    let authorizers: BTreeSet<&str> = bundle
        .authorizations
        .iter()
        .map(|a| a.authorizer.as_str())
        .collect();
    bundle
        .authorizations
        .iter()
        .filter_map(|a| {
            let (contract, function, _) = call(&a.root);
            (a.authorizer.starts_with('G')
                && function == "__check_auth"
                && authorizers.contains(contract))
            .then_some((a.authorizer.as_str(), contract))
        })
        .collect()
}

#[test]
fn the_manifest_names_exactly_the_captured_transactions() {
    let manifest = manifest();
    let on_disk: BTreeSet<String> = std::fs::read_dir(corpus())
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        manifest.keys().cloned().collect::<BTreeSet<_>>(),
        on_disk,
        "every captured directory is a manifest case and every case was captured"
    );
    let header = read(corpus().join("manifest.json"));
    assert_eq!(header["network_passphrase"], MAINNET);
    assert_eq!(header["protocol_version"], CAPTURED_PROTOCOL);
    for (case, entry) in &manifest {
        let network = captured(case, "getNetwork");
        assert_eq!(network["passphrase"], MAINNET, "{case}");
        assert_eq!(network["protocolVersion"], CAPTURED_PROTOCOL, "{case}");
        let tx = captured(case, "getTransaction");
        assert_eq!(tx["txHash"], entry.tx_hash.as_str(), "{case}");
        assert_eq!(tx["ledger"], entry.ledger, "{case}");
        assert_eq!(tx["status"], entry.status.as_str(), "{case}");
    }
}

/// Mainnet now emits meta v4 (protocol 23) for classic and Soroban transactions alike, so public
/// RPC, within its retention window, offers no v3 to capture. The v3 path stays covered by the
/// recorder's synthetic fixtures; this pins that the real corpus exercises v4 and that nothing in
/// it is a version the recorder refuses.
#[test]
fn every_mainnet_meta_is_v4() {
    for case in manifest().keys() {
        let meta = captured(case, "getTransaction")["resultMetaXdr"]
            .as_str()
            .unwrap()
            .to_string();
        let meta = TransactionMeta::from_xdr_base64(meta, xdr_limits()).unwrap();
        assert!(matches!(meta, TransactionMeta::V4(_)), "{case}");
    }
}

#[test]
fn a_fee_bumped_sac_transfer_resolves_the_source_account_credential_to_the_inner_source() {
    let case = "sac-transfer-source-account";
    let bundle = recorded(case);
    let envelope = envelope(case);
    // Fee-bumped on purpose: with two sources in the envelope, only resolving the credential to
    // the inner transaction's source passes. A plain envelope could not tell the two apart.
    let TransactionEnvelope::TxFeeBump(bump) = &envelope else {
        panic!("the case is a fee-bumped transfer");
    };
    let fee_source = muxed_strkey(&bump.tx.fee_source);
    let inner_source = muxed_strkey(&inner(&envelope).source_account);
    assert_ne!(fee_source, inner_source, "the fee payer is another account");
    let [authorization] = bundle.authorizations.as_slice() else {
        panic!("one authorizer");
    };
    assert_eq!(authorization.credential, CredentialRecord::SourceAccount);
    assert_eq!(authorization.authorizer, inner_source);
    let (token, function, args) = call(&authorization.root);
    assert_eq!(function, "transfer");
    assert!(authorization.root.sub_invocations.is_empty());
    assert_eq!(
        bundle.contract_executables[token].executable,
        ObservedExecutable::StellarAsset,
        "the invoked token is a Stellar Asset Contract"
    );
    let [ArgSummary::Address(from), ArgSummary::Address(to), ArgSummary::I128(amount)] = args
    else {
        panic!("transfer(from, to, amount): {args:?}");
    };
    assert_eq!(*from, authorization.authorizer);
    // A plain transfer authorizes exactly what it is called with — the control for the
    // divergence case below, which proves the comparison can tell the two apart.
    assert!(args_match(args, &invoked(&envelope).args));
    let [movement] = bundle.token_movements.as_slice() else {
        panic!("one movement: {:?}", bundle.token_movements);
    };
    assert_eq!(movement.kind, MovementKind::Transfer);
    assert_eq!(movement.token_contract.as_deref(), Some(token));
    assert_eq!(movement.from.as_deref(), Some(from.as_str()));
    assert_eq!(movement.to.as_deref(), Some(to.as_str()));
    assert_eq!(movement.amount, Some(*amount));
}

#[test]
fn a_classic_account_address_credential_is_recorded_as_an_address_credential() {
    let case = "classic-address-credential";
    let bundle = recorded(case);
    let envelope = envelope(case);
    let [authorization] = bundle.authorizations.as_slice() else {
        panic!("one authorizer");
    };
    assert!(authorization.authorizer.starts_with('G'));
    assert_ne!(
        authorization.authorizer,
        muxed_strkey(&inner(&envelope).source_account),
        "the authorizer signed an entry; someone else submitted the transaction"
    );
    let SorobanCredentials::Address(xdr) = &invocation(&envelope).auth[0].credentials else {
        panic!("the captured entry is an Address credential");
    };
    assert_eq!(
        authorization.credential,
        CredentialRecord::Address {
            nonce: xdr.nonce,
            signature_expiration_ledger: xdr.signature_expiration_ledger,
        }
    );
    // The network applied it at this ledger, so it had not expired before it.
    assert!(xdr.signature_expiration_ledger >= manifest()[case].ledger);
}

#[test]
fn a_smart_account_authorization_records_the_account_and_its_observed_code() {
    let case = "smart-account-credential";
    let bundle = recorded(case);
    let accounts: Vec<&AuthorizationRecord> = bundle
        .authorizations
        .iter()
        .filter(|a| a.authorizer.starts_with('C'))
        .collect();
    let [account] = accounts.as_slice() else {
        panic!("one smart-account authorizer");
    };
    assert!(
        matches!(
            account.credential,
            CredentialRecord::Address { .. } | CredentialRecord::AddressV2 { .. }
        ),
        "a contract cannot be a transaction source, so it authorizes by address credential"
    );
    // The code that ran `__check_auth` is observed by hash: what account recognition keys on.
    assert!(matches!(
        bundle.contract_executables[&account.authorizer].executable,
        ObservedExecutable::Wasm { .. }
    ));
    // The account authorized a call into another contract, and beneath it a transfer out of
    // itself: the shape a spending policy is written against.
    let (target, _, _) = call(&account.root);
    assert_ne!(target, account.authorizer);
    let transfer = nodes(&account.root)
        .into_iter()
        .skip(1)
        .find(|node| call(node).1 == "transfer")
        .expect("a nested token transfer");
    let (token, _, args) = call(transfer);
    assert!(matches!(&args[0], ArgSummary::Address(from) if *from == account.authorizer));
    assert!(bundle
        .token_movements
        .iter()
        .any(|m| m.token_contract.as_deref() == Some(token)
            && m.from.as_deref() == Some(account.authorizer.as_str())));
}

#[test]
fn a_nested_authorization_tree_keeps_its_shape_and_observes_every_contract() {
    let case = "nested-auth-tree";
    let bundle = recorded(case);
    let nested: Vec<&AuthorizationRecord> = bundle
        .authorizations
        .iter()
        .filter(|a| !a.root.sub_invocations.is_empty())
        .collect();
    assert!(!nested.is_empty(), "the case is a nested tree");
    for authorization in nested {
        for node in nodes(&authorization.root) {
            let (contract, _, _) = call(node);
            assert!(
                bundle.contract_executables.contains_key(contract),
                "{contract} is in the authorized tree but its executable was not observed"
            );
        }
    }
}

#[test]
fn a_fee_bump_records_the_inner_authorizer_and_the_inner_result() {
    let case = "fee-bump-invocation";
    let bundle = recorded(case);
    let envelope = envelope(case);
    let TransactionEnvelope::TxFeeBump(bump) = &envelope else {
        panic!("the case is a fee-bump envelope");
    };
    let fee_source = muxed_strkey(&bump.tx.fee_source);
    assert_ne!(fee_source, muxed_strkey(&inner(&envelope).source_account));
    assert!(
        bundle
            .authorizations
            .iter()
            .all(|a| a.authorizer != fee_source),
        "the fee payer authorizes nothing in the invocation"
    );
    let result = TransactionResult::from_xdr_base64(
        bundle.raw.result_xdr_base64.as_deref().unwrap(),
        xdr_limits(),
    )
    .unwrap();
    assert!(matches!(
        result.result,
        TransactionResultResult::TxFeeBumpInnerSuccess(_)
    ));
}

#[test]
fn a_failed_mainnet_invocation_is_refused_unless_failure_analysis_is_asked_for() {
    let case = "failed-invocation";
    let (snapshot, calls) = acquire(case);
    assert_eq!(calls, ["getNetwork", "getTransaction", "getLedgerEntries"]);
    let refused = record(&snapshot, RecordOptions::default()).unwrap_err();
    assert_eq!(refused, RecordError::TxFailed);
    assert!(refused.to_string().starts_with("E_TX_FAILED:"), "{refused}");

    let analysed = record(
        &snapshot,
        RecordOptions {
            allow_failed: true,
            ..RecordOptions::default()
        },
    )
    .unwrap();
    assert_eq!(analysed.execution, Execution::ExecutedFailed);
    assert_eq!(analysed.trust, TrustLevel::rpc_reported());
    assert_eq!(
        analysed.verify().unwrap(),
        analysed.recording_hash().unwrap()
    );
    // The preserved result says which operation failed and how; a failed invocation emits no
    // events, so no movement is typed from it.
    let result = TransactionResult::from_xdr_base64(
        analysed.raw.result_xdr_base64.as_deref().unwrap(),
        xdr_limits(),
    )
    .unwrap();
    let TransactionResultResult::TxFailed(operations) = result.result else {
        panic!("a plain envelope that failed in its operation");
    };
    assert!(matches!(
        operations.as_slice(),
        [OperationResult::OpInner(OperationResultTr::InvokeHostFunction(outcome))]
            if !matches!(outcome, InvokeHostFunctionResult::Success(_))
    ));
    assert!(analysed.token_movements.is_empty());
}

#[test]
fn a_classic_multi_operation_transaction_has_no_invocation_to_select() {
    let case = "classic-multi-operation";
    let (snapshot, calls) = acquire(case);
    assert_eq!(
        calls,
        ["getNetwork", "getTransaction"],
        "no contract is referenced, so no instance is read"
    );
    let operations = inner(&envelope(case)).operations.len();
    assert!(operations >= 2);
    assert_eq!(
        record(&snapshot, RecordOptions::default()).unwrap_err(),
        RecordError::NoSorobanOp
    );
    // Selecting an operation cannot turn a classic one into an invocation.
    for index in 0..operations as u32 {
        let refused = record(
            &snapshot,
            RecordOptions {
                operation_index: Some(index),
                ..RecordOptions::default()
            },
        )
        .unwrap_err();
        assert_eq!(refused, RecordError::NoSorobanOp, "operation {index}");
        assert!(refused.to_string().starts_with("E_NO_SOROBAN_OP:"));
    }
}

#[test]
fn every_authorizer_is_carried_for_synthesis_to_select() {
    let case = "multi-authorizer";
    let bundle = recorded(case);
    let authorizers: BTreeSet<&str> = bundle
        .authorizations
        .iter()
        .map(|a| a.authorizer.as_str())
        .collect();
    assert!(authorizers.len() >= 2, "{authorizers:?}");
    let fingerprints: BTreeSet<_> = bundle
        .authorizations
        .iter()
        .map(|a| a.fingerprint)
        .collect();
    assert_eq!(fingerprints.len(), bundle.authorizations.len());
    assert!(
        !delegates_to_check_auth(&bundle).is_empty(),
        "the captured case is a delegated signer approving a smart account's __check_auth"
    );
}

#[test]
fn authorized_arguments_are_recorded_not_the_invoked_ones() {
    let case = "auth-args-divergence";
    let bundle = recorded(case);
    let call_args = invoked(&envelope(case));
    let invoked_contract = address_strkey(&call_args.contract_address);
    let invoked_function = call_args.function_name.to_utf8_string_lossy();
    let diverging: Vec<&AuthorizationRecord> = bundle
        .authorizations
        .iter()
        .filter(|a| {
            let (contract, function, _) = call(&a.root);
            contract == invoked_contract && function == invoked_function
        })
        .collect();
    let [authorization] = diverging.as_slice() else {
        panic!("one authorization for the invoked function");
    };
    // `recorded` already checked the recorded arguments are the authorized ones; here they are
    // also not the arguments the function was called with (`require_auth_for_args`).
    let (_, _, recorded_args) = call(&authorization.root);
    assert!(!args_match(recorded_args, &call_args.args));
}

#[test]
fn address_v2_credentials_are_recorded_by_arm() {
    let case = "credential-address-v2";
    let bundle = recorded(case);
    let entries = invocation(&envelope(case)).auth.to_vec();
    for (authorization, entry) in bundle.authorizations.iter().zip(&entries) {
        let SorobanCredentials::AddressV2(xdr) = &entry.credentials else {
            panic!("every captured entry is AddressV2");
        };
        assert_eq!(
            authorization.credential,
            CredentialRecord::AddressV2 {
                nonce: xdr.nonce,
                signature_expiration_ledger: xdr.signature_expiration_ledger,
            }
        );
        assert!(expiration(&authorization.credential).unwrap() >= manifest()[case].ledger);
    }
    let delegated = delegates_to_check_auth(&bundle);
    assert!(!delegated.is_empty());
    for (_, account) in delegated {
        assert!(matches!(
            bundle.contract_executables[account].executable,
            ObservedExecutable::Wasm { .. }
        ));
    }
}

/// The same raw evidence imported through `source-bundle` rather than fetched decodes
/// identically but carries the import's label: `self_supplied` when the result backs the
/// claimed outcome, `incomplete` without it — never the RPC label, and without the RPC's
/// executable observations.
#[test]
fn the_same_mainnet_evidence_imported_is_labelled_by_its_acquisition() {
    let case = "smart-account-credential";
    let fetched = recorded(case);
    let tx = captured(case, "getTransaction");
    let text = |field: &str| tx[field].as_str().unwrap().to_string();
    let import = |result: Option<String>| {
        let document = serde_json::to_string(&ImportedBundle {
            network_passphrase: MAINNET.to_string(),
            envelope_xdr_base64: text("envelopeXdr"),
            result_meta_xdr_base64: Some(text("resultMetaXdr")),
            result_xdr_base64: result,
            ledger: Some(manifest()[case].ledger),
            created_at_unix: Some(text("createdAt").parse().unwrap()),
            successful: true,
        })
        .unwrap();
        import_json(&document).unwrap()
    };
    let imported = record(&import(Some(text("resultXdr"))), RecordOptions::default()).unwrap();
    assert_eq!(imported.trust, TrustLevel::self_supplied());
    assert_eq!(imported.authorizations, fetched.authorizations);
    assert_eq!(imported.token_movements, fetched.token_movements);
    assert!(imported.contract_executables.is_empty());
    assert!(imported.acquisition.is_none());
    assert_ne!(
        imported.recording_hash().unwrap(),
        fetched.recording_hash().unwrap()
    );

    let unbacked = record(&import(None), RecordOptions::default()).unwrap();
    assert_eq!(unbacked.trust, TrustLevel::incomplete());
}
