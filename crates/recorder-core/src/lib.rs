//! Pure recorder core (architecture §4.1, §4.11).
//!
//! Acquisition adapters (`source-rpc`, `source-bundle`) produce immutable, trust-labeled
//! [`EvidenceSnapshot`]s; this crate is a pure function over snapshots:
//! `record(snapshot, options) -> RecordingBundle`. No I/O, no async.
//!
//! Enforcement facts come exclusively from the authorization entries (what
//! `__check_auth` will see); token movements and state diffs are explanatory evidence.
//! Args in an auth entry are what was *authorized* (`require_auth_for_args` may differ
//! from the actual call args) and are labeled as such.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use ozpb_domain::{domains, Hash32, LedgerSeq, NetworkId, TrustLevel, CANONICALIZATION_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stellar_xdr::{
    ContractEvent, ContractEventBody, HostFunction, Limits, OperationBody, ReadXdr, ScAddress,
    ScBytes, ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, TransactionMeta,
    WriteXdr,
};

pub const RECORDING_SCHEMA: &str = "recording/v1";
// Soroban transactions and ledger entries are far smaller than this in practice. Keep a
// defensive per-value bound, then separately cap the total encoded evidence below the canonical
// hash preimage ceiling. This makes every accepted recording hashable instead of discovering an
// incompatible 4 MiB limit only after decoding and summarizing it.
const MAX_XDR_BYTES: usize = 512 * 1024;
const MAX_XDR_BASE64_BYTES: usize = MAX_XDR_BYTES.div_ceil(3) * 4;
const MAX_TOTAL_EVIDENCE_BASE64_BYTES: usize = 1024 * 1024;
const MAX_XDR_DEPTH: u32 = 128;
const MAX_SIMULATED_AUTH_ENTRIES: usize = 256;
const MAX_SIMULATED_STATE_CHANGES: usize = 4_096;

fn xdr_limits() -> Limits {
    Limits {
        depth: MAX_XDR_DEPTH,
        len: MAX_XDR_BYTES,
    }
}

// ---------------------------------------------------------------------------------------
// EvidenceSnapshot — produced only by acquisition adapters; trust is derived by the
// constructor for each acquisition path, never selectable by a caller (§4.1).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct EvidenceSnapshot {
    network_passphrase: String,
    envelope_xdr_base64: String,
    result_meta_xdr_base64: Option<String>,
    /// Auth entries returned by `simulateTransaction` in record mode (unsigned).
    simulated_auth_xdr_base64: Vec<String>,
    simulated_state_changes: Vec<StateChange>,
    contract_executables: BTreeMap<String, ExecutableObservation>,
    ledger: Option<u32>,
    created_at_unix: Option<i64>,
    execution: Execution,
    trust: TrustLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Execution {
    ExecutedSuccess,
    ExecutedFailed,
    Simulated,
}

impl EvidenceSnapshot {
    /// An executed transaction fetched live from the configured RPC (`rpc_reported`).
    pub fn from_rpc_transaction(
        network_passphrase: impl Into<String>,
        envelope_xdr_base64: impl Into<String>,
        result_meta_xdr_base64: Option<String>,
        ledger: u32,
        created_at_unix: i64,
        successful: bool,
    ) -> Self {
        EvidenceSnapshot {
            network_passphrase: network_passphrase.into(),
            envelope_xdr_base64: envelope_xdr_base64.into(),
            result_meta_xdr_base64,
            simulated_auth_xdr_base64: vec![],
            simulated_state_changes: vec![],
            contract_executables: BTreeMap::new(),
            ledger: Some(ledger),
            created_at_unix: Some(created_at_unix),
            execution: if successful {
                Execution::ExecutedSuccess
            } else {
                Execution::ExecutedFailed
            },
            trust: TrustLevel::rpc_reported(),
        }
    }

    /// A local simulation acquired via RPC `simulateTransaction` with `authMode: record`
    /// (`rpc_reported`; confidential input — §6.5).
    pub fn from_rpc_simulation(
        network_passphrase: impl Into<String>,
        envelope_xdr_base64: impl Into<String>,
        simulated_auth_xdr_base64: Vec<String>,
        latest_ledger: Option<u32>,
    ) -> Self {
        EvidenceSnapshot {
            network_passphrase: network_passphrase.into(),
            envelope_xdr_base64: envelope_xdr_base64.into(),
            result_meta_xdr_base64: None,
            simulated_auth_xdr_base64,
            simulated_state_changes: vec![],
            contract_executables: BTreeMap::new(),
            ledger: latest_ledger,
            created_at_unix: None,
            execution: Execution::Simulated,
            trust: TrustLevel::rpc_reported(),
        }
    }

    /// A user-imported raw evidence bundle: internally consistent but unverified
    /// (`self_supplied`). Never described as a verified executed transaction.
    pub fn from_import(
        network_passphrase: impl Into<String>,
        envelope_xdr_base64: impl Into<String>,
        result_meta_xdr_base64: Option<String>,
        ledger: Option<u32>,
        created_at_unix: Option<i64>,
        successful: bool,
    ) -> Self {
        EvidenceSnapshot {
            network_passphrase: network_passphrase.into(),
            envelope_xdr_base64: envelope_xdr_base64.into(),
            result_meta_xdr_base64,
            simulated_auth_xdr_base64: vec![],
            simulated_state_changes: vec![],
            contract_executables: BTreeMap::new(),
            ledger,
            created_at_unix,
            execution: if successful {
                Execution::ExecutedSuccess
            } else {
                Execution::ExecutedFailed
            },
            trust: TrustLevel::self_supplied(),
        }
    }

    pub fn trust(&self) -> TrustLevel {
        self.trust
    }

    /// Attach state changes parsed by the RPC acquisition adapter. Kept separate from the
    /// public constructor so existing callers cannot accidentally confuse meta-derived and
    /// simulation-derived evidence.
    pub fn with_simulated_state_changes(mut self, changes: Vec<StateChange>) -> Self {
        self.simulated_state_changes = changes;
        self
    }

    /// Attach executable observations acquired from `getLedgerEntries` at a known ledger.
    /// The map key is the contract strkey; `BTreeMap` provides canonical ordering for hashes.
    pub fn with_contract_executables(
        mut self,
        observations: BTreeMap<String, ExecutableObservation>,
    ) -> Self {
        self.contract_executables = observations;
        self
    }
}

// ---------------------------------------------------------------------------------------
// RecordingBundle
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingBundle {
    /// Schema identifier. Named `schema` rather than `$schema`: the value is a plain
    /// identifier, not a JSON-Schema URI, and `$` is not a legal `Symbol` character, so the
    /// old name could not be encoded in a canonical preimage at all.
    pub schema: String,
    pub canonicalization_version: u32,
    pub network_id: NetworkId,
    pub trust: TrustLevel,
    pub execution: Execution,
    pub ledger: Option<LedgerSeq>,
    pub created_at_unix: Option<i64>,
    pub operation_index: u32,
    /// One record per address-level authorization entry.
    pub authorizations: Vec<AuthorizationRecord>,
    /// Explanatory evidence only — never drives constraints automatically.
    pub token_movements: Vec<TokenMovement>,
    /// Ledger-entry state changes (created/updated/removed/restored). Explanatory
    /// evidence only — like token movements, these are never turned into constraints
    /// (effects can't be reliably attributed to a specific authorization; §4.1).
    pub state_changes: Vec<StateChange>,
    /// Contract executable/code hashes captured by the acquisition adapter. This is the
    /// evidence used to bind account recognition and code-hash-specific adapters.
    pub contract_executables: BTreeMap<String, ExecutableObservation>,
    /// Effects that could not be decoded/attributed; preserved, labeled, never guessed at.
    pub evidence_notes: Vec<String>,
    /// Raw evidence is always preserved — decoding never replaces it.
    pub raw: RawEvidence,
}

/// A summarized ledger-entry change from transaction meta (evidence only).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateChange {
    pub kind: StateChangeKind,
    /// The kind of ledger entry affected (contract_data / contract_code / account / …).
    pub entry: String,
    /// For contract-data entries, the owning contract (strkey), if resolvable.
    pub contract: Option<String>,
    /// Which meta section this change came from.
    pub source: StateChangeSource,
    /// Exact simulation evidence, when the source is `simulation`. Meta-derived entries use
    /// their decoded ledger-key summary and leave these fields empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_xdr_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_xdr_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_xdr_base64: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableObservation {
    pub executable: ObservedExecutable,
    pub observed_ledger: LedgerSeq,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedExecutable {
    Wasm { code_hash: Hash32 },
    StellarAsset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateChangeKind {
    Created,
    Updated,
    Removed,
    /// The pre-image `State` half of a `State → Updated` pair (recorded for completeness).
    State,
    /// Protocol 23+: an archived entry restored during application.
    Restored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateChangeSource {
    TxChangesBefore,
    Operation,
    TxChangesAfter,
    Simulation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawEvidence {
    pub envelope_xdr_base64: String,
    pub result_meta_xdr_base64: Option<String>,
    pub simulated_auth_xdr_base64: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    /// The authorizing address (strkey).
    pub authorizer: String,
    pub credential: CredentialRecord,
    /// Replay-invariant authorization fingerprint:
    /// `H(domain, authorizer XDR || root_invocation XDR)`. Identical for the same
    /// authorized shape whether executed or simulated.
    pub fingerprint: Hash32,
    pub root: InvocationNode,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialRecord {
    SourceAccount,
    Address {
        nonce: i64,
        signature_expiration_ledger: u32,
    },
    /// Protocol 27 (CAP-71): address-bound signature payload.
    AddressV2 {
        nonce: i64,
        signature_expiration_ledger: u32,
    },
    /// Protocol 27 (CAP-71): delegate signature tree (recursively counted).
    AddressWithDelegates {
        nonce: i64,
        signature_expiration_ledger: u32,
        delegate_count: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationNode {
    pub call: AuthorizedCall,
    pub sub_invocations: Vec<InvocationNode>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizedCall {
    Contract {
        contract: String,
        fn_name: String,
        /// The AUTHORIZED args (`require_auth_for_args` may expose a subset or transform
        /// of the actual call args — never assume equality).
        args: Vec<ArgSummary>,
    },
    CreateContract,
}

/// Decoded argument summary. Anything outside the simple shapes keeps its exact
/// canonical XDR so no information is lost.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ArgSummary {
    Address(String),
    I128(i128),
    U64(u64),
    U32(u32),
    Symbol(String),
    Other { xdr_base64: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenMovement {
    pub kind: MovementKind,
    pub token_contract: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spender: Option<String>,
    pub amount: Option<i128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_ledger: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementKind {
    Transfer,
    Mint,
    Burn,
    Approve,
}

impl RecordingBundle {
    /// Full recording hash: canonicalization version + the complete canonical bundle
    /// (raw XDR, anchors, decoded evidence, trust, schema) under the recording domain.
    pub fn recording_hash(&self) -> Result<Hash32, RecordError> {
        ozpb_domain::canonical_hash(domains::RECORDING, self)
            .map_err(|e| RecordError::Internal(e.to_string()))
    }
}

// ---------------------------------------------------------------------------------------
// Errors — stable machine-readable codes (architecture §4.6)
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("E_ENVELOPE_PARSE: {0}")]
    EnvelopeParse(String),
    #[error("E_UNSUPPORTED_ENVELOPE: {0}")]
    UnsupportedEnvelope(String),
    #[error("E_NO_SOROBAN_OP: transaction contains no InvokeHostFunction operation")]
    NoSorobanOp,
    #[error(
        "E_OPERATION_SELECTION: transaction has {0} InvokeHostFunction operations; \
         explicit operation_index required"
    )]
    OperationSelection(usize),
    #[error(
        "E_TX_FAILED: transaction failed on-chain; failed executions are not behavior \
         examples (pass allow_failed for failure analysis)"
    )]
    TxFailed,
    #[error("E_UNSUPPORTED_META_VERSION: meta v{0} is not a Soroban meta version")]
    UnsupportedMetaVersion(i32),
    #[error("E_META_PARSE: {0}")]
    MetaParse(String),
    #[error("E_UNSUPPORTED_ADDRESS: {0}")]
    UnsupportedAddress(String),
    #[error("E_AUTH_PARSE: {0}")]
    AuthParse(String),
    #[error("E_RESOURCE_LIMIT: {0}")]
    ResourceLimit(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RecordOptions {
    /// Required when the transaction has more than one InvokeHostFunction operation.
    pub operation_index: Option<u32>,
    /// Failure-analysis mode: explicitly opt in to record a failed transaction.
    pub allow_failed: bool,
}

// ---------------------------------------------------------------------------------------
// record(): the pure core
// ---------------------------------------------------------------------------------------

pub fn record(
    snapshot: &EvidenceSnapshot,
    options: RecordOptions,
) -> Result<RecordingBundle, RecordError> {
    validate_evidence_limits(snapshot)?;

    if snapshot.execution == Execution::ExecutedFailed && !options.allow_failed {
        return Err(RecordError::TxFailed);
    }

    let envelope =
        TransactionEnvelope::from_xdr_base64(&snapshot.envelope_xdr_base64, xdr_limits())
            .map_err(|e| map_xdr_parse_error("envelope", e, RecordError::EnvelopeParse))?;

    // Fee-bump envelopes are unwrapped explicitly; V0 envelopes predate Soroban.
    let tx = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(fb) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
            &inner.tx
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(RecordError::UnsupportedEnvelope(
                "TransactionV0 envelopes cannot carry Soroban operations".to_string(),
            ))
        }
    };

    // Locate InvokeHostFunction operations; multi-op requires explicit selection.
    let soroban_ops: Vec<(u32, &stellar_xdr::InvokeHostFunctionOp)> = tx
        .operations
        .iter()
        .enumerate()
        .filter_map(|(i, op)| match &op.body {
            OperationBody::InvokeHostFunction(ihf) => Some((i as u32, ihf)),
            _ => None,
        })
        .collect();

    let (operation_index, op) = match (soroban_ops.len(), options.operation_index) {
        (0, _) => return Err(RecordError::NoSorobanOp),
        (1, None) => soroban_ops[0],
        (n, None) => return Err(RecordError::OperationSelection(n)),
        (_, Some(want)) => *soroban_ops
            .iter()
            .find(|(i, _)| *i == want)
            .ok_or(RecordError::NoSorobanOp)?,
    };

    // Auth entries: executed txs carry them in the envelope; simulations supply them
    // from the RPC record-mode response. Same XDR type either way.
    let auth_entries: Vec<SorobanAuthorizationEntry> = if snapshot.execution == Execution::Simulated
    {
        snapshot
            .simulated_auth_xdr_base64
            .iter()
            .map(|b64| {
                SorobanAuthorizationEntry::from_xdr_base64(b64, xdr_limits())
                    .map_err(|e| map_xdr_parse_error("authorization", e, RecordError::AuthParse))
            })
            .collect::<Result<_, _>>()?
    } else {
        op.auth.iter().cloned().collect()
    };

    let mut authorizations = Vec::new();
    let mut evidence_notes = Vec::new();
    for entry in &auth_entries {
        authorizations.push(decode_auth_entry(entry, tx, op)?);
    }

    // Token movements + state changes from meta (evidence only). Tolerant: undecodable
    // events become notes, never guesses.
    let mut token_movements = Vec::new();
    let mut state_changes = snapshot.simulated_state_changes.clone();
    if let Some(meta_b64) = &snapshot.result_meta_xdr_base64 {
        let meta = TransactionMeta::from_xdr_base64(meta_b64, xdr_limits())
            .map_err(|e| map_xdr_parse_error("result meta", e, RecordError::MetaParse))?;
        let events = match &meta {
            TransactionMeta::V3(v3) => {
                collect_changes(
                    &v3.tx_changes_before,
                    StateChangeSource::TxChangesBefore,
                    &mut state_changes,
                );
                if let Some(om) = v3.operations.get(operation_index as usize) {
                    collect_changes(
                        &om.changes,
                        StateChangeSource::Operation,
                        &mut state_changes,
                    );
                }
                collect_changes(
                    &v3.tx_changes_after,
                    StateChangeSource::TxChangesAfter,
                    &mut state_changes,
                );
                v3.soroban_meta
                    .as_ref()
                    .map(|sm| sm.events.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
            }
            TransactionMeta::V4(v4) => {
                collect_changes(
                    &v4.tx_changes_before,
                    StateChangeSource::TxChangesBefore,
                    &mut state_changes,
                );
                if let Some(om) = v4.operations.get(operation_index as usize) {
                    collect_changes(
                        &om.changes,
                        StateChangeSource::Operation,
                        &mut state_changes,
                    );
                }
                collect_changes(
                    &v4.tx_changes_after,
                    StateChangeSource::TxChangesAfter,
                    &mut state_changes,
                );
                v4.operations
                    .get(operation_index as usize)
                    .map(|om| om.events.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
            }
            TransactionMeta::V0(_) => return Err(RecordError::UnsupportedMetaVersion(0)),
            TransactionMeta::V1(_) => return Err(RecordError::UnsupportedMetaVersion(1)),
            TransactionMeta::V2(_) => return Err(RecordError::UnsupportedMetaVersion(2)),
        };
        for ev in &events {
            match decode_token_event(ev) {
                Some(m) => token_movements.push(m),
                None => evidence_notes.push(format!(
                    "unattributed contract event (kept in raw meta): {:?}",
                    ev.type_
                )),
            }
        }
    } else if snapshot.execution != Execution::Simulated {
        evidence_notes.push("no result meta available; token movements unknown".to_string());
    }

    let bundle = RecordingBundle {
        schema: RECORDING_SCHEMA.to_string(),
        canonicalization_version: CANONICALIZATION_VERSION,
        network_id: NetworkId::from_passphrase(&snapshot.network_passphrase),
        trust: snapshot.trust,
        execution: snapshot.execution,
        ledger: snapshot.ledger.map(LedgerSeq),
        created_at_unix: snapshot.created_at_unix,
        operation_index,
        authorizations,
        token_movements,
        state_changes,
        contract_executables: snapshot.contract_executables.clone(),
        evidence_notes,
        raw: RawEvidence {
            envelope_xdr_base64: snapshot.envelope_xdr_base64.clone(),
            result_meta_xdr_base64: snapshot.result_meta_xdr_base64.clone(),
            simulated_auth_xdr_base64: snapshot.simulated_auth_xdr_base64.clone(),
        },
    };
    // Resource admission and hashing are one boundary: never return a recording that the next
    // pipeline stage can only reject because its canonical preimage exceeds the domain limit.
    // All fields here use supported canonical types, so a serialization failure at this point is
    // an input/resource failure rather than an optional best-effort hash.
    bundle.recording_hash().map_err(|error| {
        RecordError::ResourceLimit(format!(
            "recording does not fit the canonical hash boundary: {error}"
        ))
    })?;
    Ok(bundle)
}

/// Return every contract address whose executable influences the recorded authorization:
/// address-level authorizers and every contract call in the selected transaction's auth
/// trees. Acquisition adapters use this to request contract-instance ledger entries.
pub fn referenced_contract_addresses(
    snapshot: &EvidenceSnapshot,
) -> Result<Vec<String>, RecordError> {
    validate_evidence_limits(snapshot)?;
    let envelope =
        TransactionEnvelope::from_xdr_base64(&snapshot.envelope_xdr_base64, xdr_limits())
            .map_err(|e| map_xdr_parse_error("envelope", e, RecordError::EnvelopeParse))?;
    let tx = match &envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx,
        TransactionEnvelope::TxFeeBump(fb) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &fb.tx.inner_tx;
            &inner.tx
        }
        TransactionEnvelope::TxV0(_) => {
            return Err(RecordError::UnsupportedEnvelope(
                "TransactionV0 envelopes cannot carry Soroban operations".to_string(),
            ))
        }
    };

    let mut addresses = std::collections::BTreeSet::new();

    for operation in tx.operations.iter() {
        let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
            continue;
        };
        if let HostFunction::InvokeContract(call) = &invoke.host_function {
            insert_contract_address(&call.contract_address, &mut addresses);
        }
        if snapshot.execution != Execution::Simulated {
            for entry in invoke.auth.iter() {
                collect_auth_contract_addresses(entry, &mut addresses);
            }
        }
    }
    if snapshot.execution == Execution::Simulated {
        for encoded in &snapshot.simulated_auth_xdr_base64 {
            let entry = SorobanAuthorizationEntry::from_xdr_base64(encoded, xdr_limits())
                .map_err(|e| map_xdr_parse_error("authorization", e, RecordError::AuthParse))?;
            collect_auth_contract_addresses(&entry, &mut addresses);
        }
    }
    Ok(addresses.into_iter().collect())
}

fn collect_auth_contract_addresses(
    entry: &SorobanAuthorizationEntry,
    addresses: &mut std::collections::BTreeSet<String>,
) {
    match &entry.credentials {
        SorobanCredentials::Address(credentials) => {
            insert_contract_address(&credentials.address, addresses);
        }
        SorobanCredentials::AddressV2(credentials) => {
            insert_contract_address(&credentials.address, addresses);
        }
        SorobanCredentials::AddressWithDelegates(credentials) => {
            insert_contract_address(&credentials.address_credentials.address, addresses);
        }
        SorobanCredentials::SourceAccount => {}
    }
    let mut invocations = vec![&entry.root_invocation];
    while let Some(invocation) = invocations.pop() {
        if let SorobanAuthorizedFunction::ContractFn(call) = &invocation.function {
            insert_contract_address(&call.contract_address, addresses);
        }
        invocations.extend(invocation.sub_invocations.iter());
    }
}

fn insert_contract_address(
    address: &ScAddress,
    addresses: &mut std::collections::BTreeSet<String>,
) {
    if let ScAddress::Contract(contract) = address {
        addresses.insert(format!("{}", stellar_strkey::Contract(contract.0 .0)));
    }
}

fn decode_auth_entry(
    entry: &SorobanAuthorizationEntry,
    tx: &stellar_xdr::Transaction,
    _op: &stellar_xdr::InvokeHostFunctionOp,
) -> Result<AuthorizationRecord, RecordError> {
    // Resolve the authorizer + credential arm. All four Protocol ≤27 arms are handled;
    // anything new fails closed at the XDR parse layer.
    let (authorizer_sc, credential): (ScAddress, CredentialRecord) = match &entry.credentials {
        SorobanCredentials::SourceAccount => {
            let source = muxed_to_scaddress(&tx.source_account)?;
            (source, CredentialRecord::SourceAccount)
        }
        SorobanCredentials::Address(c) => (
            c.address.clone(),
            CredentialRecord::Address {
                nonce: c.nonce,
                signature_expiration_ledger: c.signature_expiration_ledger,
            },
        ),
        SorobanCredentials::AddressV2(c) => (
            c.address.clone(),
            CredentialRecord::AddressV2 {
                nonce: c.nonce,
                signature_expiration_ledger: c.signature_expiration_ledger,
            },
        ),
        SorobanCredentials::AddressWithDelegates(c) => (
            c.address_credentials.address.clone(),
            CredentialRecord::AddressWithDelegates {
                nonce: c.address_credentials.nonce,
                signature_expiration_ledger: c.address_credentials.signature_expiration_ledger,
                delegate_count: count_delegates(&c.delegates),
            },
        ),
    };

    let authorizer = scaddress_to_strkey(&authorizer_sc)?;
    let fingerprint = auth_fingerprint(&authorizer_sc, &entry.root_invocation)?;
    let root = decode_invocation(&entry.root_invocation)?;

    Ok(AuthorizationRecord {
        authorizer,
        credential,
        fingerprint,
        root,
    })
}

fn count_delegates(delegates: &stellar_xdr::VecM<stellar_xdr::SorobanDelegateSignature>) -> u32 {
    let mut n = 0u32;
    for d in delegates.iter() {
        n = n
            .saturating_add(1)
            .saturating_add(count_delegates(&d.nested_delegates));
    }
    n
}

/// Replay-invariant authorization fingerprint over canonical XDR.
///
/// The two hashed values are unchanged — the authorizer and the root authorized invocation — but
/// they now sit inside the versioned preimage every other hash uses, so this one is not the sole
/// exception whose domain lives outside the encoding. The authorizer is carried as `ScVal::Address`
/// because that is exactly what an `ScAddress` is; the invocation has no `ScVal` counterpart, so
/// it stays as its own canonical XDR bytes.
pub fn auth_fingerprint(
    authorizer: &ScAddress,
    root: &SorobanAuthorizedInvocation,
) -> Result<Hash32, RecordError> {
    let invocation = root
        .to_xdr(xdr_limits())
        .map_err(|e| map_xdr_write_error("authorized invocation", e))?;
    let invocation: ScBytes = invocation.try_into().map_err(|_| {
        RecordError::Internal("the authorized invocation exceeds the XDR length limit".to_string())
    })?;
    let preimage = ScVal::Vec(Some(
        vec![ScVal::Address(authorizer.clone()), ScVal::Bytes(invocation)]
            .try_into()
            .map_err(|_| {
                RecordError::Internal("the fingerprint vector was rejected".to_string())
            })?,
    ));
    ozpb_domain::canonical_hash_of(domains::AUTH_FINGERPRINT, preimage)
        .map_err(|e| RecordError::Internal(e.to_string()))
}

fn decode_invocation(inv: &SorobanAuthorizedInvocation) -> Result<InvocationNode, RecordError> {
    let call = match &inv.function {
        SorobanAuthorizedFunction::ContractFn(args) => AuthorizedCall::Contract {
            contract: scaddress_to_strkey(&args.contract_address)?,
            fn_name: symbol_to_string(&args.function_name),
            args: args
                .args
                .iter()
                .map(summarize_arg)
                .collect::<Result<_, _>>()?,
        },
        SorobanAuthorizedFunction::CreateContractHostFn(_)
        | SorobanAuthorizedFunction::CreateContractV2HostFn(_) => AuthorizedCall::CreateContract,
    };
    let sub_invocations = inv
        .sub_invocations
        .iter()
        .map(decode_invocation)
        .collect::<Result<_, _>>()?;
    Ok(InvocationNode {
        call,
        sub_invocations,
    })
}

fn summarize_arg(v: &ScVal) -> Result<ArgSummary, RecordError> {
    Ok(match v {
        ScVal::Address(a) => ArgSummary::Address(scaddress_to_strkey(a)?),
        ScVal::I128(p) => ArgSummary::I128(int128_parts_to_i128(p)),
        ScVal::U64(u) => ArgSummary::U64(*u),
        ScVal::U32(u) => ArgSummary::U32(*u),
        ScVal::Symbol(s) => ArgSummary::Symbol(symbol_to_string(s)),
        other => ArgSummary::Other {
            xdr_base64: other
                .to_xdr_base64(xdr_limits())
                .map_err(|e| map_xdr_write_error("argument", e))?,
        },
    })
}

fn validate_evidence_limits(snapshot: &EvidenceSnapshot) -> Result<(), RecordError> {
    ensure_base64_size("envelope", &snapshot.envelope_xdr_base64)?;
    if let Some(meta) = &snapshot.result_meta_xdr_base64 {
        ensure_base64_size("result meta", meta)?;
    }
    if snapshot.simulated_auth_xdr_base64.len() > MAX_SIMULATED_AUTH_ENTRIES {
        return Err(RecordError::ResourceLimit(format!(
            "simulation returned {} authorization entries; maximum is {MAX_SIMULATED_AUTH_ENTRIES}",
            snapshot.simulated_auth_xdr_base64.len()
        )));
    }
    let auth_bytes =
        snapshot
            .simulated_auth_xdr_base64
            .iter()
            .try_fold(0usize, |total, auth| {
                ensure_base64_size("authorization", auth)?;
                total.checked_add(auth.len()).ok_or_else(|| {
                    RecordError::ResourceLimit("authorization evidence size overflow".to_string())
                })
            })?;
    if auth_bytes > MAX_XDR_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "authorization evidence is {auth_bytes} encoded bytes; maximum is {MAX_XDR_BASE64_BYTES}"
        )));
    }
    if snapshot.simulated_state_changes.len() > MAX_SIMULATED_STATE_CHANGES {
        return Err(RecordError::ResourceLimit(format!(
            "simulation returned {} state changes; maximum is {MAX_SIMULATED_STATE_CHANGES}",
            snapshot.simulated_state_changes.len()
        )));
    }
    if snapshot.contract_executables.len() > MAX_SIMULATED_AUTH_ENTRIES {
        return Err(RecordError::ResourceLimit(format!(
            "recording contains {} contract executable observations; maximum is {MAX_SIMULATED_AUTH_ENTRIES}",
            snapshot.contract_executables.len()
        )));
    }
    let state_bytes = snapshot
        .simulated_state_changes
        .iter()
        .flat_map(|change| {
            [
                change.key_xdr_base64.as_deref(),
                change.before_xdr_base64.as_deref(),
                change.after_xdr_base64.as_deref(),
            ]
        })
        .flatten()
        .try_fold(0usize, |total, value| {
            ensure_base64_size("state change", value)?;
            total.checked_add(value.len()).ok_or_else(|| {
                RecordError::ResourceLimit("state-change evidence size overflow".to_string())
            })
        })?;
    if state_bytes > MAX_XDR_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "state-change evidence is {state_bytes} encoded bytes; maximum is {MAX_XDR_BASE64_BYTES}"
        )));
    }
    let encoded_evidence_bytes = snapshot
        .envelope_xdr_base64
        .len()
        .checked_add(
            snapshot
                .result_meta_xdr_base64
                .as_ref()
                .map_or(0, String::len),
        )
        .and_then(|total| total.checked_add(auth_bytes))
        .and_then(|total| total.checked_add(state_bytes))
        .ok_or_else(|| {
            RecordError::ResourceLimit("total encoded evidence size overflow".to_string())
        })?;
    if encoded_evidence_bytes > MAX_TOTAL_EVIDENCE_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "encoded evidence is {encoded_evidence_bytes} bytes; maximum is \
             {MAX_TOTAL_EVIDENCE_BASE64_BYTES}"
        )));
    }
    Ok(())
}

fn ensure_base64_size(label: &str, value: &str) -> Result<(), RecordError> {
    if value.len() > MAX_XDR_BASE64_BYTES {
        return Err(RecordError::ResourceLimit(format!(
            "{label} XDR is {} encoded bytes; maximum is {MAX_XDR_BASE64_BYTES}",
            value.len()
        )));
    }
    Ok(())
}

fn map_xdr_parse_error(
    label: &str,
    error: stellar_xdr::Error,
    parse_error: impl FnOnce(String) -> RecordError,
) -> RecordError {
    if matches!(
        error,
        stellar_xdr::Error::DepthLimitExceeded | stellar_xdr::Error::LengthLimitExceeded
    ) {
        RecordError::ResourceLimit(format!("{label} XDR exceeded decoding limits"))
    } else {
        parse_error(error.to_string())
    }
}

fn map_xdr_write_error(label: &str, error: stellar_xdr::Error) -> RecordError {
    if matches!(
        error,
        stellar_xdr::Error::DepthLimitExceeded | stellar_xdr::Error::LengthLimitExceeded
    ) {
        RecordError::ResourceLimit(format!("{label} XDR exceeded encoding limits"))
    } else {
        RecordError::Internal(error.to_string())
    }
}

fn int128_parts_to_i128(p: &stellar_xdr::Int128Parts) -> i128 {
    (i128::from(p.hi) << 64) | i128::from(p.lo)
}

fn symbol_to_string(s: &stellar_xdr::ScSymbol) -> String {
    String::from_utf8_lossy(s.0.as_slice()).into_owned()
}

fn muxed_to_scaddress(m: &stellar_xdr::MuxedAccount) -> Result<ScAddress, RecordError> {
    match m {
        stellar_xdr::MuxedAccount::Ed25519(key) => Ok(ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(key.clone()),
        ))),
        stellar_xdr::MuxedAccount::MuxedEd25519(m) => {
            Ok(ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(m.ed25519.clone()),
            )))
        }
    }
}

fn scaddress_to_strkey(a: &ScAddress) -> Result<String, RecordError> {
    match a {
        ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key)),
        )) => Ok(format!("{}", stellar_strkey::ed25519::PublicKey(*key))),
        ScAddress::Contract(cid) => Ok(format!("{}", stellar_strkey::Contract(cid.0 .0))),
        other => Err(RecordError::UnsupportedAddress(format!(
            "unsupported authorizer/argument address kind: {other:?}"
        ))),
    }
}

/// Summarize a `LedgerEntryChanges` list into evidence-only [`StateChange`]s. A
/// `State → Updated` pair yields two entries (the `State` pre-image is kept for
/// completeness); the summary is deliberately shallow (kind + entry type + owning
/// contract) — full values stay in the raw meta.
fn collect_changes(
    changes: &stellar_xdr::LedgerEntryChanges,
    source: StateChangeSource,
    out: &mut Vec<StateChange>,
) {
    use stellar_xdr::LedgerEntryChange as C;
    for change in changes.iter() {
        let (kind, (entry, contract)) = match change {
            C::Created(e) => (StateChangeKind::Created, entry_summary(&e.data)),
            C::Updated(e) => (StateChangeKind::Updated, entry_summary(&e.data)),
            C::State(e) => (StateChangeKind::State, entry_summary(&e.data)),
            C::Restored(e) => (StateChangeKind::Restored, entry_summary(&e.data)),
            C::Removed(k) => (StateChangeKind::Removed, key_summary(k)),
        };
        out.push(StateChange {
            kind,
            entry,
            contract,
            source,
            key_xdr_base64: None,
            before_xdr_base64: None,
            after_xdr_base64: None,
        });
    }
}

fn entry_summary(data: &stellar_xdr::LedgerEntryData) -> (String, Option<String>) {
    use stellar_xdr::LedgerEntryData as D;
    match data {
        D::ContractData(cd) => (
            "contract_data".to_string(),
            scaddress_to_strkey(&cd.contract).ok(),
        ),
        D::ContractCode(_) => ("contract_code".to_string(), None),
        D::Account(_) => ("account".to_string(), None),
        D::Trustline(_) => ("trustline".to_string(), None),
        D::Ttl(_) => ("ttl".to_string(), None),
        D::Offer(_) => ("offer".to_string(), None),
        D::Data(_) => ("data".to_string(), None),
        D::ClaimableBalance(_) => ("claimable_balance".to_string(), None),
        D::LiquidityPool(_) => ("liquidity_pool".to_string(), None),
        D::ConfigSetting(_) => ("config_setting".to_string(), None),
    }
}

fn key_summary(key: &stellar_xdr::LedgerKey) -> (String, Option<String>) {
    use stellar_xdr::LedgerKey as K;
    match key {
        K::ContractData(cd) => (
            "contract_data".to_string(),
            scaddress_to_strkey(&cd.contract).ok(),
        ),
        K::ContractCode(_) => ("contract_code".to_string(), None),
        K::Account(_) => ("account".to_string(), None),
        K::Trustline(_) => ("trustline".to_string(), None),
        K::Ttl(_) => ("ttl".to_string(), None),
        K::Offer(_) => ("offer".to_string(), None),
        K::Data(_) => ("data".to_string(), None),
        K::ClaimableBalance(_) => ("claimable_balance".to_string(), None),
        K::LiquidityPool(_) => ("liquidity_pool".to_string(), None),
        K::ConfigSetting(_) => ("config_setting".to_string(), None),
    }
}

fn decode_token_event(ev: &ContractEvent) -> Option<TokenMovement> {
    let ContractEventBody::V0(v0) = &ev.body;
    let first = v0.topics.first()?;
    let kind = match first {
        ScVal::Symbol(s) => match symbol_to_string(s).as_str() {
            "transfer" => MovementKind::Transfer,
            "mint" => MovementKind::Mint,
            "burn" => MovementKind::Burn,
            "approve" => MovementKind::Approve,
            _ => return None,
        },
        _ => return None,
    };
    let token_contract = ev
        .contract_id
        .as_ref()
        .map(|cid| format!("{}", stellar_strkey::Contract(cid.0 .0)));
    let addr_at = |i: usize| -> Option<String> {
        match v0.topics.get(i) {
            Some(ScVal::Address(a)) => scaddress_to_strkey(a).ok(),
            _ => None,
        }
    };
    let (from, to, spender) = match kind {
        MovementKind::Transfer => (addr_at(1), addr_at(2), None),
        MovementKind::Mint => (None, addr_at(1), None),
        MovementKind::Burn => (addr_at(1), None, None),
        MovementKind::Approve => (addr_at(1), None, addr_at(2)),
    };
    let amount = match &v0.data {
        ScVal::I128(p) => Some(int128_parts_to_i128(p)),
        ScVal::Map(Some(m)) => m.iter().find_map(|entry| match (&entry.key, &entry.val) {
            (ScVal::Symbol(k), ScVal::I128(p)) if symbol_to_string(k) == "amount" => {
                Some(int128_parts_to_i128(p))
            }
            _ => None,
        }),
        _ => None,
    };
    let expiration_ledger = match &v0.data {
        ScVal::Map(Some(m)) => m.iter().find_map(|entry| match (&entry.key, &entry.val) {
            (ScVal::Symbol(k), ScVal::U32(ledger))
                if symbol_to_string(k) == "expiration_ledger" =>
            {
                Some(*ledger)
            }
            _ => None,
        }),
        _ => None,
    };
    Some(TokenMovement {
        kind,
        token_contract,
        from,
        to,
        spender,
        amount,
        expiration_ledger,
    })
}

// ---------------------------------------------------------------------------------------
// Tests — fixtures constructed from real XDR types (deterministic, no network)
// ---------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------
// Deterministic fixtures (public: shared by downstream crates' tests and the e2e check)
// ---------------------------------------------------------------------------------------

// Deterministic test-support builders shared across crates' tests. `unwrap` on
// known-good literal XDR is intentional here; the core-logic lint stays in force
// everywhere else.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod fixtures {
    use super::*;
    use stellar_xdr::{
        AccountId, ContractEventType, ContractEventV0, ContractId, ExtensionPoint, Hash,
        HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Memo, MuxedAccount, Operation,
        Preconditions, PublicKey, ScMapEntry, ScSymbol, SequenceNumber, SorobanAddressCredentials,
        SorobanTransactionMeta, SorobanTransactionMetaExt, Transaction, TransactionExt,
        TransactionMetaV3, TransactionV1Envelope, Uint256,
    };

    pub const ACCOUNT_CID: [u8; 32] = [1u8; 32];
    pub const TOKEN_CID: [u8; 32] = [2u8; 32];
    pub const MERCHANT_KEY: [u8; 32] = [3u8; 32];
    pub const AMOUNT: i128 = 500_000_000;

    pub fn account_sc() -> ScAddress {
        ScAddress::Contract(ContractId(Hash(ACCOUNT_CID)))
    }
    pub fn token_sc() -> ScAddress {
        ScAddress::Contract(ContractId(Hash(TOKEN_CID)))
    }
    pub fn merchant_sc() -> ScAddress {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            MERCHANT_KEY,
        ))))
    }

    pub fn i128_val(v: i128) -> ScVal {
        ScVal::I128(stellar_xdr::Int128Parts {
            hi: (v >> 64) as i64,
            lo: v as u64,
        })
    }

    pub fn transfer_invocation() -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: token_sc(),
                function_name: ScSymbol("transfer".as_bytes().try_into().unwrap()),
                args: vec![
                    ScVal::Address(account_sc()),
                    ScVal::Address(merchant_sc()),
                    i128_val(AMOUNT),
                ]
                .try_into()
                .unwrap(),
            }),
            sub_invocations: Default::default(),
        }
    }

    pub fn address_credentials(nonce: i64) -> SorobanCredentials {
        SorobanCredentials::Address(SorobanAddressCredentials {
            address: account_sc(),
            nonce,
            signature_expiration_ledger: 4_210_000,
            signature: ScVal::Void,
        })
    }

    pub fn auth_entry(credentials: SorobanCredentials) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials,
            root_invocation: transfer_invocation(),
        }
    }

    pub fn envelope_with(auth: Vec<SorobanAuthorizationEntry>) -> TransactionEnvelope {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: transaction_with(auth),
            signatures: Default::default(),
        })
    }

    pub fn transaction_with(auth: Vec<SorobanAuthorizationEntry>) -> Transaction {
        Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([9u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(7),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(InvokeContractArgs {
                        contract_address: token_sc(),
                        function_name: ScSymbol("transfer".as_bytes().try_into().unwrap()),
                        args: Default::default(),
                    }),
                    auth: auth.try_into().unwrap(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        }
    }

    pub fn transfer_event() -> ContractEvent {
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(Hash(TOKEN_CID))),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol("transfer".as_bytes().try_into().unwrap())),
                    ScVal::Address(account_sc()),
                    ScVal::Address(merchant_sc()),
                ]
                .try_into()
                .unwrap(),
                data: i128_val(AMOUNT),
            }),
        }
    }

    pub fn approve_event() -> ContractEvent {
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(ContractId(Hash(TOKEN_CID))),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: vec![
                    ScVal::Symbol(ScSymbol("approve".as_bytes().try_into().unwrap())),
                    ScVal::Address(account_sc()),
                    ScVal::Address(merchant_sc()),
                ]
                .try_into()
                .unwrap(),
                data: ScVal::Map(Some(
                    vec![
                        ScMapEntry {
                            key: ScVal::Symbol(ScSymbol("amount".as_bytes().try_into().unwrap())),
                            val: i128_val(AMOUNT),
                        },
                        ScMapEntry {
                            key: ScVal::Symbol(ScSymbol(
                                "expiration_ledger".as_bytes().try_into().unwrap(),
                            )),
                            val: ScVal::U32(4_210_000),
                        },
                    ]
                    .try_into()
                    .unwrap(),
                )),
            }),
        }
    }

    pub fn meta_v3() -> TransactionMeta {
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![transfer_event()].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        })
    }

    pub fn meta_v3_with_approve() -> TransactionMeta {
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: Default::default(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![approve_event()].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        })
    }

    pub fn executed_snapshot() -> EvidenceSnapshot {
        let mut observations = BTreeMap::new();
        observations.insert(
            format!("{}", stellar_strkey::Contract(ACCOUNT_CID)),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: ozpb_domain::pinned_upstream::OZ_SMART_ACCOUNT_WASM,
                },
                observed_ledger: LedgerSeq(4_200_100),
            },
        );
        observations.insert(
            format!("{}", stellar_strkey::Contract(TOKEN_CID)),
            ExecutableObservation {
                executable: ObservedExecutable::StellarAsset,
                observed_ledger: LedgerSeq(4_200_100),
            },
        );
        EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(12345))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta_v3().to_xdr_base64(Limits::none()).unwrap()),
            4_200_100,
            1_780_000_000,
            true,
        )
        .with_contract_executables(observations)
    }

    /// A ContractData ledger entry owned by the token contract.
    pub fn contract_data_entry(val: i128) -> stellar_xdr::LedgerEntry {
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, LedgerEntry, LedgerEntryData, LedgerEntryExt,
        };
        LedgerEntry {
            last_modified_ledger_seq: 4_200_099,
            data: LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: token_sc(),
                key: ScVal::Symbol(ScSymbol("balance".as_bytes().try_into().unwrap())),
                durability: ContractDataDurability::Persistent,
                val: i128_val(val),
            }),
            ext: LedgerEntryExt::V0,
        }
    }

    /// Meta v3 carrying a `State → Updated` contract-data change in operation 0.
    pub fn meta_v3_with_changes() -> TransactionMeta {
        use stellar_xdr::{LedgerEntryChange, OperationMeta};
        let changes: stellar_xdr::LedgerEntryChanges = vec![
            LedgerEntryChange::State(contract_data_entry(1)),
            LedgerEntryChange::Updated(contract_data_entry(2)),
        ]
        .try_into()
        .unwrap();
        TransactionMeta::V3(TransactionMetaV3 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![OperationMeta { changes }].try_into().unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMeta {
                ext: SorobanTransactionMetaExt::V0,
                events: vec![transfer_event()].try_into().unwrap(),
                return_value: ScVal::Void,
                diagnostic_events: Default::default(),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    // Only the XDR types the test bodies construct directly; the fixture builders live
    // in the `fixtures` module with their own imports.
    use stellar_xdr::{
        ExtensionPoint, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, MuxedAccount, Operation, SorobanAddressCredentials,
        SorobanTransactionMetaExt, TransactionV1Envelope, Uint256,
    };

    #[test]
    fn executed_transfer_records_authorization_and_movement() {
        let bundle = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(bundle.trust.as_str(), "rpc_reported");
        assert_eq!(bundle.execution, Execution::ExecutedSuccess);
        assert_eq!(bundle.authorizations.len(), 1);

        let auth = &bundle.authorizations[0];
        assert!(
            auth.authorizer.starts_with('C'),
            "smart account is a C-address"
        );
        assert!(matches!(
            auth.credential,
            CredentialRecord::Address {
                nonce: 12345,
                signature_expiration_ledger: 4_210_000
            }
        ));
        match &auth.root.call {
            AuthorizedCall::Contract {
                contract,
                fn_name,
                args,
            } => {
                assert!(contract.starts_with('C'));
                assert_eq!(fn_name, "transfer");
                assert_eq!(args.len(), 3);
                assert!(matches!(&args[0], ArgSummary::Address(a) if a.starts_with('C')));
                assert!(matches!(&args[1], ArgSummary::Address(a) if a.starts_with('G')));
                assert_eq!(args[2], ArgSummary::I128(AMOUNT));
            }
            other => panic!("unexpected call: {other:?}"),
        }

        assert_eq!(bundle.token_movements.len(), 1);
        let m = &bundle.token_movements[0];
        assert_eq!(m.kind, MovementKind::Transfer);
        assert_eq!(m.amount, Some(AMOUNT));
        assert_eq!(m.spender, None);
        assert_eq!(m.expiration_ledger, None);
    }

    #[test]
    fn approve_event_records_spender_amount_and_expiration() {
        let snapshot = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(12345))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(
                meta_v3_with_approve()
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
            ),
            4_200_100,
            1_780_000_000,
            true,
        );
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();

        assert_eq!(bundle.token_movements.len(), 1);
        let approval = &bundle.token_movements[0];
        let expected_owner = format!("{}", stellar_strkey::Contract(ACCOUNT_CID));
        let expected_spender = format!("{}", stellar_strkey::ed25519::PublicKey(MERCHANT_KEY));
        assert_eq!(approval.kind, MovementKind::Approve);
        assert_eq!(approval.from.as_deref(), Some(expected_owner.as_str()));
        assert_eq!(approval.to, None);
        assert_eq!(approval.spender.as_deref(), Some(expected_spender.as_str()));
        assert_eq!(approval.amount, Some(AMOUNT));
        assert_eq!(approval.expiration_ledger, Some(4_210_000));
    }

    #[test]
    fn fingerprint_is_replay_invariant_across_executed_and_simulated() {
        // Same authorized shape via simulation (unsigned entry, different nonce):
        // the AUTH fingerprint must match; the full recording hash must differ.
        let executed = record(&executed_snapshot(), RecordOptions::default()).unwrap();

        let sim_entry = auth_entry(address_credentials(999_999)); // different nonce
        let sim = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![]).to_xdr_base64(Limits::none()).unwrap(),
            vec![sim_entry.to_xdr_base64(Limits::none()).unwrap()],
            Some(4_200_101),
        );
        let simulated = record(&sim, RecordOptions::default()).unwrap();

        assert_eq!(
            executed.authorizations[0].fingerprint, simulated.authorizations[0].fingerprint,
            "fingerprint is over (authorizer, root invocation) only"
        );
        assert_ne!(
            executed.recording_hash().unwrap(),
            simulated.recording_hash().unwrap(),
            "full recording hash covers raw evidence + anchors + trust"
        );
    }

    #[test]
    fn empty_simulation_auth_never_falls_back_to_envelope_auth() {
        let executed = executed_snapshot();
        let simulated = EvidenceSnapshot::from_rpc_simulation(
            ozpb_domain::TESTNET_PASSPHRASE,
            executed.envelope_xdr_base64.clone(),
            vec![],
            Some(4_200_101),
        );
        let bundle = record(&simulated, RecordOptions::default()).unwrap();
        assert!(
            bundle.authorizations.is_empty(),
            "simulation evidence must use exactly the auth array returned by RPC"
        );
    }

    #[test]
    fn recording_hash_is_deterministic() {
        let a = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        let b = record(&executed_snapshot(), RecordOptions::default()).unwrap();
        assert_eq!(a.recording_hash().unwrap(), b.recording_hash().unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn observed_contract_executables_are_preserved_in_the_recording_hash() {
        let address = format!("{}", stellar_strkey::Contract(ACCOUNT_CID));
        let mut observations = std::collections::BTreeMap::new();
        observations.insert(
            address.clone(),
            ExecutableObservation {
                executable: ObservedExecutable::Wasm {
                    code_hash: ozpb_domain::sha256(b"fixture-account-wasm"),
                },
                observed_ledger: LedgerSeq(4_200_100),
            },
        );
        let snapshot = executed_snapshot().with_contract_executables(observations);
        let observed = record(&snapshot, RecordOptions::default()).unwrap();
        let baseline = record(
            &executed_snapshot().with_contract_executables(BTreeMap::new()),
            RecordOptions::default(),
        )
        .unwrap();

        assert!(observed.contract_executables.contains_key(&address));
        assert_ne!(
            observed.recording_hash().unwrap(),
            baseline.recording_hash().unwrap(),
            "executable observations are trust-bearing recording evidence"
        );
    }

    #[test]
    fn oversized_xdr_is_rejected_before_decode() {
        let snapshot = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            "A".repeat(MAX_XDR_BASE64_BYTES + 1),
            None,
            None,
            None,
            true,
        );

        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::ResourceLimit(message)) if message.contains("envelope")
        ));
    }

    #[test]
    fn aggregate_evidence_size_is_rejected_before_decode() {
        let each = MAX_TOTAL_EVIDENCE_BASE64_BYTES / 2 + 1;
        assert!(each <= MAX_XDR_BASE64_BYTES);
        let snapshot = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            "A".repeat(each),
            Some("A".repeat(each)),
            None,
            None,
            true,
        );

        assert!(matches!(
            record(&snapshot, RecordOptions::default()),
            Err(RecordError::ResourceLimit(message)) if message.contains("encoded evidence")
        ));
    }

    #[test]
    fn all_credential_arms_are_recorded() {
        use stellar_xdr::{SorobanAddressCredentialsWithDelegates, SorobanDelegateSignature};

        // SourceAccount resolves the authorizer from the tx source account.
        let env = envelope_with(vec![auth_entry(SorobanCredentials::SourceAccount)]);
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert!(matches!(
            b.authorizations[0].credential,
            CredentialRecord::SourceAccount
        ));
        assert!(b.authorizations[0].authorizer.starts_with('G'));

        // AddressV2 (CAP-71).
        let v2 = SorobanCredentials::AddressV2(SorobanAddressCredentials {
            address: account_sc(),
            nonce: 5,
            signature_expiration_ledger: 10,
            signature: ScVal::Void,
        });
        let env = envelope_with(vec![auth_entry(v2)]);
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert!(matches!(
            b.authorizations[0].credential,
            CredentialRecord::AddressV2 { nonce: 5, .. }
        ));

        // AddressWithDelegates with a nested delegate tree (recursive count).
        let awd =
            SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: account_sc(),
                    nonce: 6,
                    signature_expiration_ledger: 11,
                    signature: ScVal::Void,
                },
                delegates: vec![SorobanDelegateSignature {
                    address: merchant_sc(),
                    signature: ScVal::Void,
                    nested_delegates: vec![SorobanDelegateSignature {
                        address: merchant_sc(),
                        signature: ScVal::Void,
                        nested_delegates: Default::default(),
                    }]
                    .try_into()
                    .unwrap(),
                }]
                .try_into()
                .unwrap(),
            });
        let env = envelope_with(vec![auth_entry(awd)]);
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert!(matches!(
            b.authorizations[0].credential,
            CredentialRecord::AddressWithDelegates {
                delegate_count: 2,
                ..
            }
        ));
    }

    #[test]
    fn fee_bump_envelopes_are_unwrapped() {
        let inner = TransactionV1Envelope {
            tx: transaction_with(vec![auth_entry(address_credentials(1))]),
            signatures: Default::default(),
        };
        let fb = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([8u8; 32])),
                fee: 1000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            fb.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.authorizations.len(), 1);
    }

    #[test]
    fn failed_transactions_are_rejected_unless_analysis_mode() {
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            1,
            1,
            false, // failed
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::TxFailed
        );
        let b = record(
            &snap,
            RecordOptions {
                allow_failed: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(b.execution, Execution::ExecutedFailed);
    }

    #[test]
    fn multi_operation_requires_explicit_selection() {
        let mut tx = transaction_with(vec![auth_entry(address_credentials(1))]);
        let ops: Vec<Operation> = tx.operations.iter().cloned().collect();
        let mut doubled = ops.clone();
        doubled.extend(ops);
        tx.operations = doubled.try_into().unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::OperationSelection(2)
        );
        let b = record(
            &snap,
            RecordOptions {
                operation_index: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(b.operation_index, 1);
    }

    #[test]
    fn no_soroban_op_fails() {
        let mut tx = transaction_with(vec![]);
        tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::SetOptions(stellar_xdr::SetOptionsOp {
                inflation_dest: None,
                clear_flags: None,
                set_flags: None,
                master_weight: None,
                low_threshold: None,
                med_threshold: None,
                high_threshold: None,
                home_domain: None,
                signer: None,
            }),
        }]
        .try_into()
        .unwrap();
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            env.to_xdr_base64(Limits::none()).unwrap(),
            None,
            1,
            1,
            true,
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::NoSorobanOp
        );
    }

    #[test]
    fn meta_v4_events_are_extracted_per_operation() {
        use stellar_xdr::{OperationMetaV2, SorobanTransactionMetaV2, TransactionMetaV4};
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![OperationMetaV2 {
                ext: ExtensionPoint::V0,
                changes: Default::default(),
                events: vec![transfer_event()].try_into().unwrap(),
            }]
            .try_into()
            .unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMetaV2 {
                ext: SorobanTransactionMetaExt::V0,
                return_value: None,
            }),
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.token_movements.len(), 1);
        assert_eq!(b.token_movements[0].kind, MovementKind::Transfer);
    }

    #[test]
    fn meta_v3_state_changes_are_extracted_as_evidence() {
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(
                meta_v3_with_changes()
                    .to_xdr_base64(Limits::none())
                    .unwrap(),
            ),
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        // A State→Updated pair on a contract-data entry owned by the token contract.
        assert_eq!(
            b.state_changes.len(),
            2,
            "state changes: {:?}",
            b.state_changes
        );
        let kinds: Vec<_> = b.state_changes.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&StateChangeKind::State));
        assert!(kinds.contains(&StateChangeKind::Updated));
        for c in &b.state_changes {
            assert_eq!(c.entry, "contract_data");
            assert_eq!(c.source, StateChangeSource::Operation);
            assert!(c.contract.as_deref().is_some_and(|s| s.starts_with('C')));
        }
        // Evidence-only: state changes never turn into token movements or constraints.
        assert_eq!(b.token_movements.len(), 1);
    }

    #[test]
    fn meta_v4_state_changes_are_extracted() {
        use stellar_xdr::{OperationMetaV2, SorobanTransactionMetaV2, TransactionMetaV4};
        let changes: stellar_xdr::LedgerEntryChanges =
            vec![stellar_xdr::LedgerEntryChange::Created(
                fixtures::contract_data_entry(7),
            )]
            .try_into()
            .unwrap();
        let meta = TransactionMeta::V4(TransactionMetaV4 {
            ext: ExtensionPoint::V0,
            tx_changes_before: Default::default(),
            operations: vec![OperationMetaV2 {
                ext: ExtensionPoint::V0,
                changes,
                events: Default::default(),
            }]
            .try_into()
            .unwrap(),
            tx_changes_after: Default::default(),
            soroban_meta: Some(SorobanTransactionMetaV2 {
                ext: SorobanTransactionMetaExt::V0,
                return_value: None,
            }),
            events: Default::default(),
            diagnostic_events: Default::default(),
        });
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.state_changes.len(), 1);
        assert_eq!(b.state_changes[0].kind, StateChangeKind::Created);
        assert_eq!(b.state_changes[0].entry, "contract_data");
    }

    #[test]
    fn pre_soroban_meta_versions_fail_closed() {
        let meta = TransactionMeta::V0(Default::default());
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            Some(meta.to_xdr_base64(Limits::none()).unwrap()),
            1,
            1,
            true,
        );
        assert_eq!(
            record(&snap, RecordOptions::default()).unwrap_err(),
            RecordError::UnsupportedMetaVersion(0)
        );
    }

    #[test]
    fn imported_snapshots_are_self_supplied() {
        let snap = EvidenceSnapshot::from_import(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![auth_entry(address_credentials(1))])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            None,
            None,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.trust.as_str(), "self_supplied");
    }

    #[test]
    fn sub_invocation_trees_are_preserved() {
        let mut root = transfer_invocation();
        root.sub_invocations = vec![transfer_invocation()].try_into().unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: address_credentials(1),
            root_invocation: root,
        };
        let snap = EvidenceSnapshot::from_rpc_transaction(
            ozpb_domain::TESTNET_PASSPHRASE,
            envelope_with(vec![entry])
                .to_xdr_base64(Limits::none())
                .unwrap(),
            None,
            1,
            1,
            true,
        );
        let b = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(b.authorizations[0].root.sub_invocations.len(), 1);
    }
}
