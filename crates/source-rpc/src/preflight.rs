//! State-dependent simulation of one exact transaction envelope.
//!
//! This uses authorization enforcement, unlike record-mode acquisition. The endpoint
//! simulates only part of the envelope: its source account (or the operation's), the one
//! operation's host function and authorization entries, under `authMode=enforce`. It does
//! not evaluate the envelope's signatures, fee, sequence number, or time bounds and other
//! preconditions, and for an invocation it ignores the envelope's own Soroban footprint and
//! resource limits. This adapter compares those declared limits with what the simulation
//! used; nothing else in the envelope is checked against the result. A successful
//! simulation is evidence about that invocation at the endpoint's reported ledger; it does
//! not establish that an installed policy was selected, that a later ledger will behave the
//! same way, or that a transaction was submitted.

use crate::{
    ensure_base64_size, simulation_shape, verify_network, xdr_limits, RpcError, RpcTransport,
    MAX_XDR_BASE64_BYTES,
};
use ozpb_domain::{sha256, NetworkId, TrustLevel};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use stellar_xdr::{
    LedgerKey, ReadXdr, ScVal, SorobanAuthorizationEntry, SorobanTransactionData,
    SorobanTransactionDataExt, TransactionEnvelope, TransactionExt, WriteXdr,
};

/// Result of an enforcement-mode trial of one transaction, never a policy verdict.
///
/// Serialize-only, like the observation: an outcome comes from running a simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightOutcome {
    /// The invocation succeeded at the endpoint's state, and the envelope's declared Soroban
    /// footprint and resource limits cover what the simulation used.
    SimulatedSuccess,
    /// The endpoint reported an error after reading its ledger. That covers an invocation or
    /// authorization failure and an error inside the endpoint's simulator alike; the text
    /// that could tell them apart is withheld because it can echo the envelope. A refusal
    /// before the endpoint read its ledger is an `RpcError::Rpc`, not this outcome.
    SimulationFailed,
    /// The invocation reached success only with archived entries restored, whether the
    /// endpoint reported a separate `restorePreamble` or (since protocol 23) restored them
    /// inside the simulation and listed them in the simulated transaction data. It is not a
    /// success against the endpoint's current state.
    RestorationRequired,
    /// The invocation succeeded in simulation, but the envelope as written declares less
    /// than the simulation used in each listed dimension, so the network would refuse or
    /// fail it. Keys are not named: the footprint is confidential envelope content.
    DeclaredResourcesInsufficient(Vec<DeclaredResource>),
}

/// A part of the envelope's declared `SorobanTransactionData` that is checked against the
/// simulated one. An envelope without Soroban transaction data declares an empty footprint
/// and zero limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredResource {
    /// A key the simulation read is in neither declared footprint list. A read-write
    /// declaration also permits reads.
    ReadOnlyFootprint,
    /// A key the simulation wrote is not in the declared read-write list.
    ReadWriteFootprint,
    Instructions,
    DiskReadBytes,
    WriteBytes,
    ResourceFee,
}

/// RPC-reported, state-dependent evidence about one envelope's invocation.
///
/// `envelope_xdr_sha256` identifies the input bytes, not everything that was evaluated: the
/// endpoint simulated the source account, host function and authorization entries; this
/// adapter compared the declared Soroban footprint and resource limits with the simulated
/// ones. Signatures, the transaction fee, sequence number, and time bounds and other
/// preconditions were not evaluated by either.
///
/// It is built only by [`preflight_transaction`] and has no deserializer: the trust and
/// mode labels are earned by the request this adapter made, never accepted from input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreflightObservation {
    /// SHA-256 of the canonical envelope XDR bytes, not a transaction hash.
    pub envelope_xdr_sha256: String,
    pub network_id: String,
    pub reported_ledger: u32,
    pub outcome: PreflightOutcome,
    /// The request uses `authMode=enforce`; a record-mode result never reaches here.
    pub auth_mode: SimulationAuthMode,
    /// `rpc_reported`: the result is trusted only as far as the configured RPC endpoint.
    pub evidence_trust: TrustLevel,
    /// A new ledger or restoration can change the result immediately.
    pub state_dependent: bool,
    /// Simulation discards writes, even when an invocation succeeds.
    pub writes_committed: bool,
}

/// The `authMode` a preflight request is sent with. Enforcement is the only mode here;
/// record-mode simulation is a separate acquisition path with its own evidence type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationAuthMode {
    Enforce,
}

/// Simulate the caller's one-operation envelope in authorization-enforcing mode.
///
/// The caller must provide the signed authorization entries it wants enforced inside
/// the envelope. RPC errors in a result become `SimulationFailed`; the endpoint's raw
/// error string is withheld because it can reflect confidential envelope contents.
/// A success that needed archived entries restored, by preamble or by the endpoint's
/// automatic restoration, is `RestorationRequired`, not a successful invocation. A
/// success outside the envelope's declared footprint or resource limits is
/// `DeclaredResourcesInsufficient`.
pub fn preflight_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<PreflightObservation, RpcError> {
    let envelope = local_envelope(envelope_xdr_base64)?;
    let envelope_xdr = envelope.to_xdr(xdr_limits()).map_err(|error| {
        RpcError::EnvelopeParse(format!("invalid transaction envelope: {error}"))
    })?;
    let envelope_xdr_sha256 = sha256(&envelope_xdr).to_hex();
    // The endpoint receives the bytes that were hashed, canonically encoded, never the
    // caller's own spelling of them.
    let canonical = envelope.to_xdr_base64(xdr_limits()).map_err(|error| {
        RpcError::EnvelopeParse(format!("invalid transaction envelope: {error}"))
    })?;
    let declared = declared_transaction_data(&envelope);
    verify_network(transport, network_passphrase)?;
    let result = transport
        .call(
            "simulateTransaction",
            json!({
                "transaction": canonical,
                "authMode": "enforce",
                "xdrFormat": "base64"
            }),
        )
        .map_err(redact_simulation_error)?;
    parse_preflight(
        &result,
        &declared,
        envelope_xdr_sha256,
        NetworkId::from_passphrase(network_passphrase).0.to_hex(),
    )
}

/// The caller's envelope, refused with an input code when it is too large, is not one unbroken
/// base64 string, does not decode, or has a shape simulation does not take. Each is the
/// caller's input rather than an endpoint reply, and nothing is sent for any of them.
///
/// Whitespace is refused rather than skipped. The XDR decoder skips ASCII whitespace, so a
/// spaced-out string decodes to the same bytes as the canonical one; refusing it keeps the
/// CLI and MCP tool to one rule and leaves no second spelling of an envelope to forward.
fn local_envelope(envelope_xdr_base64: &str) -> Result<TransactionEnvelope, RpcError> {
    if envelope_xdr_base64.len() > MAX_XDR_BASE64_BYTES {
        return Err(RpcError::EnvelopeTooLarge(format!(
            "transaction envelope is {} encoded bytes, over the {MAX_XDR_BASE64_BYTES}-byte XDR \
             size limit",
            envelope_xdr_base64.len()
        )));
    }
    if envelope_xdr_base64
        .bytes()
        .any(|byte| byte.is_ascii_whitespace())
    {
        return Err(RpcError::EnvelopeParse(
            "transaction envelope base64 contains whitespace; send it as one unbroken string"
                .to_string(),
        ));
    }
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr_base64, xdr_limits())
        .map_err(|error| {
            RpcError::EnvelopeParse(format!("invalid transaction envelope: {error}"))
        })?;
    simulation_shape(&envelope).map_err(RpcError::UnsupportedEnvelope)?;
    Ok(envelope)
}

/// The Soroban transaction data the envelope declares, or none (an empty footprint and zero
/// limits). A fee bump declares its inner transaction's.
fn declared_transaction_data(envelope: &TransactionEnvelope) -> SorobanTransactionData {
    let ext = match envelope {
        TransactionEnvelope::Tx(v1) => &v1.tx.ext,
        TransactionEnvelope::TxFeeBump(bump) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &bump.tx.inner_tx;
            &inner.tx.ext
        }
        // Refused by `validate_simulation_envelope`; a v0 transaction declares nothing.
        TransactionEnvelope::TxV0(_) => return SorobanTransactionData::default(),
    };
    match ext {
        TransactionExt::V1(data) => data.clone(),
        TransactionExt::V0 => SorobanTransactionData::default(),
    }
}

/// Each dimension in which the declared data does not cover the simulated data.
fn declared_shortfall(
    declared: &SorobanTransactionData,
    simulated: &SorobanTransactionData,
) -> Vec<DeclaredResource> {
    let declared_read_only: BTreeSet<&LedgerKey> =
        declared.resources.footprint.read_only.iter().collect();
    let declared_read_write: BTreeSet<&LedgerKey> =
        declared.resources.footprint.read_write.iter().collect();
    let mut short = Vec::new();
    if simulated
        .resources
        .footprint
        .read_only
        .iter()
        .any(|key| !declared_read_only.contains(key) && !declared_read_write.contains(key))
    {
        short.push(DeclaredResource::ReadOnlyFootprint);
    }
    if simulated
        .resources
        .footprint
        .read_write
        .iter()
        .any(|key| !declared_read_write.contains(key))
    {
        short.push(DeclaredResource::ReadWriteFootprint);
    }
    let (declared_limits, used) = (&declared.resources, &simulated.resources);
    for (dimension, declared_limit, used) in [
        (
            DeclaredResource::Instructions,
            declared_limits.instructions,
            used.instructions,
        ),
        (
            DeclaredResource::DiskReadBytes,
            declared_limits.disk_read_bytes,
            used.disk_read_bytes,
        ),
        (
            DeclaredResource::WriteBytes,
            declared_limits.write_bytes,
            used.write_bytes,
        ),
    ] {
        if declared_limit < used {
            short.push(dimension);
        }
    }
    if declared.resource_fee < simulated.resource_fee {
        short.push(DeclaredResource::ResourceFee);
    }
    short
}

fn redact_simulation_error(error: RpcError) -> RpcError {
    // The transport may include a plain-text HTTP error-body excerpt or a JSON-RPC
    // error that reflects the confidential envelope. Preserve the error category,
    // never endpoint-controlled text. Local envelope validation above retains its
    // useful, non-echoing diagnostics.
    match error {
        RpcError::Transport(_) => RpcError::Transport(
            "simulation transport failed (response detail withheld)".to_string(),
        ),
        RpcError::Malformed(_) => RpcError::Malformed(
            "simulation response is malformed (response detail withheld)".to_string(),
        ),
        _ => RpcError::Rpc(
            "simulation RPC refused the request (response detail withheld)".to_string(),
        ),
    }
}

fn parse_preflight(
    result: &Value,
    declared: &SorobanTransactionData,
    envelope_xdr_sha256: String,
    network_id: String,
) -> Result<PreflightObservation, RpcError> {
    let has_error = match result.get("error") {
        None => false,
        Some(Value::String(message)) if !message.is_empty() => true,
        Some(Value::String(_)) => {
            return Err(RpcError::Malformed(
                "preflight error field is empty".to_string(),
            ))
        }
        Some(_) => {
            return Err(RpcError::Malformed(
                "preflight error field is not a string".to_string(),
            ))
        }
    };
    if has_error && (result.get("restorePreamble").is_some() || result.get("results").is_some()) {
        return Err(RpcError::Malformed(
            "failed preflight also reports success or restoration".to_string(),
        ));
    }
    let reported_ledger: u32 = result
        .get("latestLedger")
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcError::Malformed("preflight lacks integer latestLedger".to_string()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("preflight latestLedger exceeds u32".to_string()))?;
    if reported_ledger == 0 {
        // stellar-rpc answers a request it refuses before reading its ledger (an envelope it
        // will not simulate) with the error and `latestLedger` 0. Nothing was simulated, and
        // the reply is well formed: it is the endpoint refusing, with its text withheld.
        return Err(if has_error {
            redact_simulation_error(RpcError::Rpc(String::new()))
        } else {
            RpcError::Malformed("preflight latestLedger cannot be zero".to_string())
        });
    }
    let outcome = if has_error {
        PreflightOutcome::SimulationFailed
    } else if let Some(restore) = result.get("restorePreamble") {
        validate_restoration(restore)?;
        PreflightOutcome::RestorationRequired
    } else {
        let simulated = validate_success(result)?;
        if restores_archived_entries(&simulated)? {
            PreflightOutcome::RestorationRequired
        } else {
            let short = declared_shortfall(declared, &simulated);
            if short.is_empty() {
                PreflightOutcome::SimulatedSuccess
            } else {
                PreflightOutcome::DeclaredResourcesInsufficient(short)
            }
        }
    };
    Ok(PreflightObservation {
        envelope_xdr_sha256,
        network_id,
        reported_ledger,
        outcome,
        auth_mode: SimulationAuthMode::Enforce,
        evidence_trust: TrustLevel::rpc_reported(),
        state_dependent: true,
        writes_committed: false,
    })
}

fn validate_success(result: &Value) -> Result<SorobanTransactionData, RpcError> {
    let results = result
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::Malformed("successful preflight lacks results".to_string()))?;
    let [one] = results.as_slice() else {
        return Err(RpcError::Malformed(format!(
            "successful preflight has {} results for one operation",
            results.len()
        )));
    };
    let returned = one
        .get("xdr")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("preflight result lacks return XDR".to_string()))?;
    ensure_base64_size("preflight return XDR", returned)?;
    ScVal::from_xdr_base64(returned, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid preflight return XDR: {error}")))?;
    let auth = one
        .get("auth")
        .and_then(Value::as_array)
        .ok_or_else(|| RpcError::Malformed("preflight result lacks auth array".to_string()))?;
    for (index, value) in auth.iter().enumerate() {
        let encoded = value.as_str().ok_or_else(|| {
            RpcError::Malformed(format!("preflight auth[{index}] is not XDR text"))
        })?;
        ensure_base64_size("preflight auth XDR", encoded)?;
        SorobanAuthorizationEntry::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RpcError::Malformed(format!("invalid preflight auth[{index}] XDR: {error}"))
        })?;
    }
    let transaction_data = result
        .get("transactionData")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::Malformed("successful preflight lacks transactionData".to_string())
        })?;
    let simulated = validate_transaction_data(transaction_data)?;
    let fee = result
        .get("minResourceFee")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::Malformed("successful preflight lacks minResourceFee".to_string())
        })?;
    fee.parse::<u64>()
        .map_err(|_| RpcError::Malformed("preflight minResourceFee is not a u64".to_string()))?;
    Ok(simulated)
}

/// Whether the simulated success needed archived entries restored first.
///
/// Since protocol 23 the endpoint restores archived entries inside the simulated invocation
/// and sends no `restorePreamble`: stellar-rpc builds the result with no preamble and
/// `soroban-simulation` lists the restored entries, by index into the simulated read-write
/// footprint, in `SorobanTransactionDataExt::V1`. That success is against restored state, not
/// the state the endpoint reports, so it is the same outcome as a preamble.
fn restores_archived_entries(simulated: &SorobanTransactionData) -> Result<bool, RpcError> {
    let SorobanTransactionDataExt::V1(ext) = &simulated.ext else {
        return Ok(false);
    };
    let writable = simulated.resources.footprint.read_write.len();
    if ext
        .archived_soroban_entries
        .iter()
        .any(|index| usize::try_from(*index).map_or(true, |index| index >= writable))
    {
        return Err(RpcError::Malformed(
            "preflight archived entry index is outside the simulated read-write footprint"
                .to_string(),
        ));
    }
    Ok(!ext.archived_soroban_entries.is_empty())
}

fn validate_restoration(restore: &Value) -> Result<(), RpcError> {
    let object = restore
        .as_object()
        .ok_or_else(|| RpcError::Malformed("restorePreamble is not an object".to_string()))?;
    let transaction_data = object
        .get("transactionData")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("restorePreamble lacks transactionData".to_string()))?;
    validate_transaction_data(transaction_data)?;
    let fee = object
        .get("minResourceFee")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("restorePreamble lacks minResourceFee".to_string()))?;
    fee.parse::<u64>().map_err(|_| {
        RpcError::Malformed("restorePreamble minResourceFee is not a u64".to_string())
    })?;
    Ok(())
}

fn validate_transaction_data(encoded: &str) -> Result<SorobanTransactionData, RpcError> {
    ensure_base64_size("preflight transactionData", encoded)?;
    SorobanTransactionData::from_xdr_base64(encoded, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid preflight transactionData: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_recorder_core::{fixtures, record, RecordOptions};
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractDataDurability, ContractId, Hash, LedgerKeyContractData, ScAddress,
        SorobanResourcesExtV0, VecM,
    };

    const NETWORK: &str = "Test SDF Network ; September 2015";

    struct CannedTransport {
        result: Result<Value, RpcError>,
        calls: RefCell<Vec<(String, Value)>>,
    }

    impl CannedTransport {
        fn new(result: Value) -> Self {
            Self {
                result: Ok(result),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl RpcTransport for CannedTransport {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.calls.borrow_mut().push((method.to_string(), params));
            if method == "getNetwork" {
                Ok(json!({
                    "passphrase": NETWORK,
                    "protocolVersion": crate::MAX_SUPPORTED_PROTOCOL
                }))
            } else {
                self.result
                    .as_ref()
                    .map(Clone::clone)
                    .map_err(|error| match error {
                        RpcError::Transport(message) => RpcError::Transport(message.clone()),
                        RpcError::Malformed(message) => RpcError::Malformed(message.clone()),
                        _ => RpcError::Rpc(error.to_string()),
                    })
            }
        }
    }

    fn envelope() -> String {
        record(&fixtures::executed_snapshot(), RecordOptions::default())
            .unwrap()
            .raw
            .envelope_xdr_base64
    }

    fn transaction_data() -> String {
        SorobanTransactionData::default()
            .to_xdr_base64(xdr_limits())
            .unwrap()
    }

    fn success() -> Value {
        json!({
            "latestLedger": 4200101,
            "results": [{
                "xdr": ScVal::Void.to_xdr_base64(xdr_limits()).unwrap(),
                "auth": []
            }],
            "transactionData": transaction_data(),
            "minResourceFee": "100"
        })
    }

    #[test]
    fn requests_auth_enforcement_and_labels_exact_state_dependent_success() {
        let tx = envelope();
        let transport = CannedTransport::new(success());
        let observation = preflight_transaction(&transport, NETWORK, &tx).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::SimulatedSuccess);
        assert_eq!(observation.auth_mode, SimulationAuthMode::Enforce);
        assert_eq!(observation.evidence_trust, TrustLevel::rpc_reported());
        // The wire labels stay the strings the shells already emit.
        let serialized = serde_json::to_value(&observation).unwrap();
        assert_eq!(serialized["auth_mode"], "enforce");
        assert_eq!(serialized["evidence_trust"], "rpc_reported");
        assert_eq!(serialized["outcome"], "simulated_success");
        assert!(observation.state_dependent);
        assert_eq!(observation.reported_ledger, 4_200_101);
        assert!(!observation.writes_committed);
        assert_eq!(
            observation.network_id,
            NetworkId::from_passphrase(NETWORK).0.to_hex()
        );
        let encoded = stellar_xdr::TransactionEnvelope::from_xdr_base64(&tx, xdr_limits())
            .unwrap()
            .to_xdr(xdr_limits())
            .unwrap();
        assert_eq!(observation.envelope_xdr_sha256, sha256(&encoded).to_hex());
        let calls = transport.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, "simulateTransaction");
        assert_eq!(calls[1].1["authMode"], "enforce");
        // The endpoint receives the hashed bytes, canonically encoded.
        assert_eq!(calls[1].1["transaction"], tx);
        let forwarded = calls[1].1["transaction"].as_str().unwrap();
        let forwarded = stellar_xdr::TransactionEnvelope::from_xdr_base64(forwarded, xdr_limits())
            .unwrap()
            .to_xdr(xdr_limits())
            .unwrap();
        assert_eq!(sha256(&forwarded).to_hex(), observation.envelope_xdr_sha256);
    }

    /// Trust and mode labels are earned by running the request, never accepted from input
    /// (docs/CHANGE-REVIEW-PLAN.md), so neither the observation nor its outcome has a
    /// deserializer that would let JSON claim `ledger_verified`, `record`, or a success. This
    /// compiles only while neither type implements `Deserialize`: with an implementation the
    /// two candidate impls below make the call ambiguous.
    #[test]
    fn an_observation_cannot_be_deserialized_into_existence() {
        trait AmbiguousIfDeserialize<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
        struct Deserializable;
        impl<T: serde::de::DeserializeOwned> AmbiguousIfDeserialize<Deserializable> for T {}
        <PreflightObservation as AmbiguousIfDeserialize<_>>::check();
        <PreflightOutcome as AmbiguousIfDeserialize<_>>::check();
    }

    #[test]
    fn a_failed_simulation_is_not_a_success_or_a_policy_denial_claim() {
        let transport = CannedTransport::new(json!({
            "latestLedger": 4200101,
            "error": "private invocation and secret authorization data"
        }));
        let observation = preflight_transaction(&transport, NETWORK, &envelope()).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::SimulationFailed);
        let serialized = serde_json::to_string(&observation).unwrap();
        assert!(!serialized.contains("private invocation"));
        assert!(!serialized.contains("secret authorization"));
    }

    #[test]
    fn restoration_is_a_separate_non_success_outcome() {
        let mut result = success();
        result["restorePreamble"] = json!({
            "transactionData": transaction_data(),
            "minResourceFee": "200"
        });
        let observation =
            preflight_transaction(&CannedTransport::new(result), NETWORK, &envelope()).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::RestorationRequired);
    }

    fn storage_key(id: u32) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash([7; 32]))),
            key: ScVal::U32(id),
            durability: ContractDataDurability::Persistent,
        })
    }

    fn with_archived(
        mut data: SorobanTransactionData,
        indices: Vec<u32>,
    ) -> SorobanTransactionData {
        data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: indices.try_into().unwrap(),
        });
        data
    }

    /// The fixture envelope with `declared` as its Soroban transaction data.
    fn envelope_declaring(declared: &SorobanTransactionData) -> String {
        let mut parsed =
            stellar_xdr::TransactionEnvelope::from_xdr_base64(envelope(), xdr_limits()).unwrap();
        let stellar_xdr::TransactionEnvelope::Tx(v1) = &mut parsed else {
            panic!("fixture has one ordinary transaction")
        };
        v1.tx.ext = stellar_xdr::TransactionExt::V1(declared.clone());
        parsed.to_xdr_base64(xdr_limits()).unwrap()
    }

    fn success_using(simulated: &SorobanTransactionData) -> Value {
        let mut result = success();
        result["transactionData"] = json!(simulated.to_xdr_base64(xdr_limits()).unwrap());
        result["minResourceFee"] = json!(simulated.resource_fee.to_string());
        result
    }

    #[test]
    fn a_success_outside_the_declared_footprint_is_not_an_unqualified_success() {
        // stellar-rpc ignores the envelope's own footprint for an invocation and reports the
        // one it recorded, so the envelope as written can still fail on submission.
        let mut simulated = SorobanTransactionData::default();
        simulated.resources.footprint.read_only = vec![storage_key(1)].try_into().unwrap();
        let observation = preflight_transaction(
            &CannedTransport::new(success_using(&simulated)),
            NETWORK,
            &envelope_declaring(&SorobanTransactionData::default()),
        )
        .unwrap();
        assert_eq!(
            observation.outcome,
            PreflightOutcome::DeclaredResourcesInsufficient(vec![
                DeclaredResource::ReadOnlyFootprint
            ])
        );
    }

    fn realistic_usage() -> SorobanTransactionData {
        let mut data = SorobanTransactionData::default();
        data.resources.footprint.read_only = vec![storage_key(1)].try_into().unwrap();
        data.resources.footprint.read_write = vec![storage_key(2)].try_into().unwrap();
        data.resources.instructions = 1_000_000;
        data.resources.disk_read_bytes = 2_000;
        data.resources.write_bytes = 300;
        data.resource_fee = 40_000;
        data
    }

    fn outcome_declaring(simulated: &SorobanTransactionData, envelope: &str) -> PreflightOutcome {
        preflight_transaction(
            &CannedTransport::new(success_using(simulated)),
            NETWORK,
            envelope,
        )
        .unwrap()
        .outcome
    }

    #[test]
    fn declared_resources_are_compared_with_the_simulation_dimension_by_dimension() {
        let simulated = realistic_usage();
        // Controls: exactly what was used covers it, and so does declaring a read as a
        // write, because a read-write footprint entry also permits reads.
        assert_eq!(
            outcome_declaring(&simulated, &envelope_declaring(&simulated)),
            PreflightOutcome::SimulatedSuccess
        );
        let mut widened = simulated.clone();
        widened.resources.footprint.read_only = VecM::default();
        widened.resources.footprint.read_write =
            vec![storage_key(2), storage_key(1)].try_into().unwrap();
        assert_eq!(
            outcome_declaring(&simulated, &envelope_declaring(&widened)),
            PreflightOutcome::SimulatedSuccess
        );

        type Shrink = fn(&mut SorobanTransactionData);
        let cases: [(Shrink, DeclaredResource); 6] = [
            (
                |data| data.resources.footprint.read_only = VecM::default(),
                DeclaredResource::ReadOnlyFootprint,
            ),
            (
                // The written key is declared, but only for reading.
                |data| {
                    data.resources.footprint.read_only =
                        vec![storage_key(1), storage_key(2)].try_into().unwrap();
                    data.resources.footprint.read_write = VecM::default();
                },
                DeclaredResource::ReadWriteFootprint,
            ),
            (
                |data| data.resources.instructions -= 1,
                DeclaredResource::Instructions,
            ),
            (
                |data| data.resources.disk_read_bytes -= 1,
                DeclaredResource::DiskReadBytes,
            ),
            (
                |data| data.resources.write_bytes -= 1,
                DeclaredResource::WriteBytes,
            ),
            (|data| data.resource_fee -= 1, DeclaredResource::ResourceFee),
        ];
        for (shrink, dimension) in cases {
            let mut declared = simulated.clone();
            shrink(&mut declared);
            assert_eq!(
                outcome_declaring(&simulated, &envelope_declaring(&declared)),
                PreflightOutcome::DeclaredResourcesInsufficient(vec![dimension])
            );
        }

        // An envelope with no Soroban transaction data declares nothing, and a fee bump
        // declares its inner transaction's data.
        assert_eq!(
            outcome_declaring(&simulated, &envelope()),
            PreflightOutcome::DeclaredResourcesInsufficient(vec![
                DeclaredResource::ReadOnlyFootprint,
                DeclaredResource::ReadWriteFootprint,
                DeclaredResource::Instructions,
                DeclaredResource::DiskReadBytes,
                DeclaredResource::WriteBytes,
                DeclaredResource::ResourceFee,
            ])
        );
        assert_eq!(
            outcome_declaring(&simulated, &fee_bump_declaring(&simulated)),
            PreflightOutcome::SimulatedSuccess
        );
        let mut short = simulated.clone();
        short.resources.instructions -= 1;
        assert_eq!(
            outcome_declaring(&simulated, &fee_bump_declaring(&short)),
            PreflightOutcome::DeclaredResourcesInsufficient(vec![DeclaredResource::Instructions])
        );
    }

    fn fee_bump_declaring(declared: &SorobanTransactionData) -> String {
        let stellar_xdr::TransactionEnvelope::Tx(inner) =
            stellar_xdr::TransactionEnvelope::from_xdr_base64(
                envelope_declaring(declared),
                xdr_limits(),
            )
            .unwrap()
        else {
            panic!("fixture has one ordinary transaction")
        };
        stellar_xdr::TransactionEnvelope::TxFeeBump(stellar_xdr::FeeBumpTransactionEnvelope {
            tx: stellar_xdr::FeeBumpTransaction {
                fee_source: stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256([9; 32])),
                fee: 200,
                inner_tx: stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner),
                ext: stellar_xdr::FeeBumpTransactionExt::V0,
            },
            signatures: VecM::default(),
        })
        .to_xdr_base64(xdr_limits())
        .unwrap()
    }

    #[test]
    fn auto_restored_archived_entries_are_restoration_not_success() {
        // Since protocol 23 stellar-rpc sends no restorePreamble for an invocation. The
        // archived entries it had to restore to reach success are listed by read-write
        // footprint index in the simulated transaction data instead.
        let mut data = SorobanTransactionData::default();
        data.resources.footprint.read_write = vec![storage_key(1)].try_into().unwrap();
        let mut result = success();
        result["transactionData"] = json!(with_archived(data, vec![0])
            .to_xdr_base64(xdr_limits())
            .unwrap());
        let observation =
            preflight_transaction(&CannedTransport::new(result), NETWORK, &envelope()).unwrap();
        assert_eq!(observation.outcome, PreflightOutcome::RestorationRequired);
    }

    #[test]
    fn malformed_or_contradictory_replies_cannot_claim_success() {
        let mut missing_auth = success();
        missing_auth["results"][0]
            .as_object_mut()
            .unwrap()
            .remove("auth");
        let mut invalid_xdr = success();
        invalid_xdr["results"][0]["xdr"] = json!("invalid");
        let mut invalid_auth = success();
        invalid_auth["results"][0]["auth"] = json!(["invalid"]);
        let mut many_results = success();
        many_results["results"] = json!([
            success()["results"][0].clone(),
            success()["results"][0].clone()
        ]);
        let mut failed_and_success = success();
        failed_and_success["error"] = json!("failed");
        for result in [
            json!({"results": success()["results"], "transactionData": transaction_data(), "minResourceFee": "100"}),
            json!({"latestLedger": 0, "results": success()["results"], "transactionData": transaction_data(), "minResourceFee": "100"}),
            missing_auth,
            invalid_xdr,
            invalid_auth,
            many_results,
            failed_and_success,
            json!({"latestLedger": 4200101, "error": ""}),
            json!({"latestLedger": 4200101, "results": success()["results"], "transactionData": "invalid", "minResourceFee": "100"}),
            json!({"latestLedger": 4200101, "restorePreamble": {"transactionData": "invalid", "minResourceFee": "100"}}),
            json!({"latestLedger": 4200101, "restorePreamble": {"transactionData": transaction_data(), "minResourceFee": "-1"}}),
            json!({
                "latestLedger": 4200101,
                "results": success()["results"],
                "transactionData": with_archived(SorobanTransactionData::default(), vec![0])
                    .to_xdr_base64(xdr_limits())
                    .unwrap(),
                "minResourceFee": "100"
            }),
        ] {
            assert!(
                matches!(
                    preflight_transaction(&CannedTransport::new(result), NETWORK, &envelope()),
                    Err(RpcError::Malformed(_))
                ),
                "malformed response must not be reported as a successful simulation"
            );
        }
    }

    #[test]
    fn a_refusal_before_simulation_is_an_rpc_refusal_not_a_malformed_reply() {
        // stellar-rpc refuses some requests before it reads its ledger and answers with the
        // error and `latestLedger` 0. That is the endpoint declining, not a broken reply.
        let transport = CannedTransport::new(json!({
            "latestLedger": 0,
            "error": "private invocation echoed in a refusal"
        }));
        let error = preflight_transaction(&transport, NETWORK, &envelope()).unwrap_err();
        assert!(matches!(error, RpcError::Rpc(_)), "{error}");
        assert!(!error.to_string().contains("private invocation"));
    }

    #[test]
    fn a_memo_is_refused_before_any_request() {
        let mut parsed = TransactionEnvelope::from_xdr_base64(envelope(), xdr_limits()).unwrap();
        let TransactionEnvelope::Tx(v1) = &mut parsed else {
            panic!("fixture has one ordinary transaction")
        };
        v1.tx.memo = stellar_xdr::Memo::Text("private invoice".try_into().unwrap());
        let transport = CannedTransport::new(success());
        let error = preflight_transaction(
            &transport,
            NETWORK,
            &parsed.to_xdr_base64(xdr_limits()).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(&error, RpcError::UnsupportedEnvelope(message) if message.contains("memo")),
            "{error}"
        );
        assert!(error.to_string().starts_with("E_UNSUPPORTED_ENVELOPE: "));
        assert!(!error.to_string().contains("private invoice"));
        assert!(transport.calls.borrow().is_empty());
    }

    #[test]
    fn whitespace_anywhere_in_an_envelope_is_refused_before_any_request() {
        // The XDR decoder skips ASCII whitespace, so a spaced-out envelope would decode and
        // hash as the canonical bytes while a different string went to the endpoint.
        let tx = envelope();
        let (head, tail) = tx.split_at(tx.len() / 2);
        for whitespace in [" ", "\t", "\n", "\r\n", "\x0c"] {
            for spaced in [
                format!("{head}{whitespace}{tail}"),
                format!("{tx}{whitespace}"),
                format!("{whitespace}{tx}"),
            ] {
                let transport = CannedTransport::new(success());
                let error = preflight_transaction(&transport, NETWORK, &spaced).unwrap_err();
                assert!(
                    matches!(&error, RpcError::EnvelopeParse(message) if message.contains("whitespace")),
                    "{whitespace:?}: {error}"
                );
                assert!(transport.calls.borrow().is_empty(), "{whitespace:?}");
            }
        }
    }

    #[test]
    fn local_input_refusals_carry_input_codes_before_any_request() {
        // The caller's own input, refused here, is not a reply from the endpoint: an agent
        // told "malformed response" would look for a fault in the RPC instead of its envelope.
        let oversized = "A".repeat(crate::MAX_XDR_BASE64_BYTES + 1);
        for (input, code) in [
            (oversized.as_str(), "E_RESOURCE_LIMIT: "),
            ("not-base64", "E_ENVELOPE_PARSE: "),
            ("AAAA", "E_ENVELOPE_PARSE: "),
        ] {
            let transport = CannedTransport::new(success());
            let error = preflight_transaction(&transport, NETWORK, input)
                .unwrap_err()
                .to_string();
            assert!(error.starts_with(code), "{error}");
            assert!(!error.contains("response"), "{error}");
            assert!(transport.calls.borrow().is_empty(), "{error}");
        }
    }

    #[test]
    fn malformed_envelope_stops_before_network_and_rpc_error_detail_is_withheld() {
        let transport = CannedTransport::new(success());
        assert!(preflight_transaction(&transport, NETWORK, "not XDR").is_err());
        assert!(transport.calls.borrow().is_empty());

        let refusing = CannedTransport {
            result: Err(RpcError::Rpc(
                "secret envelope echoed by endpoint".to_string(),
            )),
            calls: RefCell::new(Vec::new()),
        };
        let error = preflight_transaction(&refusing, NETWORK, &envelope())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret envelope"));

        let gateway = CannedTransport {
            result: Err(RpcError::Transport(
                "HTTP 400: secret envelope echoed as plain text".to_string(),
            )),
            calls: RefCell::new(Vec::new()),
        };
        let error = preflight_transaction(&gateway, NETWORK, &envelope())
            .unwrap_err()
            .to_string();
        assert!(error.contains("transport"));
        assert!(!error.contains("secret envelope"));
    }
}
