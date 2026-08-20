//! Soroban RPC acquisition adapter (architecture §4.1, §4.11).
//!
//! Does the network I/O and produces immutable, trust-labeled [`EvidenceSnapshot`]s for
//! the pure recorder. Executed transactions and record-mode simulations both come back
//! as `rpc_reported` — trusted exactly as far as the configured endpoint is. The
//! transport is split from the JSON handling so the parsing is unit-testable offline.

#![forbid(unsafe_code)]

use ozpb_recorder_core::{
    referenced_contract_addresses, EvidenceSnapshot, ExecutableObservation, ObservedExecutable,
    StateChange, StateChangeKind, StateChangeSource,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntry, LedgerEntryData,
    LedgerKey, LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, TransactionEnvelope,
    TransactionResult, TransactionResultResult, WriteXdr,
};

// Keep acquisition aligned with recorder-core's per-value bound. Accepted evidence must remain
// small enough for the recorder's canonical 4 MiB hash preimage after decoding and summarizing.
const MAX_XDR_BYTES: usize = 512 * 1024;
// The base64 form of the byte bound, named once: three fields are checked against it today
// and each new XDR field the RPC gains is another chance to mistype the arithmetic.
const MAX_XDR_BASE64_BYTES: usize = MAX_XDR_BYTES.div_ceil(3) * 4;
const MAX_XDR_DEPTH: u32 = 128;
const MAX_HTTP_RESPONSE_BYTES: usize = 24 * 1024 * 1024;
/// How much of a non-JSON-RPC error body an error message may quote.
const MAX_ERROR_BODY_EXCERPT_BYTES: usize = 200;
/// The official `getLedgerEntries` maximum for its `keys` array. Not our budget to choose: the
/// endpoint refuses a longer array, and recorder-core admits more executable observations than
/// this (its bound is one per contract an authorization can reach), so the requests are batched
/// to fit rather than the recorder's bound being lowered to one RPC method's page size.
const MAX_LEDGER_ENTRY_KEYS: usize = 200;
/// The newest Stellar protocol this build can be trusted to decode: the major version of the
/// `stellar-xdr` release it is pinned to. A network on a newer protocol can emit XDR shapes this
/// reader does not know, and the failure mode that matters is not the decode error — it is the
/// newer shape that still decodes into something subtly different. The alternative to a ceiling
/// is discovering that in a recording.
///
/// There is deliberately no floor. `getNetwork` reports the protocol the endpoint is on now,
/// which bounds what it can newly produce; it says nothing about the protocol of an old
/// transaction whose stored XDR is what a `getTransaction` actually returns, so a floor checked
/// against this field would be a claim about the wrong thing.
///
/// Raising this is an upgrade decision: bump `stellar-xdr`, then this — a test holds the two
/// together.
///
/// This gates acquisition. Whether the acquisition protocol should also be *recorded* is not
/// settled here and is not settled by §4.1: that section rules out a per-transaction
/// **historical** protocol anchor, because the endpoint's current protocol would describe the
/// wrong ledger for an old transaction (`docs/architecture.md:210-213`). "The endpoint was on
/// protocol 27 when this evidence was acquired" is a different and true statement, which that
/// argument does not reach — and the risk table still promises protocol and XDR versions per
/// bundle (`docs/architecture.md:1394`), so that promise is outstanding rather than withdrawn
/// by this gate.
const MAX_SUPPORTED_PROTOCOL: u32 = 27;

/// The limits every parse in this adapter runs under. Public so conformance tests decode
/// captured responses under exactly the production configuration instead of restating the
/// numbers, which would let the fixtures and the parser drift apart silently.
pub fn xdr_limits() -> Limits {
    Limits {
        depth: MAX_XDR_DEPTH,
        len: MAX_XDR_BYTES,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("E_RPC: transport error: {0}")]
    Transport(String),
    #[error("E_RPC: malformed response: {0}")]
    Malformed(String),
    #[error("E_RPC: rpc error: {0}")]
    Rpc(String),
    #[error("E_TX_NOT_FOUND: transaction {0} not found (may be outside RPC retention)")]
    NotFound(String),
    #[error("E_NETWORK_MISMATCH: expected '{expected}', RPC reports '{actual}'")]
    NetworkMismatch { expected: String, actual: String },
    /// The endpoint is on a protocol this build's pinned XDR does not cover. Its own variant so
    /// a caller can recognize "upgrade the toolkit" without matching on message text.
    #[error(
        "E_RPC: unsupported protocol: the endpoint reports protocol {reported}, and this build \
         decodes at most {supported}"
    )]
    UnsupportedProtocol { reported: u32, supported: u32 },
    #[error("E_RPC: recording evidence error: {0}")]
    Evidence(String),
}

/// A minimal JSON-RPC transport. The real client uses HTTP; tests inject a canned
/// responder so parsing is verified without a network.
pub trait RpcTransport {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError>;
}

/// HTTP transport over a single Soroban RPC endpoint.
pub struct HttpTransport {
    url: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            // Redirects could escape a hosted server's exact RPC allowlist and turn an
            // otherwise approved endpoint into SSRF. Callers must approve the final URL.
            .redirects(0)
            .build();
        HttpTransport {
            url: url.into(),
            agent,
        }
    }
}

impl RpcTransport for HttpTransport {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let req = json!({
            "jsonrpc": "2.0",
            "id": JSONRPC_REQUEST_ID,
            "method": method,
            "params": params
        });
        match self.agent.post(&self.url).send_json(req) {
            Ok(response) => {
                let body = read_bounded_body(response)?;
                let envelope: serde_json::Value = serde_json::from_slice(&body)
                    .map_err(|error| RpcError::Malformed(error.to_string()))?;
                jsonrpc_result(&envelope)
            }
            // A rejected call arrives as an HTTP error status carrying the JSON-RPC error in
            // its body, and the body is the half that says what was wrong. Read it under the
            // same bound and report what the endpoint said. When there is no envelope in
            // there, the status is what remains, with what the two arms below allow.
            Err(ureq::Error::Status(code, response)) => {
                let body = read_bounded_body(response)?;
                let parsed = serde_json::from_slice::<serde_json::Value>(&body).ok();
                if let Some(refusal) = parsed.as_ref().and_then(jsonrpc_error_of) {
                    return Err(RpcError::Rpc(refusal));
                }
                let detail = match parsed {
                    // A body that parses as JSON is not quoted. An endpoint or gateway that
                    // reflects the request would put the transaction envelope in it, and a
                    // simulated envelope is confidential input (architecture §6.5) that has no
                    // business in an error message on its way to a log.
                    Some(_) => String::new(),
                    // Not JSON at all: a proxy or gateway answered instead of the endpoint, and
                    // its page is what says which.
                    None => format!(": {}", body_excerpt(&body)),
                };
                Err(RpcError::Transport(format!(
                    "HTTP {code} from the endpoint{detail}"
                )))
            }
            Err(error) => Err(RpcError::Transport(error.to_string())),
        }
    }
}

/// The JSON-RPC error an error-status body carries, if it carries one.
///
/// Only a genuine envelope error counts: otherwise a gateway's JSON page would be reported as a
/// complaint about JSON-RPC framing, which is a statement about the wrong party. The id is
/// deliberately not correlated here — an endpoint refusing with an HTTP error need not echo it,
/// and nothing from this path is admitted as evidence; it is a message for the operator, so the
/// message is worth more than the correlation.
fn jsonrpc_error_of(envelope: &serde_json::Value) -> Option<String> {
    if envelope.get("jsonrpc").and_then(|value| value.as_str()) != Some("2.0") {
        return None;
    }
    let error = envelope.get("error").filter(|value| !value.is_null())?;
    Some(describe_jsonrpc_error(error))
}

/// The response body under the transport's byte bound.
///
/// Both the declared length and the reader are capped: `Content-Length` can be absent, or a
/// lie, or describe compressed bytes, so the header check alone bounds nothing.
fn read_bounded_body(response: ureq::Response) -> Result<Vec<u8>, RpcError> {
    if response
        .header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_HTTP_RESPONSE_BYTES)
    {
        return Err(RpcError::Malformed(format!(
            "response exceeds the {MAX_HTTP_RESPONSE_BYTES}-byte limit"
        )));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((MAX_HTTP_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| RpcError::Transport(error.to_string()))?;
    if bytes.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(RpcError::Malformed(format!(
            "response exceeds the {MAX_HTTP_RESPONSE_BYTES}-byte limit"
        )));
    }
    Ok(bytes)
}

/// Enough of a non-JSON-RPC body to identify what answered, and not more: the body may be
/// megabytes of HTML, and an error message is not a place to put it.
fn body_excerpt(body: &[u8]) -> String {
    let head = &body[..body.len().min(MAX_ERROR_BODY_EXCERPT_BYTES)];
    // Cut at a character boundary: a body truncated mid-sequence would otherwise be reported
    // with corruption that is not in it. Genuinely invalid bytes take the same path, which is
    // the valid prefix and nothing invented for the rest.
    let text = match std::str::from_utf8(head) {
        Ok(text) => text,
        Err(error) => std::str::from_utf8(&head[..error.valid_up_to()]).unwrap_or_default(),
    };
    let trimmed = text.trim();
    if body.len() > head.len() {
        format!("{trimmed}…")
    } else {
        trimmed.to_string()
    }
}

/// The id every request from this transport carries. One in-flight synchronous call at a time,
/// so a constant is enough — what matters is that the response is checked against it.
const JSONRPC_REQUEST_ID: u64 = 1;

/// The `result` of a JSON-RPC 2.0 response to *our* request.
///
/// The previous version accepted any object with a `result` or an `error` key, which is to say
/// it accepted a response to some other request, or to no request at all. A configured endpoint
/// is already the trust boundary and these calls are synchronous, so this is not a live race;
/// it is what catches a proxy, a cache or a mock returning the wrong payload, and it is what
/// the protocol asks of a client either way.
fn jsonrpc_result(response: &serde_json::Value) -> Result<serde_json::Value, RpcError> {
    if response.get("jsonrpc").and_then(|value| value.as_str()) != Some("2.0") {
        return Err(RpcError::Malformed(
            "response does not declare itself JSON-RPC 2.0".to_string(),
        ));
    }
    let error = response
        .get("error")
        .filter(|value| !value.is_null())
        .map(describe_jsonrpc_error);
    let id = response.get("id").unwrap_or(&serde_json::Value::Null);
    // The specification allows a null id only on an error the server could not attribute to a
    // request — a parse error, typically. A *result* with no id answers nothing.
    let answers_this_request =
        id.as_u64() == Some(JSONRPC_REQUEST_ID) || (error.is_some() && id.is_null());
    if !answers_this_request {
        return Err(RpcError::Malformed(format!(
            "response id {id} does not match request id {JSONRPC_REQUEST_ID}"
        )));
    }
    match (response.get("result"), error) {
        (Some(_), Some(_)) => Err(RpcError::Malformed(
            "response carries both a result and an error".to_string(),
        )),
        (None, None) => Err(RpcError::Malformed(
            "response carries neither a result nor an error".to_string(),
        )),
        (None, Some(error)) => Err(RpcError::Rpc(error)),
        (Some(result), None) => Ok(result.clone()),
    }
}

/// A JSON-RPC error object as its code and message, so a caller reads what happened instead of
/// re-parsing a blob of JSON. Anything not shaped like the documented object is kept verbatim
/// rather than described as something it is not.
fn describe_jsonrpc_error(error: &serde_json::Value) -> String {
    let code = error.get("code").and_then(serde_json::Value::as_i64);
    let message = error.get("message").and_then(|value| value.as_str());
    match (code, message) {
        (Some(code), Some(message)) => match error.get("data") {
            Some(data) => format!("code {code}: {message} ({data})"),
            None => format!("code {code}: {message}"),
        },
        _ => error.to_string(),
    }
}

/// Fetch an executed transaction by hash and build a snapshot (`rpc_reported`).
pub fn get_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    tx_hash: &str,
) -> Result<EvidenceSnapshot, RpcError> {
    let requested_hash = ozpb_domain::Hash32::from_hex(tx_hash).map_err(|_| {
        RpcError::Malformed(
            "transaction hash must be exactly 64 hexadecimal characters".to_string(),
        )
    })?;
    let canonical_hash = requested_hash.to_hex();
    verify_network(transport, network_passphrase)?;
    let result = transport.call(
        "getTransaction",
        json!({ "hash": canonical_hash, "xdrFormat": "base64" }),
    )?;
    let snapshot = parse_get_transaction(network_passphrase, &canonical_hash, &result)?;
    acquire_contract_executables(transport, snapshot)
}

fn parse_get_transaction(
    network_passphrase: &str,
    tx_hash: &str,
    result: &serde_json::Value,
) -> Result<EvidenceSnapshot, RpcError> {
    let status = str_field(result, "status")?;
    match status.as_str() {
        "NOT_FOUND" => return Err(RpcError::NotFound(tx_hash.to_string())),
        "SUCCESS" | "FAILED" => {}
        other => return Err(RpcError::Rpc(format!("unexpected tx status: {other}"))),
    }
    let returned_hash = str_field(result, "txHash")?;
    let returned_hash = ozpb_domain::Hash32::from_hex(&returned_hash)
        .map_err(|_| {
            RpcError::Malformed("field 'txHash' is not a 32-byte hexadecimal hash".to_string())
        })?
        .to_hex();
    if returned_hash != tx_hash {
        return Err(RpcError::Malformed(format!(
            "response txHash {returned_hash} does not match requested transaction {tx_hash}"
        )));
    }
    let envelope = str_field(result, "envelopeXdr")?;
    ensure_base64_size("envelopeXdr", &envelope)?;
    let decoded_envelope = TransactionEnvelope::from_xdr_base64(&envelope, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid envelopeXdr: {error}")))?;
    let computed_hash = decoded_envelope
        .hash(
            ozpb_domain::NetworkId::from_passphrase(network_passphrase)
                .0
                 .0,
        )
        .map(ozpb_domain::Hash32)
        .map_err(|error| RpcError::Malformed(format!("cannot hash envelopeXdr: {error}")))?
        .to_hex();
    if computed_hash != tx_hash {
        return Err(RpcError::Malformed(format!(
            "envelopeXdr hashes to {computed_hash}, not requested transaction {tx_hash}"
        )));
    }
    // The success label must be checkable against evidence: require the transaction result
    // and reject a status string that contradicts it. The stored snapshot keeps
    // status-derived success only after this agreement check.
    //
    // This is a stated requirement on the endpoint, not a tolerated omission. `resultXdr` is
    // part of the documented `getTransaction` response for SUCCESS/FAILED (see the Stellar
    // RPC method reference; the captured live testnet response in
    // `tests/captured-testnet/getTransaction.json` carries it), so an endpoint that omits it
    // cannot support checked acquisition. Accepting it anyway would mean labelling evidence
    // `rpc_reported` while nothing verified the outcome — the unchecked boolean this whole
    // path exists to remove — so the response is refused instead.
    let result_xdr = str_field(result, "resultXdr")?;
    ensure_base64_size("resultXdr", &result_xdr)?;
    let decoded_result = TransactionResult::from_xdr_base64(&result_xdr, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid resultXdr: {error}")))?;
    // Success and the operation results it claims, from one match, so the two cannot disagree.
    let (result_success, operations): (bool, &[stellar_xdr::OperationResult]) =
        match &decoded_result.result {
            TransactionResultResult::TxSuccess(operations) => (true, operations),
            TransactionResultResult::TxFeeBumpInnerSuccess(pair) => {
                let stellar_xdr::InnerTransactionResultResult::TxSuccess(operations) =
                    &pair.result.result
                else {
                    // The outer union says the inner transaction succeeded and the inner one
                    // says otherwise: the result contradicts itself before anything is
                    // compared to it.
                    return Err(RpcError::Malformed(
                        "the transaction result reports fee-bump inner success but its inner \
                         transaction result does not"
                            .to_string(),
                    ));
                };
                (true, operations)
            }
            _ => (false, &[]),
        };
    if result_success != (status == "SUCCESS") {
        return Err(RpcError::Malformed(format!(
            "status '{status}' contradicts the decoded transaction result, which records {}",
            if result_success { "success" } else { "failure" }
        )));
    }
    // `SUCCESS` is a claim about the operations as well. Nothing binds `resultXdr` to the
    // transaction hash the way `envelopeXdr` is bound — the ledger commits the result set's
    // Merkle root, not this field — so internal consistency is all that can be established
    // about it, and two things about a reported success are checkable that way.
    //
    // Its length: the envelope is hash-bound to the requested transaction, so its operation
    // count is a fact, and a result set of a different length is about a different
    // transaction. `TxSuccess([])` for a one-operation transaction is the cheapest form of
    // that, and it is what a result set carrying no per-operation claims at all looks like.
    let expected_results = envelope_operations(&decoded_envelope).len();
    if result_success && operations.len() != expected_results {
        return Err(RpcError::Malformed(format!(
            "the transaction result reports {} operation results for an envelope with \
             {expected_results} operations",
            operations.len()
        )));
    }
    // And each result, as far as this crate reads them: a transaction succeeds only if all of
    // its operations do, so a `txSUCCESS` carrying an operation that did not succeed
    // contradicts itself. Partial cover, not complete — `operation_succeeded` judges the
    // outer arms and the `InvokeHostFunction` results, and answers "succeeded" for the other
    // operation kinds rather than interpreting code enums this crate does not record. A forged
    // result can still hide a failed non-Soroban operation inside `TxSuccess`; that fail-open
    // is known and filed, and this comment does not claim otherwise.
    if let Some(index) = operations
        .iter()
        .position(|operation| !operation_succeeded(operation))
    {
        return Err(RpcError::Malformed(format!(
            "status '{status}' but operation {index} of the transaction result did not succeed"
        )));
    }
    // Optional, but not therefore unchecked: bounded here like every other XDR field, and a
    // value of some other type is refused rather than silently dropped as absent evidence.
    let meta = match result.get("resultMetaXdr") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => {
            ensure_base64_size("resultMetaXdr", text)?;
            Some(text.clone())
        }
        Some(_) => {
            return Err(RpcError::Malformed(
                "field 'resultMetaXdr' is not base64 XDR text".to_string(),
            ))
        }
    };
    let ledger: u32 = result
        .get("ledger")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::Malformed("missing integer field 'ledger'".to_string()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("field 'ledger' exceeds u32".to_string()))?;
    let created_at = result
        .get("createdAt")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| RpcError::Malformed("missing integer field 'createdAt'".to_string()))?;
    Ok(EvidenceSnapshot::from_rpc_transaction(
        network_passphrase,
        envelope,
        meta,
        ledger,
        created_at,
        status == "SUCCESS",
    ))
}

/// The operations a transaction envelope carries. A fee bump wraps a transaction, so its
/// operations are the inner transaction's — the same unwrapping the recorder does, and the same
/// one both callers here need: one to count results against, one to check the shape of.
fn envelope_operations(envelope: &TransactionEnvelope) -> &[stellar_xdr::Operation] {
    match envelope {
        TransactionEnvelope::Tx(v1) => v1.tx.operations.as_slice(),
        TransactionEnvelope::TxFeeBump(bump) => {
            let stellar_xdr::FeeBumpTransactionInnerTx::Tx(inner) = &bump.tx.inner_tx;
            inner.tx.operations.as_slice()
        }
        TransactionEnvelope::TxV0(v0) => v0.tx.operations.as_slice(),
    }
}

/// Whether one operation result reports success.
///
/// Every outer arm other than `OpInner` is a failure by definition. Within `OpInner`, only the
/// `InvokeHostFunction` arm is judged: that is the operation kind this adapter records, and
/// every other kind carries its own result enum whose codes are not this crate's to interpret.
///
/// So this **fails open** for those kinds — it answers `true` for an inner result it did not
/// read — and a forged `TxSuccess` can hide a failed non-Soroban operation from it. Covering
/// the remaining kinds means a match over every `OperationResultTr` arm and its own success
/// variant; that is filed separately rather than half-done here.
fn operation_succeeded(operation: &stellar_xdr::OperationResult) -> bool {
    use stellar_xdr::{InvokeHostFunctionResult, OperationResult, OperationResultTr};
    match operation {
        OperationResult::OpInner(OperationResultTr::InvokeHostFunction(invoke)) => {
            matches!(invoke, InvokeHostFunctionResult::Success(_))
        }
        OperationResult::OpInner(_) => true,
        _ => false,
    }
}

/// Simulate an unsigned envelope in record mode and build a snapshot (`rpc_reported`;
/// confidential input — §6.5).
pub fn simulate_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    envelope_xdr_base64: &str,
) -> Result<EvidenceSnapshot, RpcError> {
    validate_simulation_envelope(envelope_xdr_base64)?;
    verify_network(transport, network_passphrase)?;
    let result = transport.call(
        "simulateTransaction",
        json!({
            "transaction": envelope_xdr_base64,
            "authMode": "record",
            "xdrFormat": "base64"
        }),
    )?;
    let snapshot = parse_simulate(network_passphrase, envelope_xdr_base64, &result)?;
    acquire_contract_executables(transport, snapshot)
}

/// What the caller's envelope has to be before it is worth sending anywhere.
///
/// The transaction-hash path already rejects bad input before its first request; the
/// simulation path took the caller's envelope straight to `getNetwork` and
/// `simulateTransaction` and learned only afterwards — from the recorder, two round trips
/// later — that it was not XDR, was larger than any evidence the recorder will accept, or
/// was a shape simulation cannot take. Everything checked here is knowable without the
/// network, and the endpoint's time and bandwidth are not ours to spend on it.
///
/// `simulateTransaction` takes a transaction carrying exactly one operation, and this adapter
/// records Soroban invocations, so that operation must be an `InvokeHostFunction`.
fn validate_simulation_envelope(envelope_xdr_base64: &str) -> Result<(), RpcError> {
    ensure_base64_size("transaction", envelope_xdr_base64)?;
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr_base64, xdr_limits())
        .map_err(|error| RpcError::Malformed(format!("invalid transaction envelope: {error}")))?;
    // Pre-Soroban envelopes cannot carry an InvokeHostFunction operation at all; the recorder
    // refuses them too, and saying so here costs no round trip.
    if matches!(envelope, TransactionEnvelope::TxV0(_)) {
        return Err(RpcError::Malformed(
            "a TransactionV0 envelope cannot carry a Soroban operation".to_string(),
        ));
    }
    let operations = envelope_operations(&envelope);
    let [operation] = operations else {
        return Err(RpcError::Malformed(format!(
            "simulation takes a transaction with exactly one operation; this envelope has {}",
            operations.len()
        )));
    };
    if !matches!(
        operation.body,
        stellar_xdr::OperationBody::InvokeHostFunction(_)
    ) {
        return Err(RpcError::Malformed(
            "the operation to simulate must be an InvokeHostFunction".to_string(),
        ));
    }
    Ok(())
}

fn acquire_contract_executables<T: RpcTransport>(
    transport: &T,
    snapshot: EvidenceSnapshot,
) -> Result<EvidenceSnapshot, RpcError> {
    let addresses = referenced_contract_addresses(&snapshot)
        .map_err(|error| RpcError::Evidence(error.to_string()))?;
    if addresses.is_empty() {
        return Ok(snapshot);
    }

    let mut requested = BTreeMap::new();
    for address in addresses {
        let contract = address
            .parse::<stellar_strkey::Contract>()
            .map_err(|error| {
                RpcError::Evidence(format!("invalid referenced contract {address}: {error}"))
            })?;
        let sc_address = ScAddress::Contract(ContractId(Hash(contract.0)));
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_address.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let encoded_key = key
            .to_xdr_base64(xdr_limits())
            .map_err(|error| RpcError::Evidence(error.to_string()))?;
        requested.insert(encoded_key, (address, sc_address));
    }

    // One request per `MAX_LEDGER_ENTRY_KEYS` keys. Each batch is checked against its own
    // requested keys and dated by its own `latestLedger`, so a recording made of several
    // batches says which moment each observation came from instead of presenting them all as
    // one. Nothing is claimed across batches: an executable that changed between two requests
    // is not detectable here, and `ExecutableObservation` already carries the ledger per
    // observation precisely so it does not have to be.
    let mut observations = BTreeMap::new();
    let all: Vec<(&String, &(String, ScAddress))> = requested.iter().collect();
    for batch in all.chunks(MAX_LEDGER_ENTRY_KEYS) {
        let batch: BTreeMap<String, (String, ScAddress)> = batch
            .iter()
            .map(|(key, value)| ((*key).clone(), (*value).clone()))
            .collect();
        let keys: Vec<&String> = batch.keys().collect();
        let result = transport.call(
            "getLedgerEntries",
            json!({ "keys": keys, "xdrFormat": "base64" }),
        )?;
        observations.extend(parse_contract_executables(&result, &batch)?);
    }
    Ok(snapshot.with_contract_executables(observations))
}

fn parse_contract_executables(
    result: &serde_json::Value,
    requested: &BTreeMap<String, (String, ScAddress)>,
) -> Result<BTreeMap<String, ExecutableObservation>, RpcError> {
    let observed_ledger: u32 = result
        .get("latestLedger")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("getLedgerEntries has no integer latestLedger".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("latestLedger exceeds u32".to_string()))?;
    let entries = result
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| RpcError::Malformed("getLedgerEntries has no entries array".to_string()))?;
    let mut observations = BTreeMap::new();
    let mut seen_keys = std::collections::BTreeSet::new();
    for (index, value) in entries.iter().enumerate() {
        let key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RpcError::Malformed(format!("getLedgerEntries entry {index} has no string key"))
            })?;
        let (address, expected_address) = requested.get(key).ok_or_else(|| {
            RpcError::Malformed(format!(
                "getLedgerEntries returned an unrequested key at entry {index}"
            ))
        })?;
        if !seen_keys.insert(key.to_string()) {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries returned duplicate key at entry {index}"
            )));
        }
        let encoded = value
            .get("xdr")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                RpcError::Malformed(format!("getLedgerEntries entry {index} has no string xdr"))
            })?;
        let last_modified_ledger: u32 = value
            .get("lastModifiedLedgerSeq")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} has no integer lastModifiedLedgerSeq"
                ))
            })?
            .try_into()
            .map_err(|_| {
                RpcError::Malformed(format!(
                    "getLedgerEntries entry {index} lastModifiedLedgerSeq exceeds u32"
                ))
            })?;
        // `getLedgerEntries` returns the *current* value of a live entry, and reports both
        // sequences: the ledger it is serving (`latestLedger`) and the ledger that last wrote
        // the entry. An entry written after the ledger being served describes no ledger that
        // ever closed, so the pair is checked rather than only type-checked. What the pair
        // cannot establish is the reverse direction — see `observed_ledger` below.
        if last_modified_ledger > observed_ledger {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} was last modified at ledger \
                 {last_modified_ledger}, after the observed ledger {observed_ledger}"
            )));
        }
        if encoded.len() > MAX_XDR_BASE64_BYTES {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} exceeds the XDR size limit"
            )));
        }
        // `getLedgerEntries` puts **LedgerEntryData** in `xdr`, not a whole `LedgerEntry`:
        // `lastModifiedLedgerSeq` and `liveUntilLedgerSeq` are separate JSON fields, so the
        // wrapper's own fields are not in the payload. Decoding this as `LedgerEntry` fails
        // on every real response — see `a_real_rpc_ledger_entry_response_decodes`.
        let data = LedgerEntryData::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
            RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is invalid XDR: {error}"
            ))
        })?;
        let LedgerEntryData::ContractData(contract_data) = data else {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is not contract data"
            )));
        };
        if contract_data.contract != *expected_address
            || contract_data.key != ScVal::LedgerKeyContractInstance
            || contract_data.durability != ContractDataDurability::Persistent
        {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} does not match its requested contract instance"
            )));
        }
        let ScVal::ContractInstance(instance) = contract_data.val else {
            return Err(RpcError::Malformed(format!(
                "getLedgerEntries entry {index} is not a contract instance"
            )));
        };
        let executable = match instance.executable {
            ContractExecutable::Wasm(hash) => ObservedExecutable::Wasm {
                code_hash: ozpb_domain::Hash32(hash.0),
            },
            ContractExecutable::StellarAsset => ObservedExecutable::StellarAsset,
        };
        // Deliberately *not* also required: that `observed_ledger` is at or after the
        // transaction/simulation ledger. It usually is, since this call is made after that
        // acquisition, but a load-balanced endpoint can answer from a node a few ledgers
        // behind — the captured protocol-27 fixtures show it, with a simulation at 4104380 and
        // a `getLedgerEntries` at 4104260. Refusing that would reject honest evidence to
        // enforce an ordering the API never promised. What the observation means instead is
        // that it is dated at recording time and carries its own ledger: §4.1 lists these as
        // "target-contract executable hashes observed at recording time"
        // (`docs/architecture.md:208`), and the spec field they feed is `evidence_only` with an
        // `observed_ledger` and a drift response (`docs/architecture.md:331-332`).
        observations.insert(
            address.clone(),
            ExecutableObservation {
                executable,
                observed_ledger: ozpb_domain::LedgerSeq(observed_ledger),
            },
        );
    }
    if seen_keys.len() != requested.len() {
        let missing = requested
            .keys()
            .filter(|key| !seen_keys.contains(*key))
            .count();
        return Err(RpcError::Evidence(format!(
            "getLedgerEntries omitted {missing} referenced contract instances"
        )));
    }
    Ok(observations)
}

fn parse_simulate(
    network_passphrase: &str,
    envelope_xdr_base64: &str,
    result: &serde_json::Value,
) -> Result<EvidenceSnapshot, RpcError> {
    if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
        return Err(RpcError::Rpc(err.to_string()));
    }
    let auth_entries = result
        .get("results")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|r0| r0.get("auth"))
        .and_then(|a| a.as_array())
        .ok_or_else(|| {
            RpcError::Malformed("missing results[0].auth array in simulation response".to_string())
        })?;
    let auth: Vec<String> = auth_entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            entry.as_str().map(str::to_string).ok_or_else(|| {
                RpcError::Malformed(format!(
                    "simulation auth entry {index} is not base64 XDR text"
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    let latest_ledger: u32 = result
        .get("latestLedger")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::Malformed("missing integer field 'latestLedger'".to_string()))?
        .try_into()
        .map_err(|_| RpcError::Malformed("field 'latestLedger' exceeds u32".to_string()))?;
    let state_entries = result
        .get("stateChanges")
        .and_then(|changes| changes.as_array())
        .ok_or_else(|| {
            RpcError::Malformed("missing stateChanges array in simulation response".to_string())
        })?;
    let state_changes = state_entries
        .iter()
        .enumerate()
        .map(parse_simulation_state_change)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(EvidenceSnapshot::from_rpc_simulation(
        network_passphrase,
        envelope_xdr_base64,
        auth,
        Some(latest_ledger),
    )
    .with_simulated_state_changes(state_changes))
}

fn parse_simulation_state_change(
    (index, value): (usize, &serde_json::Value),
) -> Result<StateChange, RpcError> {
    let type_text = value
        .get("type")
        .and_then(|field| field.as_str())
        .ok_or_else(|| RpcError::Malformed(format!("stateChanges[{index}] has no string type")))?;
    let kind = match type_text {
        "created" => StateChangeKind::Created,
        "updated" => StateChangeKind::Updated,
        "deleted" | "removed" => StateChangeKind::Removed,
        "restored" => StateChangeKind::Restored,
        other => {
            return Err(RpcError::Malformed(format!(
                "stateChanges[{index}].type '{other}' is unsupported"
            )))
        }
    };
    let key_xdr = value
        .get("key")
        .and_then(|field| field.as_str())
        .ok_or_else(|| RpcError::Malformed(format!("stateChanges[{index}] has no string key")))?;
    // Exact evidence has to be evidence: `key` is a `LedgerKey` and `before`/`after` are whole
    // `LedgerEntry`s for that key (the official simulateTransaction schema). Text that is merely
    // string-shaped would be recorded as "exact simulation evidence" while proving nothing, and
    // an entry for some other key describes a change this one does not claim to be about.
    let key: LedgerKey = decode_state_change_xdr(index, "key", key_xdr)?;
    let before = state_change_entry(index, "before", value, &key)?;
    let after = state_change_entry(index, "after", value, &key)?;
    let sides = (before.is_some(), after.is_some());
    let contradiction = match kind {
        StateChangeKind::Created if sides != (false, true) => Some("only 'after'"),
        StateChangeKind::Updated if sides != (true, true) => Some("both 'before' and 'after'"),
        StateChangeKind::Removed if sides != (true, false) => Some("only 'before'"),
        // `restored` is outside the documented created/updated/deleted matrix, so require that
        // it carries some entry evidence rather than inventing a shape for it.
        StateChangeKind::Restored if sides == (false, false) => Some("'before', 'after' or both"),
        _ => None,
    };
    if let Some(expected) = contradiction {
        return Err(RpcError::Malformed(format!(
            "stateChanges[{index}] is '{type_text}' but a '{type_text}' entry carries {expected}"
        )));
    }
    // The summary describes what the decoded key says changed, in the recorder's own
    // vocabulary — not an opaque marker standing in for a value nobody parsed.
    let (entry, contract) = ozpb_recorder_core::ledger_key_summary(&key);
    Ok(StateChange {
        kind,
        entry,
        contract,
        source: StateChangeSource::Simulation,
        key_xdr_base64: Some(key_xdr.to_string()),
        before_xdr_base64: before,
        after_xdr_base64: after,
    })
}

fn decode_state_change_xdr<T: ReadXdr>(
    index: usize,
    field: &str,
    encoded: &str,
) -> Result<T, RpcError> {
    ensure_base64_size(&format!("stateChanges[{index}].{field}"), encoded)?;
    T::from_xdr_base64(encoded, xdr_limits()).map_err(|error| {
        RpcError::Malformed(format!(
            "stateChanges[{index}].{field} is not valid XDR: {error}"
        ))
    })
}

/// One side of a state change: absent, or a `LedgerEntry` for `key`. Returns the encoded text
/// unchanged, so the recording preserves exactly what the endpoint sent.
fn state_change_entry(
    index: usize,
    field: &str,
    value: &serde_json::Value,
    key: &LedgerKey,
) -> Result<Option<String>, RpcError> {
    let encoded = match value.get(field) {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::String(text)) => text,
        Some(_) => {
            return Err(RpcError::Malformed(format!(
                "stateChanges[{index}].{field} is not base64 XDR text"
            )))
        }
    };
    let entry: LedgerEntry = decode_state_change_xdr(index, field, encoded)?;
    if entry.to_key() != *key {
        return Err(RpcError::Malformed(format!(
            "stateChanges[{index}].{field} is a ledger entry for a different key than \
             stateChanges[{index}].key"
        )));
    }
    Ok(Some(encoded.clone()))
}

fn verify_network<T: RpcTransport>(
    transport: &T,
    expected_passphrase: &str,
) -> Result<(), RpcError> {
    let result = transport.call("getNetwork", json!({}))?;
    let actual = str_field(&result, "passphrase")?;
    if actual != expected_passphrase {
        return Err(RpcError::NetworkMismatch {
            expected: expected_passphrase.to_string(),
            actual,
        });
    }
    // The same response carries the protocol the endpoint is on, and this build decodes one
    // protocol's XDR. Checking it here costs no extra request and refuses an unusable endpoint
    // before anything is fetched from it — the alternative is a decode error deep inside a
    // parser, or worse, a newer shape that decodes into something subtly different.
    let protocol: u32 = result
        .get("protocolVersion")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RpcError::Malformed("getNetwork has no integer protocolVersion".to_string())
        })?
        .try_into()
        .map_err(|_| RpcError::Malformed("getNetwork protocolVersion exceeds u32".to_string()))?;
    if protocol > MAX_SUPPORTED_PROTOCOL {
        return Err(RpcError::UnsupportedProtocol {
            reported: protocol,
            supported: MAX_SUPPORTED_PROTOCOL,
        });
    }
    Ok(())
}

/// The base64 size bound and its message in one place, taking the field's path so the refusal
/// says which value was too large. Each XDR field the RPC gains is another chance to omit the
/// check or to word it differently.
fn ensure_base64_size(field: &str, value: &str) -> Result<(), RpcError> {
    if value.len() > MAX_XDR_BASE64_BYTES {
        return Err(RpcError::Malformed(format!(
            "field '{field}' is {} encoded bytes, over the {MAX_XDR_BASE64_BYTES}-byte XDR size \
             limit",
            value.len()
        )));
    }
    Ok(())
}

fn str_field(v: &serde_json::Value, field: &str) -> Result<String, RpcError> {
    v.get(field)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| RpcError::Malformed(format!("missing string field '{field}'")))
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A one-shot HTTP server on loopback that answers the first request with `response` and
    /// then closes.
    ///
    /// The production transport had no test at all: its response-size bounds and its
    /// JSON-RPC envelope handling only exist on a real socket, so the comments claiming a
    /// body reader cap and an error path were the only thing asserting them. This is a real
    /// HTTP exchange with no external network — the request never leaves the machine.
    fn serve_once(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            // Consume the request before answering: a client whose body is never read can see
            // a reset instead of the response we are testing.
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request);
                let Some((head, body)) = text.split_once("\r\n\r\n") else {
                    continue;
                };
                let declared = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if body.len() >= declared {
                    break;
                }
            }
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        });
        url
    }

    fn http_response(headers: &str, body: &[u8]) -> Vec<u8> {
        status_response("200 OK", headers, body)
    }

    fn status_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status}\r\n{headers}\r\n").into_bytes();
        out.extend_from_slice(body);
        out
    }

    /// A JSON body with no `Content-Length`, so the connection close delimits it: this is the
    /// case the reader cap exists for, and the only one where a lying or absent length cannot
    /// be caught by the header check.
    fn close_delimited(body: &[u8]) -> Vec<u8> {
        http_response("Content-Type: application/json\r\n", body)
    }

    fn call(response: Vec<u8>) -> Result<serde_json::Value, RpcError> {
        HttpTransport::new(serve_once(response)).call("getNetwork", json!({}))
    }

    #[test]
    fn a_well_formed_jsonrpc_response_yields_its_result() {
        let result = call(close_delimited(
            br#"{"jsonrpc":"2.0","id":1,"result":{"passphrase":"Test SDF Network ; September 2015"}}"#,
        ))
        .expect("a well-formed JSON-RPC response must be accepted");
        assert_eq!(
            result["passphrase"],
            json!("Test SDF Network ; September 2015")
        );
    }

    /// The response envelope has to be an answer to *our* request. A configured endpoint is
    /// already the trust boundary and these calls are synchronous, so this is not a live race —
    /// it is what catches a proxy, a cache or a mock handing back someone else's payload.
    #[test]
    fn a_response_that_does_not_answer_this_request_is_refused() {
        for (body, expected) in [
            (
                &br#"{"jsonrpc":"1.0","id":1,"result":{}}"#[..],
                "JSON-RPC 2.0",
            ),
            (&br#"{"id":1,"result":{}}"#[..], "JSON-RPC 2.0"),
            (&br#"{"jsonrpc":"2.0","id":2,"result":{}}"#[..], "id"),
            (&br#"{"jsonrpc":"2.0","result":{}}"#[..], "id"),
            (
                &br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}"#[..],
                "both",
            ),
            (&br#"{"jsonrpc":"2.0","id":1}"#[..], "neither"),
        ] {
            let error = call(close_delimited(body))
                .expect_err(&format!(
                    "must be refused: {}",
                    String::from_utf8_lossy(body)
                ))
                .to_string();
            assert!(
                error.contains(expected),
                "the refusal must say what is wrong ('{expected}'): {error}"
            );
        }
    }

    /// A JSON-RPC error object is reported as its code and message, not as a stringified blob
    /// of JSON that a caller has to re-parse to learn what happened.
    #[test]
    fn a_jsonrpc_error_keeps_its_code_and_message() {
        let error = call(close_delimited(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid hash","data":"detail"}}"#,
        ))
        .expect_err("a JSON-RPC error is an error")
        .to_string();
        // The whole error object stringified also happens to contain each of these words, so
        // the assertion is on the assembled form — otherwise it would pass against a blob.
        assert!(
            error.contains("code -32602: invalid hash"),
            "the code and message must be read out of the error object: {error}"
        );
        assert!(error.contains("detail"), "the data must survive: {error}");
    }

    /// An error the endpoint could not attribute to a request carries a null id by the
    /// specification, so that one case is accepted — for an error, and only for an error.
    #[test]
    fn a_null_id_is_accepted_only_on_an_error() {
        let error = call(close_delimited(
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#,
        ))
        .expect_err("an unattributable error is still an error");
        assert!(matches!(error, RpcError::Rpc(_)), "{error}");
        let error = call(close_delimited(
            br#"{"jsonrpc":"2.0","id":null,"result":{}}"#,
        ))
        .expect_err("a result must answer a request")
        .to_string();
        assert!(error.contains("id"), "{error}");
    }

    /// Endpoints answer a rejected call with an HTTP error status and a JSON-RPC error body,
    /// and the body is the part that says what was wrong. Discarding it for the status line
    /// leaves an operator with "400" where the endpoint sent a code and a message.
    #[test]
    fn a_jsonrpc_error_under_an_http_error_status_is_still_read() {
        let error = call(status_response(
            "400 Bad Request",
            "Content-Type: application/json\r\n",
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid hash"}}"#,
        ))
        .expect_err("a rejected call is an error")
        .to_string();
        assert!(
            error.contains("code -32602: invalid hash"),
            "the endpoint's own explanation must survive its status code: {error}"
        );
    }

    /// And when the body is not a JSON-RPC envelope, the status is what there is to report —
    /// with the body's beginning, since that is where a proxy or gateway says what it did.
    #[test]
    fn an_http_error_without_a_jsonrpc_body_reports_the_status() {
        let error = call(status_response(
            "502 Bad Gateway",
            "Content-Type: text/html\r\n",
            b"<html>upstream connect error</html>",
        ))
        .expect_err("a gateway failure is an error")
        .to_string();
        assert!(error.contains("502"), "the status must be named: {error}");
        assert!(
            error.contains("upstream connect error"),
            "the body says what happened: {error}"
        );
    }

    /// A JSON body under an error status is reported by status alone. It may be the endpoint or
    /// a gateway reflecting the request back, and the request carries a transaction envelope —
    /// confidential input for a simulation (§6.5), which must not travel into an error message
    /// and from there into a log.
    #[test]
    fn a_json_error_body_is_not_quoted_back() {
        let error = call(status_response(
            "403 Forbidden",
            "Content-Type: application/json\r\n",
            br#"{"detail":"rejected","echo":"AAAAAgAAAAAJCQkJ-secret-envelope"}"#,
        ))
        .expect_err("a refused call is an error")
        .to_string();
        assert!(error.contains("403"), "the status must be named: {error}");
        for fragment in ["rejected", "secret-envelope", "detail"] {
            assert!(
                !error.contains(fragment),
                "'{fragment}' came back out of a JSON body: {error}"
            );
        }
    }

    /// The excerpt is cut by bytes, so the cut can land inside a character. It must stop at the
    /// character boundary instead of reporting the half-sequence as corruption: the body is not
    /// corrupt, our slice was. This is the failure that a lossy conversion hides by producing a
    /// replacement character that looks like something the endpoint sent.
    #[test]
    fn a_truncated_error_body_is_cut_at_a_character_boundary() {
        // 'é' is two bytes, and it starts at the last byte the excerpt may take, so the cut
        // falls between them.
        let filler = "x".repeat(MAX_ERROR_BODY_EXCERPT_BYTES - 1);
        let body = format!("{filler}ético");
        let error = call(status_response(
            "500 Internal Server Error",
            "Content-Type: text/plain\r\n",
            body.as_bytes(),
        ))
        .expect_err("a server error is an error")
        .to_string();
        assert!(
            error.ends_with(&format!("{filler}…")),
            "the excerpt must end at the boundary, followed by the elision marker: {error}"
        );
        assert!(
            !error.contains('\u{FFFD}'),
            "a byte cut in half is our slice's doing, not content the endpoint sent: {error}"
        );
    }

    #[test]
    fn a_declared_length_over_the_bound_is_refused() {
        let over = MAX_HTTP_RESPONSE_BYTES + 1;
        let error = call(http_response(
            &format!("Content-Type: application/json\r\nContent-Length: {over}\r\n"),
            br#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        ))
        .expect_err("a response declaring more than the bound must be refused")
        .to_string();
        assert!(error.contains("limit"), "{error}");
    }

    /// The bound has to hold when nothing declares the length — the case the header check
    /// cannot cover, and the reason the body reader is capped as well.
    #[test]
    fn an_undeclared_body_over_the_bound_is_refused() {
        let error = call(close_delimited(&vec![b'x'; MAX_HTTP_RESPONSE_BYTES + 1]))
            .expect_err("an oversized close-delimited body must be refused")
            .to_string();
        assert!(error.contains("limit"), "{error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozpb_recorder_core::{fixtures as fx, record, RecordOptions};
    use std::cell::RefCell;
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ContractExecutable, ExtensionPoint, Hash,
        LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits, ScContractInstance, ScVal,
        WriteXdr,
    };

    const NET: &str = "Test SDF Network ; September 2015";

    /// What `getNetwork` really answers: the passphrase and the protocol the endpoint is on.
    fn network_response() -> serde_json::Value {
        json!({ "passphrase": NET, "protocolVersion": MAX_SUPPORTED_PROTOCOL })
    }

    /// A real `getLedgerEntries` response, captured verbatim from Stellar testnet
    /// (the native SAC's contract instance, protocol 27).
    ///
    /// This test exists because the hand-written mocks above did not catch a three-week
    /// outage of the live recording path. They encoded a whole `LedgerEntry`, while the RPC
    /// puts **LedgerEntryData** in `xdr` — `lastModifiedLedgerSeq` and `liveUntilLedgerSeq`
    /// are separate JSON fields. The mocks therefore agreed with our code instead of with
    /// the network, so `cargo test` was green while `ozpb record` failed against every real
    /// endpoint. A captured response is the only anchor that catches that class of error.
    ///
    /// Public-chain data, so it is a legitimate fixture (§6.5 forbids private bundles only).
    #[test]
    fn a_real_rpc_ledger_entry_response_decodes() {
        // Concatenated to keep the line width; this is one base64 string.
        const REAL_XDR: &str = concat!(
            "AAAABgAAAAAAAAAB15KLcsJwPM/q9+uf9O9NUEpVqLl5/JtFDqLIQrTRzmEAAAAUAAAAAQAAABMA",
            "AAABAAAAAQAAAAIAAAAPAAAACE1FVEFEQVRBAAAAEQAAAAEAAAADAAAADwAAAAdkZWNpbWFsAAAA",
            "AAMAAAAHAAAADwAAAARuYW1lAAAADgAAAAZuYXRpdmUAAAAAAA8AAAAGc3ltYm9sAAAAAAAOAAAA",
            "Bm5hdGl2ZQAAAAAAEAAAAAEAAAABAAAADwAAAAlBc3NldEluZm8AAAAAAAAQAAAAAQAAAAEAAAAP",
            "AAAABk5hdGl2ZQAA",
        );

        let data = LedgerEntryData::from_xdr_base64(REAL_XDR, xdr_limits())
            .expect("a real getLedgerEntries `xdr` field must decode as LedgerEntryData");
        let LedgerEntryData::ContractData(contract_data) = data else {
            panic!("expected contract data");
        };
        assert_eq!(contract_data.key, ScVal::LedgerKeyContractInstance);
        assert_eq!(contract_data.durability, ContractDataDurability::Persistent);
        let ScVal::ContractInstance(instance) = contract_data.val else {
            panic!("expected a contract instance");
        };
        assert_eq!(instance.executable, ContractExecutable::StellarAsset);

        // And the shape the code used to assume must still be rejected, so a future
        // "simplification" back to `LedgerEntry` fails here rather than in production.
        assert!(
            stellar_xdr::LedgerEntry::from_xdr_base64(REAL_XDR, xdr_limits()).is_err(),
            "the payload is LedgerEntryData; decoding it as LedgerEntry must fail"
        );
    }

    struct CannedTransport {
        result: serde_json::Value,
        last_method: RefCell<String>,
    }

    impl RpcTransport for CannedTransport {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            *self.last_method.borrow_mut() = method.to_string();
            if method == "getNetwork" {
                Ok(network_response())
            } else if method == "getLedgerEntries" {
                Ok(json!({
                    "entries": ledger_entries_for(&params)?,
                    "latestLedger": OBSERVED_LEDGER
                }))
            } else {
                Ok(self.result.clone())
            }
        }
    }

    const OBSERVED_LEDGER: u64 = 4_200_102;
    const LAST_MODIFIED_LEDGER: u64 = 4_200_099;

    /// A valid `getLedgerEntries` entry list for exactly the keys the adapter asked for — the
    /// shape the RPC really returns: `LedgerEntryData` in `xdr`, with the ledger sequences
    /// beside it as their own JSON fields.
    ///
    /// One encoder for every mock in this file. The earlier hand-written mock encoded a whole
    /// `LedgerEntry`, so it agreed with the code rather than with the network and the decode
    /// bug was invisible for three weeks; a second copy of that decision is a second chance to
    /// make the same mistake.
    fn ledger_entries_for(params: &serde_json::Value) -> Result<Vec<serde_json::Value>, RpcError> {
        let keys = params["keys"]
            .as_array()
            .ok_or_else(|| RpcError::Malformed("test transport received no keys".to_string()))?;
        Ok(keys
            .iter()
            .map(|encoded| {
                let encoded = encoded.as_str().unwrap();
                let key = LedgerKey::from_xdr_base64(encoded, Limits::none()).unwrap();
                let LedgerKey::ContractData(contract_key) = key else {
                    panic!("expected contract-data key")
                };
                let entry = LedgerEntryData::ContractData(ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract: contract_key.contract,
                    key: ScVal::LedgerKeyContractInstance,
                    durability: ContractDataDurability::Persistent,
                    val: ScVal::ContractInstance(ScContractInstance {
                        executable: ContractExecutable::StellarAsset,
                        storage: None,
                    }),
                })
                .to_xdr_base64(Limits::none())
                .unwrap();
                json!({
                    "key": encoded,
                    "xdr": entry,
                    "lastModifiedLedgerSeq": LAST_MODIFIED_LEDGER
                })
            })
            .collect())
    }

    /// Serves a valid transaction and a `getLedgerEntries` response built for the keys actually
    /// requested, then applies one mutation to it. Each executable branch is therefore reached
    /// with everything else about the response valid.
    struct MutatedEntriesTransport {
        transaction: serde_json::Value,
        mutate: fn(Vec<serde_json::Value>) -> serde_json::Value,
    }

    impl RpcTransport for MutatedEntriesTransport {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            match method {
                "getNetwork" => Ok(network_response()),
                "getTransaction" => Ok(self.transaction.clone()),
                "getLedgerEntries" => Ok((self.mutate)(ledger_entries_for(&params)?)),
                other => Err(RpcError::Rpc(format!("unexpected method {other}"))),
            }
        }
    }

    /// Every fail-closed branch over `getLedgerEntries`, each reached from an otherwise valid
    /// response. The implementation had these branches; nothing exercised them, so a deleted
    /// check would not have been noticed — and the executable observation is what binds account
    /// recognition to a code hash.
    #[test]
    fn each_ledger_entry_response_defect_is_refused() {
        let (_, valid) = valid_executed_response();
        let tx_hash = transaction_hash(valid["envelopeXdr"].as_str().unwrap());
        let run = |mutate: fn(Vec<serde_json::Value>) -> serde_json::Value| {
            let transport = MutatedEntriesTransport {
                transaction: valid.clone(),
                mutate,
            };
            get_transaction(&transport, NET, &tx_hash)
        };

        // The control value: unmutated, the same response records two observations.
        let snapshot = run(|entries| json!({"entries": entries, "latestLedger": OBSERVED_LEDGER}))
            .expect("the unmutated ledger-entry response must record");
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        assert_eq!(bundle.contract_executables.len(), 2);

        type Mutation = fn(Vec<serde_json::Value>) -> serde_json::Value;
        let cases: [(&str, Mutation); 7] = [
            ("omitted", |mut entries| {
                entries.pop();
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
            ("duplicate", |mut entries| {
                entries[1] = entries[0].clone();
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
            ("unrequested", |mut entries| {
                entries[0]["key"] =
                    json!(base64(&LedgerKey::ContractData(LedgerKeyContractData {
                        contract: ScAddress::Contract(ContractId(Hash([9u8; 32]))),
                        key: ScVal::LedgerKeyContractInstance,
                        durability: ContractDataDurability::Persistent,
                    })));
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
            ("invalid XDR", |mut entries| {
                entries[0]["xdr"] = json!("AAAA-not-xdr");
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
            ("not contract data", |mut entries| {
                entries[0]["xdr"] = json!(base64(&LedgerEntryData::Ttl(stellar_xdr::TtlEntry {
                    key_hash: Hash([4u8; 32]),
                    live_until_ledger_seq: 7,
                })));
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
            // Contract data, but for a key nobody asked about: the entry has to be the
            // instance of the contract whose key returned it.
            ("does not match", |mut entries| {
                entries[0]["xdr"] = json!(base64(&fx::contract_data_entry(1).data));
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
            // The current-state API reports both sequences; an entry last modified after the
            // ledger the endpoint says it is serving describes no ledger that ever existed.
            ("after the observed ledger", |mut entries| {
                entries[0]["lastModifiedLedgerSeq"] = json!(OBSERVED_LEDGER + 1);
                json!({"entries": entries, "latestLedger": OBSERVED_LEDGER})
            }),
        ];
        for (expected, mutate) in cases {
            let error = run(mutate)
                .expect_err(&format!("a response that is '{expected}' must be refused"))
                .to_string();
            assert!(
                error.contains(expected),
                "the refusal must say what was wrong ('{expected}'): {error}"
            );
        }
    }

    fn fixture_envelope_and_meta() -> (String, String) {
        let bundle = record(&fx::executed_snapshot(), RecordOptions::default()).unwrap();
        (
            bundle.raw.envelope_xdr_base64,
            bundle.raw.result_meta_xdr_base64.unwrap(),
        )
    }

    fn transaction_hash(envelope: &str) -> String {
        let envelope = TransactionEnvelope::from_xdr_base64(envelope, xdr_limits()).unwrap();
        ozpb_domain::Hash32(
            envelope
                .hash(ozpb_domain::NetworkId::from_passphrase(NET).0 .0)
                .unwrap(),
        )
        .to_hex()
    }

    #[test]
    fn get_transaction_parses_and_records() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let tx_hash = transaction_hash(&envelope);
        let t = CannedTransport {
            result: json!({
                "status": "SUCCESS",
                "txHash": tx_hash.clone(),
                "envelopeXdr": envelope,
                "resultXdr": result_xdr(true),
                "resultMetaXdr": meta,
                "ledger": 4200100,
                "createdAt": "1780000000"
            }),
            last_method: RefCell::new(String::new()),
        };
        let snap = get_transaction(&t, NET, &tx_hash).unwrap();
        assert_eq!(*t.last_method.borrow(), "getLedgerEntries");
        assert_eq!(snap.trust().as_str(), "rpc_reported");
        let bundle = record(&snap, RecordOptions::default()).unwrap();
        assert_eq!(bundle.authorizations.len(), 1);
        assert_eq!(bundle.token_movements.len(), 1);
    }

    #[test]
    fn not_found_maps_to_retention_error() {
        let t = CannedTransport {
            result: json!({"status": "NOT_FOUND"}),
            last_method: RefCell::new(String::new()),
        };
        let err = get_transaction(&t, NET, &"d".repeat(64)).unwrap_err();
        assert!(matches!(err, RpcError::NotFound(_)));
    }

    #[test]
    fn transaction_hash_is_validated_before_network_io() {
        let t = CannedTransport {
            result: json!({"status": "NOT_FOUND"}),
            last_method: RefCell::new(String::new()),
        };
        let error = get_transaction(&t, NET, "deadbeef").unwrap_err();
        assert!(matches!(error, RpcError::Malformed(_)));
        assert!(t.last_method.borrow().is_empty());
    }

    #[test]
    fn response_and_envelope_hashes_must_match_the_request() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let actual = transaction_hash(&envelope);
        let requested = "0".repeat(64);
        let response = json!({
            "status": "SUCCESS",
            "txHash": actual,
            "envelopeXdr": envelope,
            "resultXdr": result_xdr(true),
            "resultMetaXdr": meta,
            "ledger": 4200100,
            "createdAt": "1780000000"
        });
        let error = parse_get_transaction(NET, &requested, &response).unwrap_err();
        assert!(error.to_string().contains("does not match requested"));

        let response = json!({
            "status": "SUCCESS",
            "txHash": requested,
            "envelopeXdr": envelope,
            "resultXdr": result_xdr(true),
            "resultMetaXdr": meta,
            "ledger": 4200100,
            "createdAt": "1780000000"
        });
        let error = parse_get_transaction(NET, &requested, &response).unwrap_err();
        assert!(error.to_string().contains("envelopeXdr hashes to"));
    }

    fn succeeded_operation() -> stellar_xdr::OperationResult {
        stellar_xdr::OperationResult::OpInner(stellar_xdr::OperationResultTr::InvokeHostFunction(
            stellar_xdr::InvokeHostFunctionResult::Success(Hash([0u8; 32])),
        ))
    }

    /// The recorder fixture's transaction result, given the one operation result the fixture
    /// envelope's one operation must have.
    ///
    /// The fixture encodes `TxSuccess([])`/`TxFailed([])`, which is enough for the recorder —
    /// it checks only the transaction-level outcome — but describes a transaction with no
    /// operations, and this adapter requires one result per operation. Fee and extension still
    /// come from the fixture, so there is one place that decides what a transaction result
    /// looks like and this only supplies what the pairing here requires.
    fn result_xdr(success: bool) -> String {
        let outcome = if success {
            succeeded_operation()
        } else {
            stellar_xdr::OperationResult::OpInner(
                stellar_xdr::OperationResultTr::InvokeHostFunction(
                    stellar_xdr::InvokeHostFunctionResult::Trapped,
                ),
            )
        };
        let results = vec![outcome].try_into().unwrap();
        let mut result = fx::transaction_result(success);
        result.result = if success {
            TransactionResultResult::TxSuccess(results)
        } else {
            TransactionResultResult::TxFailed(results)
        };
        base64(&result)
    }

    /// One result per operation, or the result set is about a different transaction. The
    /// envelope is hash-bound to the request, so its operation count is a fact and the result
    /// set's length is the endpoint's claim about that fact.
    ///
    /// `TxSuccess([])` against a one-operation envelope is the cheapest form of the lie, and it
    /// is what the shared recorder fixture encodes — the recorder accepts it because it checks
    /// only the transaction-level outcome, so nothing here noticed that the "valid" response
    /// two other tests assert `is_ok()` on described a transaction with no operations.
    #[test]
    fn the_result_set_must_have_one_result_per_operation() {
        use stellar_xdr::TransactionResultExt;
        let (tx_hash, valid) = valid_executed_response();
        assert!(
            parse_get_transaction(NET, &tx_hash, &valid).is_ok(),
            "the control response pairs one operation with one operation result"
        );
        let envelope = TransactionEnvelope::from_xdr_base64(
            valid["envelopeXdr"].as_str().unwrap(),
            xdr_limits(),
        )
        .unwrap();
        assert_eq!(
            envelope_operations(&envelope).len(),
            1,
            "the fixture envelope has one operation; the counts below are relative to that"
        );

        for results in [vec![], vec![succeeded_operation(), succeeded_operation()]] {
            let count = results.len();
            let mut response = valid.clone();
            response["resultXdr"] = json!(base64(&TransactionResult {
                fee_charged: 100,
                result: TransactionResultResult::TxSuccess(results.try_into().unwrap()),
                ext: TransactionResultExt::V0,
            }));
            let error = parse_get_transaction(NET, &tx_hash, &response)
                .expect_err(&format!(
                    "{count} results for one operation must be refused"
                ))
                .to_string();
            assert!(
                error.contains("operation"),
                "the refusal must name the mismatch: {error}"
            );
        }
    }

    /// The success label must be checkable against evidence, not lifted from a bare
    /// status string: `resultXdr` is required for executed transactions.
    #[test]
    fn executed_rpc_evidence_requires_the_transaction_result() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let tx_hash = transaction_hash(&envelope);
        let response = json!({
            "status": "SUCCESS",
            "txHash": tx_hash,
            "envelopeXdr": envelope,
            "resultMetaXdr": meta,
            "ledger": 4200100,
            "createdAt": "1780000000"
        });
        let error = parse_get_transaction(NET, &tx_hash, &response).unwrap_err();
        assert!(
            error.to_string().contains("resultXdr"),
            "an executed transaction without a result must be rejected: {error}"
        );
    }

    /// A status string that contradicts the decoded TransactionResult is rejected in both
    /// directions: neither a failure sold as SUCCESS nor a success sold as FAILED may
    /// become an evidence snapshot.
    #[test]
    fn rpc_status_must_agree_with_the_decoded_transaction_result() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let tx_hash = transaction_hash(&envelope);
        for (status, result_success) in [("SUCCESS", false), ("FAILED", true)] {
            let response = json!({
                "status": status,
                "txHash": tx_hash,
                "envelopeXdr": envelope,
                "resultXdr": result_xdr(result_success),
                "resultMetaXdr": meta,
                "ledger": 4200100,
                "createdAt": "1780000000"
            });
            let error = parse_get_transaction(NET, &tx_hash, &response).unwrap_err();
            assert!(
                error.to_string().contains("contradicts"),
                "status {status} with success={result_success} result must be rejected: {error}"
            );
        }

        // And an undecodable result is malformed evidence, not a shrug.
        let response = json!({
            "status": "SUCCESS",
            "txHash": tx_hash,
            "envelopeXdr": envelope,
            "resultXdr": "not base64 xdr",
            "resultMetaXdr": meta,
            "ledger": 4200100,
            "createdAt": "1780000000"
        });
        assert!(parse_get_transaction(NET, &tx_hash, &response).is_err());
    }

    /// Every XDR field this parser takes from the response is bounded here, including the one
    /// whose size only the recorder used to catch. This is where a response becomes evidence; a
    /// bound enforced two layers later is a bound a reader of this function cannot see, and it
    /// reports the recorder's limit rather than naming the field that broke it.
    #[test]
    fn an_oversized_executed_xdr_field_is_refused_by_name() {
        let (tx_hash, valid) = valid_executed_response();
        assert!(
            parse_get_transaction(NET, &tx_hash, &valid).is_ok(),
            "the unmutated response must parse, or the sizes below prove nothing"
        );
        for field in ["envelopeXdr", "resultXdr", "resultMetaXdr"] {
            let mut response = valid.clone();
            response[field] = json!("A".repeat(MAX_XDR_BASE64_BYTES + 1));
            let error = parse_get_transaction(NET, &tx_hash, &response)
                .expect_err(&format!("an oversized '{field}' must be refused"))
                .to_string();
            assert!(
                error.contains(field) && error.contains("size limit"),
                "the refusal must name the field and the bound: {error}"
            );
        }
    }

    /// `SUCCESS` is a claim about the operations too, and a `txSUCCESS` carrying an operation
    /// that did not succeed contradicts itself. Nothing binds `resultXdr` to the transaction
    /// hash — the ledger commits the result set's Merkle root, not this field — so internal
    /// consistency is the whole of what can be checked about it, and it is checked completely.
    #[test]
    fn a_successful_result_may_not_contain_an_operation_that_failed() {
        use stellar_xdr::{
            InvokeHostFunctionResult, OperationResult, OperationResultTr, TransactionResultExt,
        };
        let (tx_hash, valid) = valid_executed_response();
        let with_operation = |operation: OperationResult| {
            let mut response = valid.clone();
            response["resultXdr"] = json!(base64(&TransactionResult {
                fee_charged: 100,
                result: TransactionResultResult::TxSuccess(vec![operation].try_into().unwrap()),
                ext: TransactionResultExt::V0,
            }));
            parse_get_transaction(NET, &tx_hash, &response)
        };

        // The control value: the same one-operation success, with a result that did succeed.
        with_operation(OperationResult::OpInner(
            OperationResultTr::InvokeHostFunction(InvokeHostFunctionResult::Success(Hash(
                [0u8; 32],
            ))),
        ))
        .expect("a success whose operation succeeded is the ordinary case");

        for operation in [
            OperationResult::OpNoAccount,
            OperationResult::OpInner(OperationResultTr::InvokeHostFunction(
                InvokeHostFunctionResult::Trapped,
            )),
        ] {
            let error = with_operation(operation)
                .expect_err("a success carrying a failed operation must be rejected")
                .to_string();
            assert!(
                error.contains("operation"),
                "the refusal must name the operation: {error}"
            );
        }
    }

    #[test]
    fn simulate_collects_record_mode_auth_entries() {
        let (envelope, _) = fixture_envelope_and_meta();
        let t = CannedTransport {
            result: json!({
                "results": [{ "auth": [] }],
                "stateChanges": [],
                "latestLedger": 4200101
            }),
            last_method: RefCell::new(String::new()),
        };
        let snap = simulate_transaction(&t, NET, &envelope).unwrap();
        assert_eq!(*t.last_method.borrow(), "getLedgerEntries");
        assert_eq!(snap.trust().as_str(), "rpc_reported");
    }

    /// The caller's envelope is checked here before it is sent anywhere: an oversized blob, a
    /// string that is not XDR, or a shape simulation cannot take is refused locally instead of
    /// spending the endpoint's time and bandwidth to be told so.
    #[test]
    fn the_simulation_envelope_is_validated_before_network_io() {
        let (valid, _) = fixture_envelope_and_meta();
        let simulation = || CannedTransport {
            result: json!({
                "results": [{ "auth": [] }],
                "stateChanges": [],
                "latestLedger": 4200101
            }),
            last_method: RefCell::new(String::new()),
        };
        // The control value: the fixture envelope is exactly the accepted shape — one
        // InvokeHostFunction operation — so the refusals below are about what they say.
        let accepted = simulation();
        simulate_transaction(&accepted, NET, &valid)
            .expect("a single-InvokeHostFunction envelope is the shape simulation takes");
        assert_eq!(*accepted.last_method.borrow(), "getLedgerEntries");

        let two_operations = {
            let TransactionEnvelope::Tx(mut v1) =
                TransactionEnvelope::from_xdr_base64(&valid, xdr_limits()).unwrap()
            else {
                panic!("the fixture envelope is a v1 transaction");
            };
            let mut operations = v1.tx.operations.to_vec();
            operations.push(operations[0].clone());
            v1.tx.operations = operations.try_into().unwrap();
            base64(&TransactionEnvelope::Tx(v1))
        };
        let not_soroban = {
            let TransactionEnvelope::Tx(mut v1) =
                TransactionEnvelope::from_xdr_base64(&valid, xdr_limits()).unwrap()
            else {
                panic!("the fixture envelope is a v1 transaction");
            };
            let mut operations = v1.tx.operations.to_vec();
            operations[0].body =
                stellar_xdr::OperationBody::BumpSequence(stellar_xdr::BumpSequenceOp {
                    bump_to: stellar_xdr::SequenceNumber(9),
                });
            v1.tx.operations = operations.try_into().unwrap();
            base64(&TransactionEnvelope::Tx(v1))
        };
        for (envelope, expected) in [
            ("not-base64-xdr".to_string(), "envelope"),
            ("A".repeat(MAX_XDR_BASE64_BYTES + 1), "size limit"),
            (two_operations, "operation"),
            (not_soroban, "InvokeHostFunction"),
        ] {
            let transport = simulation();
            let error = simulate_transaction(&transport, NET, &envelope)
                .expect_err("an envelope simulation cannot take must be refused")
                .to_string();
            assert!(
                error.contains(expected),
                "the refusal must say what is wrong ('{expected}'): {error}"
            );
            assert!(
                transport.last_method.borrow().is_empty(),
                "nothing may be sent to the endpoint before the envelope is checked: {}",
                transport.last_method.borrow()
            );
        }
    }

    #[test]
    fn rpc_error_is_surfaced() {
        let result = json!({"error": "boom"});
        let err = parse_simulate(NET, "env", &result).unwrap_err();
        assert!(matches!(err, RpcError::Rpc(_)));
    }

    struct NetworkMismatchTransport {
        envelope: String,
        meta: String,
    }

    impl RpcTransport for NetworkMismatchTransport {
        fn call(
            &self,
            method: &str,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            match method {
                "getNetwork" => Ok(json!({
                    "passphrase": "Public Global Stellar Network ; September 2015"
                })),
                "getTransaction" => Ok(json!({
                    "status": "SUCCESS",
                    "envelopeXdr": self.envelope,
                    "resultXdr": result_xdr(true),
                    "resultMetaXdr": self.meta,
                    "ledger": 4200100,
                    "createdAt": "1780000000"
                })),
                other => Err(RpcError::Rpc(format!("unexpected method {other}"))),
            }
        }
    }

    /// The protocol ceiling is the major version of the pinned `stellar-xdr`, not a number
    /// somebody chose. If the dependency moves and this constant does not, the two disagree
    /// about what this crate can decode and this test says so.
    #[test]
    fn the_protocol_ceiling_is_the_pinned_xdr_major_version() {
        let pinned: u32 = stellar_xdr::VERSION
            .pkg
            .split('.')
            .next()
            .expect("a semver package version")
            .parse()
            .expect("a numeric major version");
        assert_eq!(
            MAX_SUPPORTED_PROTOCOL, pinned,
            "the supported protocol ceiling and the pinned stellar-xdr major must move together"
        );
    }

    /// `getNetwork` reports the protocol the endpoint is on, and this crate is built against
    /// one protocol's XDR. A newer protocol is refused by name, before any transaction is
    /// fetched, instead of being discovered as a decode failure somewhere inside a parser — or
    /// not discovered at all, when the newer shapes happen to still decode.
    #[test]
    fn a_protocol_this_build_cannot_decode_is_refused_before_fetching_anything() {
        struct ProtocolTransport {
            network: serde_json::Value,
            calls: RefCell<Vec<String>>,
        }
        impl RpcTransport for ProtocolTransport {
            fn call(
                &self,
                method: &str,
                _params: serde_json::Value,
            ) -> Result<serde_json::Value, RpcError> {
                self.calls.borrow_mut().push(method.to_string());
                match method {
                    "getNetwork" => Ok(self.network.clone()),
                    other => Err(RpcError::Rpc(format!("unexpected method {other}"))),
                }
            }
        }
        let run = |network: serde_json::Value| {
            let transport = ProtocolTransport {
                network,
                calls: RefCell::new(Vec::new()),
            };
            let result = get_transaction(&transport, NET, &"0".repeat(64));
            let calls = transport.calls.borrow().clone();
            (result, calls)
        };

        // The control value: on the supported protocol the acquisition proceeds past
        // `getNetwork` — this transport then refuses `getTransaction`, which is how we know it
        // got that far.
        let (_, calls) = run(network_response());
        assert_eq!(calls, ["getNetwork", "getTransaction"]);

        for (network, expected) in [
            (
                json!({ "passphrase": NET, "protocolVersion": MAX_SUPPORTED_PROTOCOL + 1 }),
                "protocol",
            ),
            (json!({ "passphrase": NET }), "protocolVersion"),
            (
                json!({ "passphrase": NET, "protocolVersion": "27" }),
                "protocolVersion",
            ),
        ] {
            let (result, calls) = run(network);
            let error = result
                .expect_err("an unusable protocol report must stop the acquisition")
                .to_string();
            assert!(
                error.contains(expected),
                "the refusal must name what is wrong ('{expected}'): {error}"
            );
            assert_eq!(
                calls,
                ["getNetwork"],
                "nothing may be fetched after the protocol is refused"
            );
        }
    }

    #[test]
    fn rpc_network_must_match_the_requested_network() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let transport = NetworkMismatchTransport { envelope, meta };
        let err = get_transaction(&transport, NET, &"0".repeat(64)).unwrap_err();
        assert!(
            err.to_string().starts_with("E_NETWORK_MISMATCH:"),
            "a mainnet response must never be labelled as testnet evidence: {err}"
        );
    }

    /// One response valid in every respect, and the hash it is valid for. Assembled from the
    /// recorder's own fixture so the envelope really hashes to that transaction and the result
    /// really says SUCCESS — which is what lets a negative test remove exactly one field and
    /// know the parser got as far as that field's check.
    fn valid_executed_response() -> (String, serde_json::Value) {
        let (envelope, meta) = fixture_envelope_and_meta();
        let tx_hash = transaction_hash(&envelope);
        let response = json!({
            "status": "SUCCESS",
            "txHash": tx_hash,
            "envelopeXdr": envelope,
            "resultXdr": result_xdr(true),
            "resultMetaXdr": meta,
            "ledger": 4200100,
            "createdAt": "1780000000"
        });
        (tx_hash, response)
    }

    /// Each field the executed path requires, removed one at a time from a response that is
    /// otherwise valid, and the error must name the field it is about.
    ///
    /// Removing one field from a valid whole is the only way to know the check under test ran.
    /// The predecessor of this test — `executed_rpc_evidence_requires_ledger_and_timestamp` —
    /// omitted `txHash` from both of its candidates and passed `"abc"` as the requested hash,
    /// so both failed at the transaction-hash check and it stayed green with the `ledger` and
    /// `createdAt` requirements deleted from the parser.
    #[test]
    fn each_required_executed_field_is_named_when_it_is_missing() {
        let (tx_hash, valid) = valid_executed_response();
        // The control value: without it, every case below could be failing for the same
        // unrelated reason and the loop would still be green.
        assert!(
            parse_get_transaction(NET, &tx_hash, &valid).is_ok(),
            "the unmutated response must parse, or the removals below prove nothing"
        );
        for field in [
            "status",
            "txHash",
            "envelopeXdr",
            "resultXdr",
            "ledger",
            "createdAt",
        ] {
            let mut response = valid.clone();
            response
                .as_object_mut()
                .expect("the fixture response is a JSON object")
                .remove(field);
            let error = parse_get_transaction(NET, &tx_hash, &response)
                .expect_err(&format!("a response without '{field}' must be rejected"))
                .to_string();
            assert!(
                error.contains(field),
                "removing '{field}' must produce an error naming it: {error}"
            );
        }
    }

    /// A transport that enforces the official `getLedgerEntries` limit, so a request the real
    /// endpoint would refuse is refused here too, and records the size of each batch it served.
    struct KeyLimitTransport {
        batches: RefCell<Vec<usize>>,
    }

    impl RpcTransport for KeyLimitTransport {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            assert_eq!(
                method, "getLedgerEntries",
                "this transport serves one method"
            );
            let count = params["keys"].as_array().expect("keys array").len();
            if count > MAX_LEDGER_ENTRY_KEYS {
                return Err(RpcError::Rpc(format!(
                    "getLedgerEntries accepts at most {MAX_LEDGER_ENTRY_KEYS} keys, got {count}"
                )));
            }
            self.batches.borrow_mut().push(count);
            // A different ledger per batch: two batches genuinely are two observations of two
            // moments, and the recording must not claim otherwise.
            Ok(json!({
                "entries": ledger_entries_for(&params)?,
                "latestLedger": OBSERVED_LEDGER + self.batches.borrow().len() as u64
            }))
        }
    }

    /// The recorder admits more executable observations than `getLedgerEntries` accepts keys in
    /// one request, so asking for all of them at once made a recording that fits every local
    /// bound fail at the endpoint and nowhere else.
    ///
    /// Each observation carries the ledger of the response that produced it, so batching states
    /// what it actually saw instead of dating every observation by one batch's ledger.
    #[test]
    fn contract_instances_are_requested_within_the_official_key_limit() {
        let (envelope, _) = fixture_envelope_and_meta();

        // The control value: a snapshot referencing few contracts is still one request.
        let single = KeyLimitTransport {
            batches: RefCell::new(Vec::new()),
        };
        acquire_contract_executables(&single, fx::executed_snapshot())
            .expect("two referenced contracts are one request");
        assert_eq!(*single.batches.borrow(), vec![2]);

        let credentials = |index: usize| {
            let mut id = [0u8; 32];
            id[0] = 0xAA;
            id[1] = (index >> 8) as u8;
            id[2] = (index & 0xff) as u8;
            stellar_xdr::SorobanCredentials::Address(stellar_xdr::SorobanAddressCredentials {
                address: ScAddress::Contract(ContractId(Hash(id))),
                nonce: index as i64,
                signature_expiration_ledger: 4_210_000,
                signature: ScVal::Void,
            })
        };
        let auth: Vec<String> = (0..MAX_LEDGER_ENTRY_KEYS + 1)
            .map(|index| base64(&fx::auth_entry(credentials(index))))
            .collect();
        // Those credential addresses plus the contract the fixture invocation calls.
        let expected_addresses = MAX_LEDGER_ENTRY_KEYS + 2;
        let snapshot = EvidenceSnapshot::from_rpc_simulation(NET, envelope, auth, Some(4_200_101));

        let transport = KeyLimitTransport {
            batches: RefCell::new(Vec::new()),
        };
        let snapshot = acquire_contract_executables(&transport, snapshot)
            .expect("more referenced contracts than one request holds must still be acquired");
        assert_eq!(
            *transport.batches.borrow(),
            vec![
                MAX_LEDGER_ENTRY_KEYS,
                expected_addresses - MAX_LEDGER_ENTRY_KEYS
            ]
        );

        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        assert_eq!(bundle.contract_executables.len(), expected_addresses);
        let mut per_ledger = BTreeMap::new();
        for observation in bundle.contract_executables.values() {
            *per_ledger
                .entry(observation.observed_ledger.0)
                .or_insert(0usize) += 1;
        }
        assert_eq!(
            per_ledger,
            BTreeMap::from([
                (OBSERVED_LEDGER as u32 + 1, MAX_LEDGER_ENTRY_KEYS),
                (
                    OBSERVED_LEDGER as u32 + 2,
                    expected_addresses - MAX_LEDGER_ENTRY_KEYS
                ),
            ]),
            "each observation is dated by the response that produced it"
        );
    }

    #[test]
    fn simulation_auth_shape_is_required_and_strict() {
        let (envelope, _) = fixture_envelope_and_meta();
        for result in [
            json!({"stateChanges": [], "latestLedger": 4200101}),
            json!({"results": [], "stateChanges": [], "latestLedger": 4200101}),
            json!({"results": [{"auth": [7]}], "stateChanges": [], "latestLedger": 4200101}),
            json!({"results": [{"auth": []}], "latestLedger": 4200101}),
        ] {
            assert!(parse_simulate(NET, &envelope, &result).is_err());
        }
    }

    fn base64(value: &impl WriteXdr) -> String {
        value.to_xdr_base64(xdr_limits()).unwrap()
    }

    /// One simulation state change valid in every respect: two real `LedgerEntry` values for
    /// one `LedgerKey`, encoded the way `simulateTransaction` encodes them. Negatives below
    /// are this object with exactly one field replaced.
    fn valid_state_change() -> serde_json::Value {
        let before = fx::contract_data_entry(1);
        let after = fx::contract_data_entry(2);
        json!({
            "type": "updated",
            "key": base64(&before.to_key()),
            "before": base64(&before),
            "after": base64(&after)
        })
    }

    fn simulation_response(changes: serde_json::Value) -> serde_json::Value {
        json!({
            "results": [{ "auth": [] }],
            "stateChanges": changes,
            "latestLedger": 4200101
        })
    }

    #[test]
    fn simulation_state_changes_are_preserved_as_evidence() {
        let (envelope, _) = fixture_envelope_and_meta();
        let result = simulation_response(json!([valid_state_change()]));
        let snapshot = parse_simulate(NET, &envelope, &result).unwrap();
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        assert_eq!(bundle.state_changes.len(), 1);
        assert_eq!(
            bundle.state_changes[0].source,
            ozpb_recorder_core::StateChangeSource::Simulation
        );
    }

    /// The exact XDR is the evidence, so it must be XDR: `key` a `LedgerKey`, `before` and
    /// `after` `LedgerEntry`s for *that* key. Text that merely looks like base64 is not
    /// simulation evidence, and an entry belonging to some other key is evidence about
    /// something the change does not claim to be about.
    #[test]
    fn simulation_state_evidence_must_decode_and_match_its_key() {
        let (envelope, _) = fixture_envelope_and_meta();
        // The control value: the unmutated change must parse, or every case below could be
        // failing for one unrelated reason.
        assert!(
            parse_simulate(
                NET,
                &envelope,
                &simulation_response(json!([valid_state_change()]))
            )
            .is_ok(),
            "the valid state change must parse, or the mutations below prove nothing"
        );

        let other_key = {
            let mut entry = fx::contract_data_entry(2);
            let stellar_xdr::LedgerEntryData::ContractData(data) = &mut entry.data else {
                panic!("the fixture entry is contract data");
            };
            data.contract = fx::account_sc();
            entry
        };
        for (field, replacement, expected) in [
            ("key", json!("AAAA-key-xdr"), "key"),
            ("before", json!("AAAA-before-xdr"), "before"),
            ("after", json!(base64(&other_key)), "key"),
            // A whole `LedgerEntryData` where a `LedgerEntry` belongs: the same
            // wrapper-versus-payload confusion that broke `getLedgerEntries` for three weeks,
            // in the field where it would be silent.
            (
                "before",
                json!(base64(&fx::contract_data_entry(1).data)),
                "before",
            ),
        ] {
            let mut change = valid_state_change();
            change[field] = replacement;
            let error = parse_simulate(NET, &envelope, &simulation_response(json!([change])))
                .expect_err(&format!(
                    "state change with a bad '{field}' must be rejected"
                ))
                .to_string();
            assert!(
                error.contains(expected),
                "a bad '{field}' must be reported against '{expected}': {error}"
            );
        }
    }

    /// The documented presence matrix: a creation has no before, a deletion has no after, an
    /// update has both. A response that contradicts its own change kind is malformed, not a
    /// change we quietly record half of.
    #[test]
    fn simulation_state_change_kinds_require_their_documented_sides() {
        let (envelope, _) = fixture_envelope_and_meta();
        let with = |kind: &str, sides: &[&str]| {
            let mut change = valid_state_change();
            change["type"] = json!(kind);
            let object = change.as_object_mut().unwrap();
            for side in ["before", "after"] {
                if !sides.contains(&side) {
                    object.remove(side);
                }
            }
            change
        };
        // Control: each kind with exactly the sides it documents.
        for (kind, sides) in [
            ("created", &["after"][..]),
            ("updated", &["before", "after"][..]),
            ("deleted", &["before"][..]),
        ] {
            assert!(
                parse_simulate(
                    NET,
                    &envelope,
                    &simulation_response(json!([with(kind, sides)]))
                )
                .is_ok(),
                "'{kind}' with {sides:?} is the documented shape and must parse"
            );
        }
        for (kind, sides) in [
            ("created", &["before", "after"][..]),
            ("created", &[][..]),
            ("updated", &["before"][..]),
            ("updated", &["after"][..]),
            ("deleted", &["before", "after"][..]),
            ("deleted", &[][..]),
        ] {
            assert!(
                parse_simulate(
                    NET,
                    &envelope,
                    &simulation_response(json!([with(kind, sides)]))
                )
                .is_err(),
                "'{kind}' with {sides:?} contradicts its kind and must be rejected"
            );
        }
    }

    /// The recorded summary comes from the decoded key, not from a placeholder: a reader of the
    /// recording sees which kind of entry changed and which contract owns it, the same way the
    /// meta-derived changes describe themselves.
    #[test]
    fn simulation_state_changes_are_summarized_from_the_decoded_key() {
        let (envelope, _) = fixture_envelope_and_meta();
        let snapshot = parse_simulate(
            NET,
            &envelope,
            &simulation_response(json!([valid_state_change()])),
        )
        .unwrap();
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        let change = &bundle.state_changes[0];
        assert_eq!(change.entry, "contract_data");
        assert_eq!(
            change.contract,
            Some(format!("{}", stellar_strkey::Contract(fx::TOKEN_CID))),
            "the owning contract is in the decoded key; a summary that omits it is a guess"
        );
    }

    struct ExecutableTransport {
        transaction: serde_json::Value,
        instance_keys: Vec<String>,
        instance_entries: Vec<serde_json::Value>,
        calls: RefCell<Vec<String>>,
    }

    impl RpcTransport for ExecutableTransport {
        fn call(
            &self,
            method: &str,
            params: serde_json::Value,
        ) -> Result<serde_json::Value, RpcError> {
            self.calls.borrow_mut().push(method.to_string());
            match method {
                "getNetwork" => Ok(network_response()),
                "getTransaction" => Ok(self.transaction.clone()),
                "getLedgerEntries" => {
                    assert_eq!(params["keys"], json!(self.instance_keys));
                    Ok(json!({
                        "entries": self.instance_entries,
                        "latestLedger": 4200102
                    }))
                }
                other => Err(RpcError::Rpc(format!("unexpected method {other}"))),
            }
        }
    }

    #[test]
    fn rpc_acquisition_records_observed_contract_wasm_hashes() {
        let (envelope, meta) = fixture_envelope_and_meta();
        let tx_hash = transaction_hash(&envelope);
        let code_hash = [7u8; 32];
        let instance = |contract: stellar_xdr::ScAddress, executable: ContractExecutable| {
            let key = LedgerKey::ContractData(LedgerKeyContractData {
                contract: contract.clone(),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            let entry = LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract,
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
                val: ScVal::ContractInstance(ScContractInstance {
                    executable,
                    storage: None,
                }),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            (
                key.clone(),
                json!({
                    "key": key,
                    "xdr": entry,
                    "lastModifiedLedgerSeq": 4200099
                }),
            )
        };
        let account = format!("{}", stellar_strkey::Contract(fx::ACCOUNT_CID));
        let token = format!("{}", stellar_strkey::Contract(fx::TOKEN_CID));
        let mut keyed_entries = vec![
            (
                account.clone(),
                instance(fx::account_sc(), ContractExecutable::Wasm(Hash(code_hash))),
            ),
            (
                token,
                instance(fx::token_sc(), ContractExecutable::StellarAsset),
            ),
        ];
        keyed_entries.sort_by(|left, right| left.1 .0.cmp(&right.1 .0));
        let instance_keys = keyed_entries
            .iter()
            .map(|(_, (key, _))| key.clone())
            .collect();
        let instance_entries = keyed_entries
            .into_iter()
            .map(|(_, (_, entry))| entry)
            .collect();
        let transport = ExecutableTransport {
            transaction: json!({
                "status": "SUCCESS",
                "txHash": tx_hash.clone(),
                "envelopeXdr": envelope,
                "resultXdr": result_xdr(true),
                "resultMetaXdr": meta,
                "ledger": 4200100,
                "createdAt": "1780000000"
            }),
            instance_keys,
            instance_entries,
            calls: RefCell::new(Vec::new()),
        };

        let snapshot = get_transaction(&transport, NET, &tx_hash).unwrap();
        let bundle = record(&snapshot, RecordOptions::default()).unwrap();
        let observation = bundle.contract_executables.get(&account).unwrap();
        assert!(matches!(
            observation.executable,
            ozpb_recorder_core::ObservedExecutable::Wasm { code_hash: observed }
                if observed.0 == code_hash
        ));
        assert_eq!(observation.observed_ledger.0, 4_200_102);
        assert_eq!(
            transport.calls.borrow().as_slice(),
            ["getNetwork", "getTransaction", "getLedgerEntries"]
        );
    }
}
