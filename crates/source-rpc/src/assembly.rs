//! Unsigned install assembly. Recording authorization estimates resources; it does not
//! check the owner's authorization. Wallets must reconstruct, review and enforce-simulate
//! their completed authorization before signing the transaction.

use super::{ensure_base64_size, verify_network, xdr_limits, RpcError, RpcTransport};
use ozpb_domain::NetworkId;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::*;

/// Local assembly parameters, never a signed envelope or caller-supplied simulation.
pub struct InstallAssemblyRequest {
    pub invocation: InvokeContractArgs,
    pub fee_payer: String,
    pub max_fee_stroops: u32,
    /// Hard bounded to 1..=120; this is a transaction bound, not an authority validity claim.
    pub validity_ledgers: u32,
    pub authority_observed_ledger: u32,
}

#[derive(Clone, Debug)]
pub struct InstallAssemblyObservation {
    pub envelope_xdr_base64: String,
    pub envelope_xdr_sha256: String,
    pub network_id: String,
    pub sequence_read_ledger: u32,
    pub simulation_ledger: u32,
    pub min_ledger: u32,
    /// Exclusive upper bound, as in Stellar's LedgerBounds.
    pub max_ledger: u32,
    pub fee_stroops: u32,
    pub source_sequence: i64,
    pub restoration: AssemblyRestoration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssemblyRestoration {
    None,
    /// This envelope restores only. Execute it through the wallet, then acquire a new intent.
    SeparateTransaction,
    /// Protocol 23+ restores within the invocation. Wallet preflight must account for this.
    Automatic,
}

pub fn assemble_install_transaction<T: RpcTransport>(
    transport: &T,
    network_passphrase: &str,
    request: &InstallAssemblyRequest,
) -> Result<InstallAssemblyObservation, RpcError> {
    assemble(transport, network_passphrase, request)
}

fn endpoint_error(error: RpcError) -> RpcError {
    match error {
        RpcError::Transport(_) => {
            RpcError::Transport("assembly request failed (endpoint detail withheld)".into())
        }
        RpcError::Rpc(_) => {
            RpcError::Rpc("assembly request failed (endpoint detail withheld)".into())
        }
        RpcError::Malformed(_) => {
            malformed("invalid assembly RPC response (endpoint detail withheld)")
        }
        RpcError::NetworkMismatch { .. } => RpcError::NetworkMismatch {
            expected: "configured network".into(),
            actual: "different network (endpoint detail withheld)".into(),
        },
        other => other,
    }
}

fn malformed(message: &str) -> RpcError {
    RpcError::Malformed(message.into())
}

fn invalid(message: &str) -> RpcError {
    RpcError::InvalidRequest(message.into())
}

fn assemble<T: RpcTransport>(
    transport: &T,
    passphrase: &str,
    request: &InstallAssemblyRequest,
) -> Result<InstallAssemblyObservation, RpcError> {
    // Refuse before sending anything. The facade supplies the exact five typed arguments;
    // the adapter additionally constrains the operation it will ever assemble.
    if !(1..=120).contains(&request.validity_ledgers) || request.authority_observed_ledger == 0 {
        return Err(invalid(
            "assembly requires 1..=120 validity ledgers and an authority observation",
        ));
    }
    if request.max_fee_stroops < 100 {
        return Err(invalid("maximum fee must be at least 100 stroops"));
    }
    if !matches!(request.invocation.contract_address, ScAddress::Contract(_))
        || request.invocation.function_name
            != ScSymbol::try_from("add_context_rule").map_err(|_| invalid("function name"))?
        || request.invocation.args.len() != 5
    {
        return Err(invalid(
            "only the exact add_context_rule invocation can be assembled",
        ));
    }
    let payer = request
        .fee_payer
        .parse::<stellar_strkey::ed25519::PublicKey>()
        .map_err(|_| invalid("fee payer must be a canonical classic G-address"))?;
    if format!("{payer}") != request.fee_payer {
        return Err(invalid("fee payer must be a canonical classic G-address"));
    }
    verify_network(transport, passphrase).map_err(endpoint_error)?;
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer.0))),
    });
    let response = transport
        .call(
            "getLedgerEntries",
            json!({"keys":[encode(&key)?],"xdrFormat":"base64"}),
        )
        .map_err(endpoint_error)?;
    let sequence_ledger = ledger(&response)?;
    ordered_ledgers(request.authority_observed_ledger, sequence_ledger)?;
    let entries = response["entries"]
        .as_array()
        .ok_or_else(|| malformed("sequence response lacks entries"))?;
    let [entry] = entries.as_slice() else {
        return Err(malformed(
            "fee payer read did not return exactly one account",
        ));
    };
    let returned_key: LedgerKey = decode_field(entry, "key")?;
    if returned_key != key {
        return Err(malformed("fee payer response answers a different key"));
    }
    let LedgerEntryData::Account(account) = decode_field(entry, "xdr")? else {
        return Err(malformed("fee payer response is not an account"));
    };
    if account.account_id != AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(payer.0))) {
        return Err(malformed("fee payer entry does not match its key"));
    }
    let modified = entry["lastModifiedLedgerSeq"]
        .as_u64()
        .ok_or_else(|| malformed("fee payer lacks modification ledger"))?;
    if modified == 0 || modified > u64::from(sequence_ledger) {
        return Err(malformed("fee payer modification ledger is invalid"));
    }
    let source_sequence = account.seq_num.0;
    if source_sequence < 0 {
        return Err(malformed("negative fee payer sequence"));
    }
    let next_sequence = source_sequence
        .checked_add(1)
        .ok_or_else(|| malformed("fee payer sequence overflow"))?;
    let max_ledger = sequence_ledger
        .checked_add(request.validity_ledgers)
        .ok_or_else(|| malformed("transaction ledger bound overflow"))?;
    let fees = transport
        .call("getFeeStats", json!({}))
        .map_err(endpoint_error)?;
    let fee_ledger = ledger(&fees)?;
    ordered_ledgers(sequence_ledger, fee_ledger)?;
    let inclusion_fee = unsigned_decimal(
        &fees["sorobanInclusionFee"]["p90"],
        "invalid inclusion fee estimate",
    )?
    .max(100);
    let inclusion_fee =
        u32::try_from(inclusion_fee).map_err(|_| malformed("inclusion fee exceeds u32"))?;
    if inclusion_fee > request.max_fee_stroops {
        return Err(invalid("inclusion fee exceeds maximum fee"));
    }
    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(request.invocation.clone()),
            auth: Default::default(),
        }),
    };
    let mut envelope = TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(payer.0)),
            fee: inclusion_fee,
            seq_num: SequenceNumber(next_sequence),
            cond: Preconditions::V2(PreconditionsV2 {
                time_bounds: None,
                ledger_bounds: Some(LedgerBounds {
                    min_ledger: sequence_ledger,
                    max_ledger,
                }),
                min_seq_num: None,
                min_seq_age: Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: Default::default(),
            }),
            memo: Memo::None,
            operations: vec![operation]
                .try_into()
                .map_err(|_| invalid("operation bound"))?,
            ext: TransactionExt::V0,
        },
        signatures: Default::default(),
    };
    let simulation = transport
        .call(
            "simulateTransaction",
            json!({
                "transaction":encode(&TransactionEnvelope::Tx(envelope.clone()))?,
                "authMode":"record", "xdrFormat":"base64"
            }),
        )
        .map_err(endpoint_error)?;
    let simulation_ledger = ledger(&simulation)?;
    ordered_ledgers(fee_ledger, simulation_ledger)?;
    ordered_ledgers(request.authority_observed_ledger, simulation_ledger)?;
    // latestLedger is already closed. Both invocation and restoration drafts
    // need at least the next ledger below the transaction's exclusive maximum.
    if simulation_ledger
        .checked_add(1)
        .is_none_or(|next| next >= max_ledger)
    {
        return Err(malformed("assembly ledger bound already expired"));
    }
    if simulation.get("error").is_some() {
        return Err(malformed(
            "install simulation failed (endpoint detail withheld)",
        ));
    }
    let mut data = transaction_data(&simulation)?;
    let results = simulation["results"]
        .as_array()
        .ok_or_else(|| malformed("install simulation lacks results"))?;
    let [one] = results.as_slice() else {
        return Err(malformed("install simulation must have one result"));
    };
    let returned: ScVal = decode_field(one, "xdr")?;
    returned
        .validate()
        .map_err(|_| malformed("invalid simulation return value"))?;
    let auth = one["auth"]
        .as_array()
        .ok_or_else(|| malformed("install simulation lacks authorization"))?;
    let [encoded_auth] = auth.as_slice() else {
        return Err(malformed(
            "install simulation must record exactly one account authorization",
        ));
    };
    let mut auth: SorobanAuthorizationEntry = decode_value(encoded_auth)?;
    let expected_root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(request.invocation.clone()),
        sub_invocations: Default::default(),
    };
    if auth.root_invocation != expected_root {
        return Err(malformed(
            "recorded authorization differs from the intended install invocation",
        ));
    }
    let credentials = match &mut auth.credentials {
        SorobanCredentials::Address(credentials) | SorobanCredentials::AddressV2(credentials) => {
            credentials
        }
        _ => {
            return Err(malformed(
                "unsupported recorded account authorization credentials",
            ))
        }
    };
    if credentials.address != request.invocation.contract_address
        || credentials.signature != ScVal::Void
    {
        return Err(malformed(
            "recorded authorization has another address or a signature",
        ));
    }
    // The wallet must supply the owner payload and may lower this upper bound. Any change
    // requires revalidating and enforce-simulating that completed authorization.
    credentials.signature_expiration_ledger = max_ledger - 1;
    let restoration = if let Some(restore) = simulation.get("restorePreamble") {
        let invocation_footprint = data.resources.footprint.clone();
        data = transaction_data(restore)?;
        if !data.resources.footprint.read_only.is_empty()
            || data.resources.footprint.read_write.is_empty()
        {
            return Err(malformed(
                "restoration footprint must contain only nonempty writable keys",
            ));
        }
        if automatic_restoration(&data)? {
            return Err(malformed(
                "separate restoration cannot itself declare automatic restoration",
            ));
        }
        for key in &data.resources.footprint.read_write {
            if !restorable_key(key)
                || !invocation_footprint.read_only.contains(key)
                    && !invocation_footprint.read_write.contains(key)
            {
                return Err(malformed(
                    "restoration key is not a persistent Soroban entry in the invocation footprint",
                ));
            }
        }
        envelope.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::RestoreFootprint(RestoreFootprintOp {
                ext: ExtensionPoint::V0,
            }),
        }]
        .try_into()
        .map_err(|_| invalid("operation bound"))?;
        AssemblyRestoration::SeparateTransaction
    } else {
        envelope.tx.operations = vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(request.invocation.clone()),
                auth: vec![auth]
                    .try_into()
                    .map_err(|_| invalid("authorization bound"))?,
            }),
        }]
        .try_into()
        .map_err(|_| invalid("operation bound"))?;
        if automatic_restoration(&data)? {
            AssemblyRestoration::Automatic
        } else {
            AssemblyRestoration::None
        }
    };
    let resource_fee =
        u32::try_from(data.resource_fee).map_err(|_| malformed("resource fee exceeds u32"))?;
    let fee = inclusion_fee
        .checked_add(resource_fee)
        .ok_or_else(|| malformed("total fee overflow"))?;
    if fee > request.max_fee_stroops {
        return Err(invalid("assembled fee exceeds maximum fee"));
    }
    envelope.tx.fee = fee;
    envelope.tx.ext = TransactionExt::V1(data);
    let envelope = TransactionEnvelope::Tx(envelope);
    let bytes = envelope
        .to_xdr(xdr_limits())
        .map_err(|_| malformed("assembled envelope exceeds XDR bounds"))?;
    Ok(InstallAssemblyObservation {
        envelope_xdr_base64: encode(&envelope)?,
        envelope_xdr_sha256: hex::encode(Sha256::digest(&bytes)),
        network_id: NetworkId::from_passphrase(passphrase).0.to_hex(),
        sequence_read_ledger: sequence_ledger,
        simulation_ledger,
        min_ledger: sequence_ledger,
        max_ledger,
        fee_stroops: fee,
        source_sequence,
        restoration,
    })
}

fn ledger(value: &Value) -> Result<u32, RpcError> {
    value["latestLedger"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| malformed("assembly response lacks a nonzero u32 latestLedger"))
}

fn ordered_ledgers(before: u32, after: u32) -> Result<(), RpcError> {
    if after < before || after - before > 12 {
        return Err(malformed(
            "assembly reads have inconsistent or stale ledgers; retry the authority check",
        ));
    }
    Ok(())
}

fn unsigned_decimal(value: &Value, message: &str) -> Result<u64, RpcError> {
    let text = value.as_str().ok_or_else(|| malformed(message))?;
    let parsed = text.parse::<u64>().map_err(|_| malformed(message))?;
    if parsed.to_string() != text {
        return Err(malformed(message));
    }
    Ok(parsed)
}

fn encode<T: WriteXdr>(value: &T) -> Result<String, RpcError> {
    value
        .to_xdr_base64(xdr_limits())
        .map_err(|_| malformed("assembly XDR exceeds bounds"))
}

fn decode_value<T: ReadXdr>(value: &Value) -> Result<T, RpcError> {
    let encoded = value
        .as_str()
        .ok_or_else(|| malformed("assembly response lacks XDR text"))?;
    ensure_base64_size("assembly response XDR", encoded)?;
    T::from_xdr_base64(encoded, xdr_limits())
        .map_err(|_| malformed("invalid assembly response XDR"))
}

fn decode_field<T: ReadXdr>(value: &Value, field: &str) -> Result<T, RpcError> {
    decode_value(&value[field])
}

fn transaction_data(value: &Value) -> Result<SorobanTransactionData, RpcError> {
    let data: SorobanTransactionData = decode_field(value, "transactionData")?;
    let fee = unsigned_decimal(&value["minResourceFee"], "invalid minimum resource fee")?;
    if i64::try_from(fee).ok() != Some(data.resource_fee) {
        return Err(malformed(
            "minimum resource fee disagrees with transaction data",
        ));
    }
    // Duplicate or overlapping footprint entries are not an admissible transaction.
    let mut seen = std::collections::BTreeSet::new();
    for key in data
        .resources
        .footprint
        .read_only
        .iter()
        .chain(data.resources.footprint.read_write.iter())
    {
        if !seen.insert(encode(key)?) {
            return Err(malformed("duplicate assembly footprint key"));
        }
    }
    Ok(data)
}

fn automatic_restoration(data: &SorobanTransactionData) -> Result<bool, RpcError> {
    let SorobanTransactionDataExt::V1(ext) = &data.ext else {
        return Ok(false);
    };
    let mut seen = std::collections::BTreeSet::new();
    for index in &ext.archived_soroban_entries {
        let key = data.resources.footprint.read_write.get(*index as usize);
        if key.is_none_or(|key| !restorable_key(key)) || !seen.insert(*index) {
            return Err(malformed(
                "invalid automatic restoration footprint index or key",
            ));
        }
    }
    Ok(!seen.is_empty())
}

fn restorable_key(key: &LedgerKey) -> bool {
    matches!(
        key,
        LedgerKey::ContractCode(_)
            | LedgerKey::ContractData(LedgerKeyContractData {
                durability: ContractDataDurability::Persistent,
                ..
            })
    )
}

#[cfg(test)]
mod tests;
