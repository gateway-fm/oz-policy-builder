//! Streaming digest of the exact keys, values, and TTL metadata inspected by one scan.
//!
//! The digest is an identity of endpoint responses, not a cryptographic ledger proof.
//! Every field is length-delimited or fixed-width. Keys are canonical XDR and sorted by
//! their bytes; absent requested keys are included with a distinct tag.

use ozpb_domain::{domains, Hash32, NetworkId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LedgerWitness {
    Absent,
    Present {
        entry_data_xdr: Vec<u8>,
        last_modified_ledger: u32,
        live_until_ledger: u32,
    },
}

/// `account_id` is the parsed 32-byte C-address identity, never the request's spelling.
/// `ledger` is endpoint-reported. All witnesses must have passed the entry validators
/// before this function is called.
pub(crate) fn ordered_ledger_witness_digest(
    network: NetworkId,
    account_id: [u8; 32],
    ledger: u32,
    entries: &BTreeMap<Vec<u8>, LedgerWitness>,
) -> Hash32 {
    let mut hash = Sha256::new();
    hash.update(domains::ACCOUNT_LEDGER_WITNESS.as_bytes());
    hash.update([0]);
    let NetworkId(Hash32(network_bytes)) = network;
    hash.update(network_bytes);
    hash.update(account_id);
    hash.update(ledger.to_be_bytes());
    hash.update((entries.len() as u32).to_be_bytes());
    for (key, witness) in entries {
        hash.update((key.len() as u32).to_be_bytes());
        hash.update(key);
        match witness {
            LedgerWitness::Absent => hash.update([0]),
            LedgerWitness::Present {
                entry_data_xdr,
                last_modified_ledger,
                live_until_ledger,
            } => {
                hash.update([1]);
                hash.update((entry_data_xdr.len() as u32).to_be_bytes());
                hash.update(entry_data_xdr);
                hash.update(last_modified_ledger.to_be_bytes());
                hash.update(live_until_ledger.to_be_bytes());
            }
        }
    }
    Hash32(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(entries: &BTreeMap<Vec<u8>, LedgerWitness>) -> Hash32 {
        ordered_ledger_witness_digest(NetworkId(Hash32([3; 32])), [7; 32], 10, entries)
    }

    #[test]
    fn ordering_is_canonical_and_every_value_and_ttl_is_committed() {
        let value = LedgerWitness::Present {
            entry_data_xdr: vec![1, 2, 3],
            last_modified_ledger: 4,
            live_until_ledger: 20,
        };
        let mut entries = BTreeMap::new();
        entries.insert(vec![2], LedgerWitness::Absent);
        entries.insert(vec![1], value.clone());
        let original = digest(&entries);
        let reordered =
            BTreeMap::from([(vec![1], value.clone()), (vec![2], LedgerWitness::Absent)]);
        assert_eq!(original, digest(&reordered));

        for changed in [
            LedgerWitness::Absent,
            LedgerWitness::Present {
                entry_data_xdr: vec![1, 2, 4],
                last_modified_ledger: 4,
                live_until_ledger: 20,
            },
            LedgerWitness::Present {
                entry_data_xdr: vec![1, 2, 3],
                last_modified_ledger: 5,
                live_until_ledger: 20,
            },
            LedgerWitness::Present {
                entry_data_xdr: vec![1, 2, 3],
                last_modified_ledger: 4,
                live_until_ledger: 21,
            },
        ] {
            entries.insert(vec![1], changed);
            assert_ne!(original, digest(&entries));
        }
    }
}
