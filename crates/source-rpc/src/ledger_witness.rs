//! Streaming digest of the exact keys, values, and TTL metadata inspected by one scan.
//!
//! The digest is an identity of endpoint responses, not a cryptographic ledger proof.
//! Every field is length-delimited or fixed-width. Keys are canonical XDR and sorted by
//! their bytes; absent requested keys are included with a distinct tag. The byte layout is
//! specified in `docs/CANONICAL-HASHING.md`.

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
    /// A classic ledger entry (an account), which has no TTL to report.
    Classic {
        entry_data_xdr: Vec<u8>,
        last_modified_ledger: u32,
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
            LedgerWitness::Classic {
                entry_data_xdr,
                last_modified_ledger,
            } => {
                hash.update([2]);
                hash.update((entry_data_xdr.len() as u32).to_be_bytes());
                hash.update(entry_data_xdr);
                hash.update(last_modified_ledger.to_be_bytes());
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
    fn digest_is_the_documented_byte_layout() {
        // Recomputed outside this crate from the layout in docs/CANONICAL-HASHING.md.
        let entries = BTreeMap::from([
            (
                vec![1],
                LedgerWitness::Present {
                    entry_data_xdr: vec![1, 2, 3],
                    last_modified_ledger: 4,
                    live_until_ledger: 20,
                },
            ),
            (vec![2], LedgerWitness::Absent),
        ]);
        assert_eq!(
            digest(&entries).to_hex(),
            "ac6be4d14e27d084fad6f9908747ea68f3bd8484a6a5a91f8c13b17c8a657497"
        );
    }

    #[test]
    fn a_classic_entry_has_its_own_tag_and_no_ttl() {
        // Recomputed outside this crate from the layout in docs/CANONICAL-HASHING.md.
        let mut expected = Sha256::new();
        expected.update(b"ozpb:v1:account-ledger-witness\0");
        expected.update([3; 32]);
        expected.update([7; 32]);
        expected.update(10u32.to_be_bytes());
        expected.update(1u32.to_be_bytes());
        expected.update(1u32.to_be_bytes());
        expected.update([1]);
        expected.update([2]);
        expected.update(3u32.to_be_bytes());
        expected.update([1, 2, 3]);
        expected.update(4u32.to_be_bytes());
        let entries = BTreeMap::from([(
            vec![1],
            LedgerWitness::Classic {
                entry_data_xdr: vec![1, 2, 3],
                last_modified_ledger: 4,
            },
        )]);
        assert_eq!(digest(&entries), Hash32(expected.finalize().into()));
        // The same value, pinned, so a change to the layout cannot pass by changing both sides.
        assert_eq!(
            digest(&entries).to_hex(),
            "6ddd386868d7f42e37ccddcfee25f98a1c0695df4a07679c4efd94d9e8f2b13a"
        );
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
