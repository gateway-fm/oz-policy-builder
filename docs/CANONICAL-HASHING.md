# Canonical hashing

Every hash this toolkit publishes is taken over an `ScVal` encoded as XDR, except the account
ledger witness and the plain SHA-256 values, which have their own sections below. This document
is the specification an independent implementation follows to reproduce one.

It exists because a hash is only evidence if someone other than its author can recompute it. The
previous scheme hashed `serde_json` output, whose byte layout was defined by nothing but this
repository's Rust source — field order came from declaration order, and map ordering from a rule
written in a doc comment. Anyone outside the repository was asked to take the values on trust,
which is the opposite of the point.

The rules below are implemented in `crates/domain/src/canonical.rs` and pinned by tests there,
including one that encodes a fixture and compares the bytes against a value written down in the
test. If this document and the code disagree, that test fails.

## The preimage

```text
preimage = ScVal::Vec [ ScVal::U32(canonicalization version)
                      , ScVal::String(domain)
                      , <the encoded value>
                      ]

hash     = SHA-256(preimage encoded as XDR)
```

The canonicalization version is **2**. Version 1 was the JSON scheme and is not reproducible from
a specification; nothing in the current tree produces it.

The domain travels inside the preimage rather than as a prefix outside it, following the protocol:
`HashIdPreimage` is a union whose discriminant names the structure being hashed, and the hash
covers the whole encoded union.

### Why not the protocol's own union

`HashIdPreimage` and its `EnvelopeType` discriminants are a registry the protocol owns. Taking a
number from it would mean a future protocol addition silently collides with these hashes, and
would tell any tool reading the bytes that a policy specification is a protocol object, which is
false. Only the pattern is borrowed.

### Domains

The tag is the domain string itself. The `v1` inside it is the **schema** version of that
structure and is independent of the canonicalization version above; the architecture treats the
two as separate and so does this.

| Domain | Structure |
|---|---|
| `ozpb:v1:auth-fingerprint` | authorizer plus root authorized invocation |
| `ozpb:v1:recording` | a complete recording bundle |
| `ozpb:v1:policy-spec` | a policy specification |
| `ozpb:v1:signer-set` | the signers of one rule, as the account stores them |
| `ozpb:v1:registry-snapshot` | a capability registry snapshot |
| `ozpb:v1:codegen-input` | the normalized inputs a generated crate is emitted from |
| `ozpb:v1:build-manifest` | a build manifest |
| `ozpb:v1:policy-binding-set` | a policy binding set |
| `ozpb:v1:policy-check-request` | the complete typed `CheckAgainstPolicyInput` |
| `ozpb:v1:account-state` | the enumerated account rule-set an authority result was computed over |
| `ozpb:v1:account-ledger-witness` | the raw entries one account scan read; its own byte layout, below |
| `ozpb:v1:account-method-inventory` | the source-reviewed method table for one exact account Wasm hash |
| `ozpb:v1:account-admin-candidate` | one observed, structurally eligible management rule |
| `ozpb:v1:generated-source` | a generated crate's source files, lockfile excluded |
| `ozpb:v1:generated-crate-files` | a generated crate's complete emitted file set |
| `ozpb:v1:surface-verdict` | the `authority_commitment`: authority-relevant state plus exact intent |

One structure, one domain. A domain used for two structures forfeits exactly the separation the
scheme exists to provide.

The authority commitment covers (as one canonical map, so the order is the encoding's, not this
list's): the network ID, the account address and observed
account code hash, the spec hash, the binding-set hash, every bound policy address with its
observed code hash, the grant (spec rule index, target, whether it keeps state, its signers as
the account stores them, and the rest of the exact `add_context_rule` arguments: name,
`valid_until`, each policy address with its install parameters), the scope, the authority list,
the refusals, the unresolved items, the coverage exclusions, the notes, and the authority state
(the `account-state` digest and the signing configuration of every classic account read). The
observed ledger and the acquisition evidence (TTLs, ledger metadata) are deliberately absent: a
re-read immediately before signing reproduces the commitment exactly when nothing that decides
the answer has moved, whichever ledger it lands on. It identifies a result; it does not
authenticate one.

The policy-check request hash covers the deserialized input, including its specification, binding
set, signed registry snapshot, account and network identities, both rule selectors, configured RPC
source, ordered candidate signers, and proposed invocation. The permit/deny evidence records this
hash as `request_hash` so a consumer can compare it with the request it sent.

The account method inventory hash covers `AccountMethodInventory`
(`crates/registry/src/account_methods.rs`) by the ordinary rules. A signed account entry commits
to it as `method_inventory_digest`; `reviewed_table_digest_is_a_known_answer` pins the value of
the current reviewed table.

The account admin-candidate fingerprint identifies one eligible management rule as a scan
observed it. Its preimage is a named struct, so a `Map` keyed by these field `Symbol`s:

```text
network_id       String(lowercase hex of the 32-byte network ID)
account_address  String(account C-strkey)
rule_id          U32(rule ID)
scope            Vec [ Symbol("default") ]  |  Vec [ Symbol("call_account") ]
valid_until      Vec []  |  Vec [ U32(ledger) ]
signer_entries   Vec [ Vec [ U32(signer ID), String(delegated G- or C-strkey) ], … ]  ascending by ID
```

`network_id` is a `NetworkId`, a newtype over `Hash32`, and `Hash32` serializes as its 64
lowercase hex characters. A delegated signer is an account (G-) or contract (C-) address, written
as its canonical strkey. `scope` is `default` for a `Default` rule and `call_account` for a
`CallContract` rule naming the account itself. The rule's display name is not committed.
`admin_fingerprint_is_the_documented_canonical_structure` in
`crates/source-rpc/src/account_state_projection.rs` builds this `ScVal` by hand and pins two
known answers.

## The encoding

The mapping is from serde's data model, so the JSON on the wire and the preimage are two encodings
of one schema: a reader holding the JSON can derive the `ScVal` from these rules alone.

| Rust / serde | `ScVal` |
|---|---|
| `bool` | `Bool` |
| `i8` `i16` `i32` | `I32` |
| `i64` | `I64` |
| `i128` | `I128` |
| `u8` `u16` `u32` | `U32` |
| `u64` | `U64` |
| `u128` | `U128` |
| `f32` `f64` | **rejected** |
| `char`, `&str`, `String` | `String` |
| `&[u8]` | `Bytes` |
| `None` | `Vec []` |
| `Some(v)` | `Vec [v]` |
| `()`, unit struct | `Void` |
| newtype struct | the inner value, transparently |
| sequence, tuple, tuple struct | `Vec` |
| named struct | `Map`, keys `Symbol(field name)` |
| map | `Map`, keys the **encoded key** |
| unit variant | `Vec [Symbol(variant)]` |
| newtype variant | `Vec [Symbol(variant), inner]` |
| tuple variant | `Vec [Symbol(variant), fields…]` |
| struct variant | `Vec [Symbol(variant), Map]` |

Field and variant names are the **serialized** names, after any `serde(rename)` or
`rename_all`. Most of this schema is `snake_case`; `ContextType` serializes as `CallContract` and
`SelfMarker` as `SELF`, and those are the names that are encoded. Normalising the casing would
change every hash.

### Decisions worth their reasoning

**Struct field names are `Symbol`s; map keys are not.** A field name is schema, and holding it to
`Symbol`'s charset and 32-byte limit is useful — it fails loudly on a name no `ScVal` could
carry, which is why `$schema` had to be renamed. A map *key* here is data: registry snapshots are
keyed by 64-character hex hashes, recording bundles by 56-character strkeys, templates by names
like `policy-templates/scope@1`. None of those is a legal `Symbol`, so keys are encoded by the
ordinary rules, which makes them `String`s.

**`Option` is wrapped, not flattened.** Soroban's own convention maps `None` to `Void` and
`Some(v)` to `v`. That is more compact and makes `None` and `Some(())` the same bytes. Wrapping
costs a few bytes and makes the ambiguity unrepresentable.

**Floats are refused at encode time.** `clippy.toml` bans them in this workspace, but a lint is a
policy about code we write; the encoder refuses them for any type, including one it has never
seen. `ScVal` has no float variant, so the refusal matches the platform.

**Map ordering is not defined here.** `ScMap::sorted_from_entries` sorts by key and validates, and
`impl Validate for ScMap` requires strictly ascending keys, which also rejects duplicates. That
rule is published by the XDR crate; restating it would risk restating it differently.

**`Symbol` validity is checked when a symbol is built.** `ScSymbol`'s own conversion enforces only
the 32-byte length — the charset lives in `impl Validate for ScVal`, which `ScMap` runs over its
keys. So a struct field name was checked and an enum variant tag inside a `Vec` was not. An
implementation that skips this check can produce an `ScVal` no host would accept, whose bytes
still hash.

### Types that are built as `ScVal` directly

Two preimages are not derived from a Rust type through serde, because their inputs are already
protocol values. Routing them through the serde encoder would encode `ScVal`'s *own* serde
representation and then map that to an `ScVal` again.

**Authorization fingerprint** — `Vec [ Address(authorizer), Bytes(canonical XDR of the root
authorized invocation) ]`. The invocation has no `ScVal` counterpart, so it is carried as its own
XDR bytes.

**Signer set** — `Vec [ <signer>, … ]`, sorted by the XDR crate's ordering on the encoded values,
so the set has one encoding regardless of the order the signers were listed in. Each signer is the
shape `stellar-accounts` stores, which is what `__check_auth` matches against:

```text
Signer::Delegated(address)        → Vec [ Symbol("Delegated"), String(strkey) ]
Signer::External(verifier, key)   → Vec [ Symbol("External"), String(strkey), Bytes(key) ]
```

`verifier_code_hash` is absent because the account matches on `Signer`, which does not carry it.
The address is its strkey rather than a parsed `Address`: parsing verifies a checksum, this
schema admits addresses without one, and a hash that fails on input the schema accepts pushes the
failure to a caller who then has to compare two `Result`s. A strkey is a checksummed canonical
encoding of exactly one address, so carrying it as a string conflates nothing.

## Account ledger witness

`ozpb:v1:account-ledger-witness` is not an `ScVal` preimage. A scan's witness set holds the raw
entry XDR of every rule, signer, policy, and contract instance it read, which can exceed
`MAX_CANONICAL_PREIMAGE_BYTES` (4 MiB), so the digest is streamed over a length-delimited byte
layout instead. The domain is an outer prefix ended by a zero byte, and the canonicalization
version is not part of it; the `v1` in the domain is the only version this layout carries.

```text
SHA-256(
    "ozpb:v1:account-ledger-witness" || 0x00
 || network ID                        32 bytes
 || account contract ID               32 bytes, parsed from the C-address
 || reported ledger                   u32
 || entry count                       u32
 || for each entry, ascending by key bytes:
        key length u32 || key                      canonical XDR LedgerKey
     || 0x00                                       a requested key the endpoint omitted
      | 0x01 || payload length u32 || payload      canonical XDR LedgerEntryData
             || lastModifiedLedgerSeq u32 || liveUntilLedgerSeq u32
)
```

Every integer is big-endian. A key read twice in one scan appears once and must carry identical
bytes and metadata both times, or the scan fails; an archived entry never reaches the digest,
because the scan refuses it first. The ledger is the endpoint's reported `latestLedger`, so the
digest identifies the responses a scan used; it is not a ledger-state proof.
`digest_is_the_documented_byte_layout` in `crates/source-rpc/src/ledger_witness.rs` pins a value
recomputed from this layout outside the crate.

## Hashes that are deliberately not domain-separated

Two values in a build manifest are plain SHA-256 over raw bytes.

`wasm_hash` is the contract code hash the network computes and the capability registry matches
against. It is not this project's to define, and wrapping it would produce a value that identifies
nothing on chain.

`lockfile_hash` is one file's bytes exactly as they sit on disk, so a reader checks it with
`sha256sum Cargo.lock`. There is no structure whose encoding it could be confused with, and
wrapping it would cost that affordance.

## Reproducing a hash

These steps apply to the canonical `ScVal` hashes only. The account ledger witness follows its
own byte layout above, and `wasm_hash` and `lockfile_hash` are plain SHA-256 over raw bytes.
For the types under "Types that are built as `ScVal` directly", build the value as that section
describes instead of steps 1–2, then wrap and hash it as in steps 3–4.

1. Take the structure's JSON as this toolkit emits it.
2. Map it to an `ScVal` by the table above, using the serialized field names.
3. Wrap it: `Vec [ U32(2), String(domain), value ]`.
4. Encode that as XDR and take its SHA-256.

The worked example in `crates/domain/src/canonical.rs`
(`the_preimage_is_the_structure_the_rules_describe`) builds the expected `ScVal` by hand from
these rules, compares the encoder against it, and then pins the resulting bytes — so the
specification and the implementation cannot drift apart without a test failing.
