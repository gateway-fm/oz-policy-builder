# Canonical hashing

Every hash this toolkit publishes is taken over an `ScVal` encoded as XDR. This document is the
specification an independent implementation follows to reproduce one.

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
| `ozpb:v1:account-state` | the enumerated account rule-set a verdict was computed over |
| `ozpb:v1:generated-source` | a generated crate's source files, lockfile excluded |
| `ozpb:v1:generated-crate-files` | a generated crate's complete emitted file set |
| `ozpb:v1:surface-verdict` | reserved; the verdict is not hashed yet |

One structure, one domain. A domain used for two structures forfeits exactly the separation the
scheme exists to provide.

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

## Hashes that are deliberately not domain-separated

Two values in a build manifest are plain SHA-256 over raw bytes.

`wasm_hash` is the contract code hash the network computes and the capability registry matches
against. It is not this project's to define, and wrapping it would produce a value that identifies
nothing on chain.

`lockfile_hash` is one file's bytes exactly as they sit on disk, so a reader checks it with
`sha256sum Cargo.lock`. There is no structure whose encoding it could be confused with, and
wrapping it would cost that affordance.

## Reproducing a hash

1. Take the structure's JSON as this toolkit emits it.
2. Map it to an `ScVal` by the table above, using the serialized field names.
3. Wrap it: `Vec [ U32(2), String(domain), value ]`.
4. Encode that as XDR and take its SHA-256.

The worked example in `crates/domain/src/canonical.rs`
(`the_preimage_is_the_structure_the_rules_describe`) builds the expected `ScVal` by hand from
these rules, compares the encoder against it, and then pins the resulting bytes — so the
specification and the implementation cannot drift apart without a test failing.
