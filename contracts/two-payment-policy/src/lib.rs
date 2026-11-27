// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GENERATED POLICY — template family `policy-templates/scope@1`.
//! Normalized codegen input hash:
//! f5c73c5c5705cba01abd7184a81beeee2b230d00c9bceae0d6abf9295cfc7aa5
//!
//! DO NOT EDIT BY HAND: any manual change switches this artifact to CUSTOM
//! SOURCE MODE (architecture §4.4) — spec conformance, differential testing,
//! and generated-mode guarantees no longer apply to an edited copy.
//!
//! Check order is the generated-code contract (§4.4): account authorization and
//! installation state first, then the signer predicate (the OZ account defers
//! signer validation to policies), then strict signer-set, then
//! target/function/tuple scoping, then stateful invariants (missing state
//! denies; the call cap never resets within an installation — only `uninstall`,
//! which the smart account alone can call, clears it). No setters, no upgrade
//! entry point.
//!
//! Storage lifetime is maintained **only while this policy is used**: a
//! permitted call, or `install`, extends the entries it depends on toward the
//! rule's validity window where one is set and the network maximum otherwise —
//! never past either. An installed but idle policy still drifts into archival,
//! and so does one that only ever denies, since a denial reverts the extension
//! along with everything else. First use after a long gap may therefore cost a
//! restore. Once a call cap is spent the policy stops extending entirely: it
//! can never permit again, so it stops paying rent.
//!
//! Those two entry points are the only ones that extend anything. A query
//! through the getters is a pure read: it buys no rent, because these entries
//! belong to the smart account's install/uninstall lifecycle rather than to
//! this contract, and a caller who is not the account has no business paying to
//! keep them alive. So the set of callers who can make this policy cost
//! anything is exactly the set who can use it.
#![no_std]

pub mod contract;

// Provenance, read with `stellar contract info meta`. The spec this was built
// from, its registry snapshot and the toolkit revision are in the
// BuildManifest, not here: they would make one grant shape a different Wasm per
// spec.
soroban_sdk::contractmeta!(key = "ozpb_generator", val = "oz-policy-builder/codegen@1");
soroban_sdk::contractmeta!(key = "ozpb_template_family", val = "policy-templates/scope@1");
soroban_sdk::contractmeta!(
    key = "ozpb_codegen_input",
    val = "f5c73c5c5705cba01abd7184a81beeee2b230d00c9bceae0d6abf9295cfc7aa5"
);
