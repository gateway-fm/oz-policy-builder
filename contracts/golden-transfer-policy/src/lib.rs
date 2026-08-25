// SPDX-License-Identifier: Apache-2.0 OR MIT
//! GENERATED POLICY — template family `policy-templates/scope@1`.
//! Normalized codegen input hash:
//! 662ad7a94de0d249461d9e8b2c6525a95ab64f4e46f5ca0abf78479cf6181260
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
//! permitted call, `install`, and a successful read through `is_installed` or
//! `remaining_calls` each extend the entries the policy depends on toward the
//! rule's validity window where one is set and the network maximum otherwise —
//! never past either. Every one of them goes through the same `ttl_target`
//! computation, so no entry point can buy rent that another could not. A policy
//! nothing calls at all still drifts into archival, and so does one that only
//! ever denies, since a denial reverts the extension along with everything
//! else. First use after a long gap may therefore cost a restore. Once a call
//! cap is spent the policy stops extending entirely: it can never permit again,
//! so it stops paying rent.
//!
//! The reads are unauthenticated, and bounded by the same thing the writes are:
//! `ttl_target` clamps every extension to VALID_UNTIL_LEDGER, past which every
//! entry point denies. A third party can pay to keep this policy out of
//! archival, and only for as long as it can still permit something.
#![no_std]

pub mod contract;
