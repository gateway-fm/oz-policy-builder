#!/usr/bin/env bash
# License & supply-chain gate (architecture §4.11 engineering gate).
#
# Enforces the RFP's "open source, permissive license" requirement across the ENTIRE
# dependency tree — our own crates (Apache-2.0 OR MIT) plus every transitive dependency — for
# the toolkit, on-chain contracts and native execution workspaces. Also verifies crates
# come only from allowed sources and flags known security advisories. Config: deny.toml.
#
# licenses/bans/sources are deterministic and offline. The advisory check needs the RustSec
# database (network), and this release/CI gate fails closed when that database cannot be checked.
# Use `scripts/verify-phase1.sh --offline` for the explicitly reduced, network-free gate.
set -euo pipefail
cd "$(dirname "$0")/.."

# Check the expiry and reviewed dependency inventory before any advisory can be ignored.
python3 scripts/check-advisory-exception.py

# Pinned: advisory-database handling and lint defaults are part of this gate's meaning, so a
# different version can legitimately produce a different verdict. CI installs exactly this one.
EXPECTED_DENY_VERSION="0.20.2"
if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "cargo-deny not installed:"
    echo "  cargo install cargo-deny --locked --version ${EXPECTED_DENY_VERSION}"
    exit 1
fi
HAVE=$(cargo deny --version 2>/dev/null | awk '{print $2}')
if [ "$HAVE" != "$EXPECTED_DENY_VERSION" ]; then
    echo "  note: cargo-deny ${HAVE} (CI pins ${EXPECTED_DENY_VERSION}); verdicts may differ"
fi

echo "== toolkit workspace: licenses · bans · sources =="
cargo deny --locked check licenses bans sources

echo "== contracts workspace (on-chain deliverables): licenses · bans · sources =="
# One shared config over two very different dependency graphs, so each run reports entries the
# OTHER one needs as "not encountered". Silenced per side rather than globally, because the day an
# entry is unused by BOTH trees that warning is the only thing that says so — and it is still
# emitted by the side that owns the entry.
#
# Here: every allowed licence and the `webpki-roots` exception belong to the toolkit tree, so this
# run has nothing to say about them. A rejected licence or a disallowed source still fails.
cargo deny --locked --manifest-path contracts/Cargo.toml --config deny.toml check licenses bans sources \
    -A license-not-encountered -A license-exception-not-encountered

echo "== native execution workspace: licenses · bans · sources =="
cargo deny --locked --manifest-path execution-runtime/Cargo.toml --config deny.toml check licenses bans sources \
    -A license-not-encountered -A license-exception-not-encountered

echo "== security advisories (RustSec; all workspaces; fail closed) =="
# Runs over all workspaces — contracts and native execution have separate
# Soroban SDK dependency graphs. A missing/unreachable database is not evidence that the dependency
# tree is safe, so cargo-deny's non-zero verdict is propagated unchanged.
# The shared ignores belong to the Soroban trees (the temporary crypto-bigint exception
# and an unmaintained build-time macro crate), so this run cannot match them. This is
# the shared-config artefact above, silenced on the side that does not own it. The contracts run below keeps the warning,
# which is where a genuinely stale ignore would surface.
cargo deny --locked check advisories -A advisory-not-detected
cargo deny --locked --manifest-path contracts/Cargo.toml --config deny.toml check advisories
cargo deny --locked --manifest-path execution-runtime/Cargo.toml --config deny.toml check advisories -A advisory-not-detected

echo "LICENSE & SUPPLY-CHAIN GATE PASSED"
