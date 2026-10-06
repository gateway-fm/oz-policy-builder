#!/usr/bin/env bash
# Launch the MCP server with the development registry trust configured, for an editor or agent
# session started in this repository (see `.mcp.json`).
#
# `synthesize_policy` refuses to run until OZPB_REGISTRY_ROOTS_JSON and OZPB_REGISTRY_MIN_VERSION
# are set, and that refusal is deliberate: the server verifies a request's registry snapshot
# against roots the *operator* configured, so a request cannot bring its own trust root. This
# wrapper supplies the committed development roots — suitable for a local session and for the
# demo, and not a production trust configuration.
#
# The roots are read from the committed file rather than pasted into `.mcp.json`, so there is one
# copy to keep correct instead of two.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${CLAUDE_PLUGIN_DATA:-$HERE}/target}"
BIN="$CARGO_TARGET_DIR/release/ozpb-mcp-server"
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ] || [ ! -x "$BIN" ]; then
    # Cargo refreshes a plugin binary after source updates; the plugin manifest
    # puts its target dir in persistent plugin data. A project checkout with an
    # existing binary keeps the fast path. Stdout belongs to MCP alone.
    cargo build --locked --release -p ozpb-mcp-server --manifest-path "$HERE/Cargo.toml" >&2
fi
export OZPB_REGISTRY_ROOTS_JSON="$(cat "$HERE/docs/examples/registry-roots.json")"
export OZPB_REGISTRY_MIN_VERSION="${OZPB_REGISTRY_MIN_VERSION:-1}"
# The snapshot a request may omit, so an agent holding a recording can synthesize without
# transcribing a signed document. Verified against the roots above either way.
export OZPB_REGISTRY_SNAPSHOT_JSON="$(cat "$HERE/docs/examples/registry.signed.json")"
exec "$BIN" "$@"
