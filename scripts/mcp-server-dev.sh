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
export OZPB_REGISTRY_ROOTS_JSON="$(cat "$HERE/docs/examples/registry-roots.json")"
export OZPB_REGISTRY_MIN_VERSION="${OZPB_REGISTRY_MIN_VERSION:-1}"
exec "$HERE/target/release/ozpb-mcp-server" "$@"
