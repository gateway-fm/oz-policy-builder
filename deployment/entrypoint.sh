#!/bin/sh
set -eu
umask 077
mkdir -p "$CARGO_HOME" "$OZPB_BUILD_CACHE_DIR" "$TMPDIR"
cp /opt/ozpb/cargo-config.toml "$CARGO_HOME/config.toml"
if [ "${1:-serve}" != serve ]; then
    exec "$@"
fi
if [ "$#" -gt 1 ]; then
    echo 'serve takes no arguments' >&2
    exit 1
fi
# File inputs keep credentials out of Compose interpolation, image layers, and argv.
# The current binary requires this environment variable; compiler subprocesses clear it.
token_file=/run/ozpb/bearer-token
if [ ! -f "$token_file" ] || [ "$(wc -c < "$token_file")" -gt 129 ]; then
    echo 'a bounded bearer-token file is required' >&2
    exit 1
fi
OZPB_HTTP_BEARER_TOKEN=$(cat "$token_file")
case "$OZPB_HTTP_BEARER_TOKEN" in
    *[!A-Za-z0-9._~-]*|'') echo 'bearer-token must contain 32 to 128 URL-safe characters' >&2; exit 1 ;;
esac
if [ "${#OZPB_HTTP_BEARER_TOKEN}" -lt 32 ] || [ "${#OZPB_HTTP_BEARER_TOKEN}" -gt 128 ]; then
    echo 'bearer-token must contain 32 to 128 URL-safe characters' >&2
    exit 1
fi
export OZPB_HTTP_BEARER_TOKEN
OZPB_REGISTRY_ROOTS_JSON=$(cat /run/ozpb/registry-roots.json)
OZPB_REGISTRY_SNAPSHOT_JSON=$(cat /run/ozpb/registry.signed.json)
OZPB_RPC_SOURCES_JSON=$(cat /run/ozpb/rpc-sources.json)
export OZPB_REGISTRY_ROOTS_JSON OZPB_REGISTRY_SNAPSHOT_JSON OZPB_RPC_SOURCES_JSON
exec /usr/local/bin/ozpb-mcp-server --http 127.0.0.1:8080
