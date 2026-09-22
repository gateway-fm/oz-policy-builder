#!/usr/bin/env bash
# Synthesize a PolicySpec through the MCP server, over stdio, and check the result against the
# spec the CLI produced for the same run.
#
# The point is not that a policy comes out — `demo-tranche1.sh` already shows that. The point is
# that the MCP surface and the CLI reach the *same* spec hash, so "also available over MCP" is a
# second door onto one implementation rather than a second implementation. `MCP-WALKTHROUGH.md`
# §3 makes that claim and asks the reader to compare the two hashes by hand; this is the same
# comparison in one command, against a run of their own.
#
#   usage: bash scripts/demo/mcp-synthesize.sh [demo-runs/<timestamp>]
#
# With no argument it takes the most recent run. Needs `cargo build -r -p ozpb-mcp-server` first.
set -euo pipefail

RUN="${1:-$(ls -1dt demo-runs/*/ 2>/dev/null | head -1)}"
[ -n "$RUN" ] && [ -d "$RUN" ] || { echo "no demo run found — run scripts/demo-tranche1.sh first" >&2; exit 2; }
RUN="${RUN%/}"
[ -x target/release/ozpb-mcp-server ] || { echo "build it first: cargo build -r -p ozpb-mcp-server" >&2; exit 2; }

for f in 03-recording.json 04-decisions.json 04-synthesis.json; do
    [ -f "$RUN/$f" ] || { echo "$RUN is missing $f — is it a completed run?" >&2; exit 2; }
done

SESSION="$(mktemp)"; trap 'rm -f "$SESSION" "$SESSION.out"' EXIT

# The documented three-argument request, and what is absent from it is the point: the account, its
# code hash, the authorizer and the template family are derived from the recording, and the
# registry snapshot comes from what the server was started with. `03-recording.json` is the
# envelope the CLI writes around the bundle, which is also what `record_simulation` hands back
# over MCP, hence the unwrap.
python3 - "$RUN" > "$SESSION" <<'PY'
import json, sys
run = sys.argv[1]
load = lambda p: json.load(open(p))
for line in (
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "demo", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "synthesize_policy", "arguments": {
            "bundles": [load(f"{run}/03-recording.json")["bundle"]],
            "decisions": load(f"{run}/04-decisions.json"),
            # Opt-in rather than a default: composing OpenZeppelin's reviewed spending-limit
            # policy into a grant is a decision too. `"pinned"` selects it without transcribing
            # its hash; omit it and a decisions file that asks for a limit gets
            # E_UNREGISTERED_POLICY rather than a policy with the limit quietly dropped.
            "spending_limit_capability": "pinned"}}},
):
    print(json.dumps(line))
PY

echo "== synthesizing through the MCP server (stdio) =="
echo "   run: $RUN"

# The wrapper, not the binary: it supplies the committed development registry trust, which is
# what `.mcp.json` starts and what the walkthrough tells a reader to run. Calling the binary
# directly here would mean this script configured trust its own way and demonstrated a
# deployment nobody else has.
scripts/mcp-server-dev.sh < "$SESSION" 2>/dev/null | tail -1 > "$SESSION.out"

python3 - "$RUN" "$SESSION.out" <<'PY'
import json, sys
run, out = sys.argv[1], sys.argv[2]
result = json.load(open(out)).get("result", {})
payload = result.get("structuredContent", {})
if result.get("isError"):
    print("  MCP returned an error:")
    for line in payload.get("details", [payload.get("message", "?")]):
        print(f"    {line}")
    sys.exit(1)
mcp = payload["spec_hash"]
cli = json.load(open(f"{run}/04-synthesis.json"))["spec_hash"]
for line in payload.get("rationale", []):
    print(f"  rationale : {line}")
print(f"  MCP spec hash : {mcp}")
print(f"  CLI spec hash : {cli}")
if mcp != cli:
    print("  MISMATCH — the two surfaces disagree, which is a defect, not a demo")
    sys.exit(1)
print("  identical — one implementation, two surfaces")
PY
