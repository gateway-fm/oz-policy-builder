# Using the MCP server

The toolkit has two shells over one core: a CLI (`ozpb`) and an MCP server
(`ozpb-mcp-server`). `docs/DEVELOPERS.md` covers the CLI and
`scripts/demo-tranche1.sh` runs the whole pipeline against testnet. This is about the **MCP**
shell: how you actually use it, and — at the back, for when you need it — how to speak to it
directly.

Nothing here holds a key or deploys anything.

---

## 1. Build it, then just use Claude Code

```bash
cargo build -r -p ozpb-mcp-server
```

That is the whole setup. `.mcp.json` in the repository root already points at
`target/release/ozpb-mcp-server`, so a Claude Code session started in this directory has the
tools available.

**You never start the server yourself, and there is no daemon to connect to.** A stdio MCP
server is launched *by the client*, as a child process, once per session, and it exits when
the session ends. That is the design: one process inside your own trust domain, no port, no
listener, nothing left running. If you are looking for something to `curl`, see §4 — and
that is the hosted shape, not the local one.

So the demo is a conversation. Ask for what you want:

> Record what authorization a transfer from `C…` to `G…` would need on testnet, then
> synthesize a minimum-permission policy for it and generate the crate.

The agent composes the tool calls and you watch it work — while it still holds no key and
deploys nothing. That is the point of shipping an MCP server rather than only a CLI: the
person who needs a scoped policy does not have to know the pipeline exists.

### The one command to show it works

If all you want is to demonstrate that the server is live and doing real work, this is
enough — one sentence, no tool names, no file paths:

> Record Stellar testnet transaction `<hash>` for me, using RPC
> `https://rpc.testnet.stellar.gateway.fm`, and tell me what authorization it required.

The agent picks `record_transaction`, and you get back the authorization tree, the observed
code hash of every contract involved, and the evidence trust level. That is the recording
layer — RFP requirement #1 — answering from a hash you can paste from an explorer.

The hash has to be recent: RPC retention drops transactions after a few days, and an expired
one comes back as `E_RETENTION_EXPIRED` rather than a guess. If you have no hash to hand, run
`bash scripts/demo-tranche1.sh` and use the account it prints, or ask for the *simulated*
path instead — "what would a transfer of 1 XLM from `C…` to `G…` require?" — which needs no
hash and no signature.

**Going further than one command is better done with the skill.** The full flow needs
decisions only you can make — how long the grant lives, a call cap, a spend limit, which
signer — and a bare agent asks for those unevenly, or guesses. Systematically asking them is
the skill's job, and the skill is a later milestone (§4.7). Driving the rest by hand is
covered in the appendix; driving it conversationally is worth waiting for.

### Two more things worth trying

Because they are what a reviewer will ask:

- **Ask it what tools it has.** The answer comes from the server, not from this page: the
  served set is what this milestone ships, and a list written here would go stale the moment
  it changes.
- **Give it something impossible** — a spec that is not a spec, a transaction hash that never
  existed. The refusals are the interesting half, and §3 says what shape they take.

## 2. What each tool needs

Only two are pure. Knowing which is which saves a confusing failure.

| Tool | Needs |
|---|---|
| `evaluate_spec` | nothing — pure and offline. The one to try first |
| `import_recording` | nothing, but anything arriving this way is labelled `self_supplied`: a `trust` field in caller JSON is a claim, not a receipt |
| `record_transaction` | the network, and a transaction hash still inside RPC retention — a few days |
| `record_simulation` | the network, but no signature and no custody: it asks what an *unsigned* envelope would require. This is the path the demo script uses |
| `synthesize_policy` | the signed registry snapshot and its root keys. `docs/examples/registry.signed.json` and `docs/examples/registry-roots.json` are the committed pair, and the same bytes the demo feeds it |
| `generate_code` | the pinned `stellar contract build` installed, and a warm dependency cache. The first call is slow |

To see them in sequence without an agent, run `bash scripts/demo-tranche1.sh`: it drives the
same operations through the CLI and keeps every input and output as a file.

## 3. Two answers that look like bugs

Worth knowing before showing this to anyone, because both invite the wrong conclusion.

**`evaluate_spec` answers `indeterminate` on a call that looks like it should pass.**

```json
{"verdict": "indeterminate", "deny_reason": "ReviewedPoliciesUnmodeled"}
```

The invocation matches the generated scope policy, so a naive evaluator would say `permit`.
But the spec also composes OpenZeppelin's reviewed spending-limit policy, whose rolling state
this evaluator does not model — so a whole-spec `permit` would be a claim it cannot support.
An evaluator that answered `permit` there would be more useful and less honest. Deny is still
definite where it can be: a recipient outside the allowed tuple gives
`{"verdict": "deny", "deny_reason": "NoTupleMatched"}`.

**A bad input comes back as a result, not as a crash.**

```json
{"isError": true, "structuredContent": {"code": "E_SPEC_INVALID",
 "message": "malformed input JSON: missing field `name`"}}
```

`isError: true` on a *tool result*, not a JSON-RPC protocol error — so a model can read it,
fix its arguments and retry, which it cannot do with a transport-level failure. The `code` is
stable; the prose after it is for humans and may change.

## 4. If you want a listener instead

`--http <addr>` serves the same handler at `/v1/mcp`. It will not start bare:

```console
$ ./target/release/ozpb-mcp-server --http 127.0.0.1:8080
Error: OZPB_HTTP_BEARER_TOKEN is required for HTTP mode
```

That refusal is the feature. HTTP mode also requires `OZPB_RPC_ALLOWLIST`, binds localhost
only, and applies bearer auth, a request-size bound and a rate limit. `docs/DEVELOPERS.md`
has the full set, and what is still owed before anything resembling multi-tenant hosting.
This is the shape a hosted deployment would take; it is not what this milestone deploys, and
it is not how to run it locally.

---

## Appendix: speaking to it directly

You do not need this to use the toolkit. It is here for two cases: seeing the actual wire
format, and debugging the server without a client in the way.

The server speaks newline-delimited JSON-RPC on stdin/stdout and exits when stdin closes, so
a whole session is one pipe. Every session opens with the same two lines — an `initialize`
request and an `initialized` notification. Skip them and tool calls are refused, which is the
protocol working rather than a bug.

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
| ./target/release/ozpb-mcp-server 2>/dev/null \
| python3 -c 'import sys,json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]'
```

(`json.tool --json-lines` would be shorter, but that flag only exists in recent Python 3.x
and this page is meant to be pasted, not adapted.)

A real tool call, using the committed examples as its three inputs:

```bash
python3 - > /tmp/mcp-session.jsonl <<'EOF'
import json
def line(o): print(json.dumps(o))
line({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",
      "capabilities":{},"clientInfo":{"name":"manual","version":"0"}}})
line({"jsonrpc":"2.0","method":"notifications/initialized"})
line({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"evaluate_spec","arguments":{
    "spec":       json.load(open("docs/examples/subscription-spec.json")),
    "context":    json.load(open("docs/examples/eval-context.json")),
    "invocation": json.load(open("docs/examples/invocation-permit.json"))}}})
EOF

./target/release/ozpb-mcp-server < /tmp/mcp-session.jsonl 2>/dev/null
```

That returns the `indeterminate` verdict from §3. Swap `invocation-permit.json` for
`invocation-deny.json` to get the definite one, and send a spec that is not one to see the
error shape — handshake included, since a bare `tools/call` is refused:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"evaluate_spec","arguments":{"spec":{"schema":"nope"},"context":{},"invocation":{}}}}' \
| ./target/release/ozpb-mcp-server 2>/dev/null | tail -1
```

Every command on this page was run to write it, and the outputs are pasted from those runs.

---

## What this does not show

No policy is installed and nothing is signed, here or anywhere in this milestone. The
permit/deny dry-run report, the wallet install flow and the hosted endpoint are the next
tranche's deliverables. `evaluate_spec` is the reference evaluator answering about a spec —
not a smart account executing a policy, which is a different and stronger claim that belongs
with the harness.

The agent skill that pairs with this server — its clarification questions, its
confirm-before-deploy flow — is also a later milestone. Without it, an agent driving these
tools is capable and unguided; that gap is the reason the skill exists.
