# Driving the MCP server by hand

The toolkit has two shells over one core: a CLI (`ozpb`) and an MCP server
(`ozpb-mcp-server`). `docs/DEVELOPERS.md` covers the CLI and
`scripts/demo-tranche1.sh` runs the whole pipeline against testnet. This walks the **MCP**
shell instead, by hand, so you can see what an agent sees and show it to someone.

Nothing here touches the network or holds a key. Every command below was run to write this
page, and the outputs are copied from that run rather than described.

---

## 1. Build it

```bash
cargo build -r -p ozpb-mcp-server
```

One binary, `target/release/ozpb-mcp-server`. Stdio is the default transport — one process
inside your own trust domain, which is how Claude Code runs it, and what the rest of this
page uses.

There is also `--http <addr>`, serving the same handler at `/v1/mcp`, but it will not start
bare:

```console
$ ./target/release/ozpb-mcp-server --http 127.0.0.1:8080
Error: OZPB_HTTP_BEARER_TOKEN is required for HTTP mode
```

That refusal is the feature. HTTP mode also requires `OZPB_RPC_ALLOWLIST`, binds localhost
only, and applies bearer auth, a request-size bound and a rate limit — see
`docs/DEVELOPERS.md` for the full set and for what is still owed before anything like
multi-tenant hosting. For a demo, stay on stdio.

## 2. Talk to it

The server speaks newline-delimited JSON-RPC on stdin/stdout. It exits when stdin closes,
so a whole session is one pipe: write the requests, read the responses.

Every session starts with the same two lines — an `initialize` request and an
`initialized` notification. Skip them and tool calls are refused, which is the protocol
working as intended rather than a bug in the server.

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

`tools/list` is the answer to "what does this milestone expose" — ask the server rather
than trusting a list in a document, including this one. Each entry carries an
`outputSchema` as well as an input schema, so an agent knows the shape of what it will get
back and not only what to send.

## 3. Call a tool that needs nothing

`evaluate_spec` is the one to demo first: pure, offline, and it answers the question the
whole project is about — *would this policy allow this call?* The committed examples under
`docs/examples/` are its three inputs, and they are the same bytes a reader can inspect.

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

The interesting part of the response, from the run that produced this page:

```json
{"verdict": "indeterminate", "deny_reason": "ReviewedPoliciesUnmodeled"}
```

**That is the correct answer, and it is worth dwelling on.** The invocation matches the
generated scope policy, so a naive evaluator would say `permit`. But the spec also composes
OpenZeppelin's reviewed spending-limit policy, whose rolling state this evaluator does not
model — so a whole-spec `permit` would be a claim it cannot support. It returns
`indeterminate` instead. An evaluator that answered `permit` here would be more useful and
less honest.

Swap `invocation-permit.json` for `invocation-deny.json` — same spec, a recipient the
allowed tuple does not name — and the verdict is definite:

```json
{"verdict": "deny", "deny_reason": "NoTupleMatched"}
```

## 4. See what a failure looks like

Worth demoing deliberately, because agents recover from errors and the shape is the
contract. Send a spec that is not one — the handshake first, as always, since a bare
`tools/call` is refused:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"evaluate_spec","arguments":{"spec":{"schema":"nope"},"context":{},"invocation":{}}}}' \
| ./target/release/ozpb-mcp-server 2>/dev/null | tail -1
```

```json
{"isError": true, "structuredContent": {"code": "E_SPEC_INVALID",
 "message": "malformed input JSON: missing field `name`"}}
```

Two things to point at. It is a **tool result** with `isError: true`, not a JSON-RPC
protocol error — so a model can read it, correct itself and retry, which it cannot do with
a transport-level failure. And the `code` is stable and documented; the prose after it is
for humans and may change.

## 5. The tools that do need something

- **`record_transaction`** takes a testnet/mainnet transaction hash and an RPC URL, and
  returns the authorization evidence. It needs the network, and the hash must still be
  within RPC retention — a few days.
- **`record_simulation`** takes an unsigned transaction envelope instead, so it needs no
  signature and no custody. This is the path `scripts/demo-tranche1.sh` uses.
- **`import_recording`** takes a recording someone else produced. Anything arriving this way
  is labelled `self_supplied`, because a `trust` field in caller JSON is a claim and not a
  receipt.
- **`synthesize_policy`** turns a recording plus your decisions into a PolicySpec. It needs
  the signed registry snapshot and its root keys — `docs/examples/registry.signed.json` and
  `registry-roots.json` are the committed pair, and the same bytes the demo feeds it.
- **`generate_code`** turns a PolicySpec into a compilable crate. It shells out to the
  pinned `stellar contract build`, so it needs that installed and a warm dependency cache;
  the first call is slow.

The easiest way to see these in sequence is `bash scripts/demo-tranche1.sh`, which drives
the same operations through the CLI and keeps every input and output as a file. This page is
about the MCP surface; that script is about the pipeline.

## 6. From Claude Code instead

`.mcp.json` in the repository root already points at the release binary, so once it is
built the tools appear in a Claude Code session started in this directory. That is the
demo worth showing to someone who asks *why* an MCP server: you ask in words, and the
agent composes the same calls you just made by hand — while still holding no key and
deploying nothing.

The agent skill that pairs with it, with its clarification questions and
confirm-before-deploy flow, is a later milestone. Without it, an agent driving these tools
is capable and unguided; that gap is the reason the skill exists.

---

## What this does not show

No policy is installed and nothing is signed, here or anywhere in this milestone. The
permit/deny dry-run report, the wallet install flow and the hosted endpoint are the next
tranche's deliverables. `evaluate_spec` is the reference evaluator answering about a spec —
not a smart account executing a policy, which is a different and stronger claim that
belongs with the harness.
