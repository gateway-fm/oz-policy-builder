# Developer guide

How to use the toolkit, how the synthesizer decides scope, and how to extend it with a new
policy primitive. (Design rationale lives in `architecture.md`; this is the working guide.)

> **Scope markers.** The toolkit is delivered in milestones and this guide names all of them.
> Anything a later milestone contracts is marked **Tranche 2**, in the same terms as the
> per-component banners in `architecture.md`; anything unmarked is Tranche 1 and is shipped
> here. A marker means "not part of what a Tranche 1 delivery is reviewed against, and not
> claimed as working": marked operations are named so the shape of the whole flow is visible,
> and are described rather than demonstrated.

## 0. One-time setup for a new clone

```sh
git config core.hooksPath .githooks
```

That points git at `.githooks/pre-push`, which runs two checks before anything leaves the
machine. Git does not track `.git/hooks` and cloning does not carry hooks, which is why the hook
lives in a tracked directory and is pointed at rather than installed.

It matters here more than the one command suggests. The gate's strong check compares this
tracked tree against the private root that sits beside the checkout — by filename and by
content hash, so a confidential document is caught whatever it is renamed to — and that root
exists on a working machine and nowhere else. CI checks out one repository, `..` is empty
there, and it says so rather than reporting a pass it did not earn; what CI can still do is
match the shapes confidential material takes, which is its half of the check and the backstop
for anything pushed with `--no-verify`.

The second check applies only to a push at the publication repository, and only there. Changes
are authored here, in the repository that carries the later-milestone code and tests, and then
carried across with `git cherry-pick -x`, which records where each one came from. A commit
written straight into the extracted tree skips the only place that can tell you it broke a
later milestone, and afterwards nothing says it happened — so the hook asks every commit in the
push to declare itself: carried across, or `Public-only: <why>` in the message for the cases
that genuinely cannot live here, such as a document naming a file the other tree does not have.

## 1. Using the toolkit

Two shells over one library (`crates/toolkit`): a CLI (`ozpb`) and an MCP server
(`ozpb-mcp-server`). Both expose the same operations. The pipeline the first milestone
contracts is:

```
record → synthesize → generate
```

with `evaluate` available at any point to ask the independent reference evaluator what a spec
does with a given invocation. The later stages of the full flow — `dry_run` (prove), `verify`
(reproduce), the authority-surface check, and `prepare_install_intent` — are **Tranche 2**:
the dry-run harness, the call-surface check and the install intent are second-milestone
deliverables, described in `architecture.md` §4.5–4.8. No command for them appears below,
deliberately: an example that looks runnable and is not misleads worse than a sentence saying
the stage is not part of this milestone.
`evaluate_spec` stays available throughout as an optional pure check of the generated
scope, and it returns `indeterminate` when an attached reviewed policy would make a
whole-composition verdict unsafe to state.

### CLI

```bash
cargo build -p ozpb-cli          # produces target/debug/ozpb

# 0. the development registry trust files the pipeline reads (derived from `registry::dev`,
#    so they cannot drift from the code the way committed copies would)
ozpb dev-registry --out docs/examples

# 1. record an executed transaction (by hash, via any Soroban RPC) → RecordingBundle JSON
ozpb record --tx-hash <hash> --rpc-url https://rpc.testnet.stellar.gateway.fm \
  --network "Test SDF Network ; September 2015" > rec.json
# …or record what an *unsigned* envelope would need authorized — `simulateTransaction` in
# record mode, so no signature and no custody of anything:
ozpb simulate --envelope-xdr <base64-envelope> \
  --rpc-url https://rpc.testnet.stellar.gateway.fm \
  --network "Test SDF Network ; September 2015" > rec.json
# …or offline from a raw evidence bundle:
ozpb import --bundle docs/examples/import-bundle.json > rec.json

# 2. synthesize a minimum-permission PolicySpec (needs your decisions: who/how-long/…)
export OZPB_REGISTRY_MIN_VERSION=<persisted-anti-rollback-floor>
ozpb synthesize --bundle rec.json --selected-authorizer <C…> \
  --account account.json --signed-registry docs/examples/registry.signed.json \
  --registry-roots docs/examples/registry-roots.json \
  --decisions docs/examples/decisions.json \
  --template-family policy-templates/scope@1 > synthesis.json

# `synthesize` prints an envelope — the spec, its canonical hash, and the per-constraint
# rationale — while the stages below take a bare PolicySpec. Handing over the envelope is a
# parse error rather than something quietly ignored, because every schema type here is
# `deny_unknown_fields`, so lift the spec out:
python3 scripts/demo/extract_spec.py synthesis.json spec.json

# 3. ask the reference evaluator what the spec does with an invocation (pure, no network)
ozpb evaluate --spec spec.json --context docs/examples/eval-context.json \
  --invocation docs/examples/invocation-permit.json

# 4. generate the locked crate, build Wasm, and emit its binding BuildManifest (never deploys)
ozpb generate --spec spec.json --rule 0 --out ./generated
```

### Build configuration (operator-side)

`generate` compiles the policy, and takes the flags below (each with an env fallback the MCP
server reads too). The Tranche-2 operations that also compile — `verify` and the
call-surface check — are specified to take the same four, so this is the configuration surface
for compilation generally, not for one subcommand:

| Flag | Env | Default |
|---|---|---|
| `--build-timeout-secs` | `OZPB_BUILD_TIMEOUT_SECS` | 600 |
| `--build-cache-dir` | `OZPB_BUILD_CACHE_DIR` | a shared dir under the system temp dir |
| `--build-jobs` | `OZPB_BUILD_JOBS` | available parallelism − 1 |
| `--stellar-binary` | `OZPB_STELLAR_BINARY` | `stellar` on `PATH` |

**Point the cache dir at persistent storage.** With a cold cache every build recompiles
`soroban-sdk` and `stellar-accounts` from scratch, which is what the timeout is mostly
spent on. Two properties of a shared cache to plan for: it is **not pruned** (cargo does not
GC target directories, so distinct specs accumulate — give the volume a quota and clear it on
a schedule), and it **serializes concurrent builds** on cargo's build-directory lock, so a
hosted worker should size its concurrency to one build at a time per cache. The default path
is per-uid and is refused if it is a symlink, not a directory, owned by another user, or
group/world-accessible — a shared cache an attacker can pre-create is a route to poisoned
dependency artifacts, and `verify` reproduces through the same cache, so a poisoned build
would reproduce identically.

These are deliberately *not* request fields: a caller-chosen timeout is resource exhaustion
and a caller-chosen builder path is arbitrary execution, so they stay operator configuration
(the same reasoning as the RPC allowlist). There is likewise no flag for the
builder kind — the hermetic stub emits unattestable wasm and is test-only. An unusable
binary or cache fails with `EBuildUnavailable`, distinct from `EBuildFailed`, so an operator
fault never reads to an agent as "your spec does not compile".

`registry-roots.json` is out-of-band trust configuration, not request data:
`{"threshold":2,"keys":{"ops-a":"<32-byte-hex>","ops-b":"<32-byte-hex>"}}`.
It may also contain a durable `checkpoint` (`version`, `log_index`, `root`) to reject
same-version equivocation after restart. The MCP server receives the same JSON through
`OZPB_REGISTRY_ROOTS_JSON`, paired with `OZPB_REGISTRY_MIN_VERSION`.

`docs/examples/` holds runnable inputs for the commands above, and
`crates/toolkit/tests/examples_are_current.rs` fails if any of them drifts from what the code
produces — so an example that no longer works is a red test, not a puzzled reader.
`bash scripts/verify-phase1.sh` is the strict first-milestone release gate;
`bash scripts/verify-phase1.sh --offline` is the explicitly reduced local gate.

### Demonstrating the Tranche-1 outcome

```bash
bash scripts/demo-tranche1.sh          # ~2 min, live testnet, throwaway identities
OZPB_ACCOUNT=C... bash scripts/demo-tranche1.sh   # reuse an existing OZ smart account
```

Deploys OpenZeppelin's smart-account example, records what authorization a transfer from it
would require, synthesizes a minimum-permission spec, generates the policy crate, and has the
real `stellar contract build` accept it — the contractual outcome — then checks that source and
wasm are byte-identical across two runs. The script derives its policy expiry from the latest
testnet ledger and also exercises a deliberately incompatible account-hash input, which must be
refused by registry resolution. Account recognition is generation compatibility, not a claim
that installation on the live account is safe.

Three things it makes explicit, because each one broke a demo attempt:

- It records a **simulated** transfer. `simulateTransaction` with `authMode: record` returns the
  authorizations an invocation *would* need, so recording requires no signature and no custody.
  The executed path is the same code with `record --tx-hash`, and additionally needs the smart
  account's signer.
- **A transaction hash cannot be replayed later** — RPC retention drops it — so the script
  creates fresh state every run rather than referencing a hash from a document.
- **The authorizer must be a smart account.** A policy scopes a smart account's context rule, so
  synthesis fails closed on an ordinary `G` account. The script also asserts the deployed
  account's on-chain code hash equals the pinned one, which doubles as a live check of the pin.

### Verifying the pinned upstream trust anchors

`ozpb_domain::pinned_upstream` holds the wasm hashes of three OpenZeppelin contracts — the
spending-limit policy, the smart account, and the ed25519 verifier. The first two are Phase 1
trust anchors. The verifier pin is retained for later work, but external-verifier signers are
rejected in Phase 1 because a supplied verifier address is not yet bound to its observed Wasm.

```bash
bash scripts/verify-pinned-upstream.sh    # clones the pinned tag, rebuilds, compares
```

Deliberately not part of `verify-phase1/2`: it clones and does a cold build of upstream's
workspace, which takes minutes. Run it when the pins change, when bumping the upstream tag, or
when reviewing the trust anchors.

Two things to know. **The hash depends on the compiler** — upstream's `rust-toolchain.toml`
says `channel = "stable"`, which floats, so the script forces this repository's pinned rustc;
building with another one legitimately yields a different hash from identical source.
**Upstream publishes no wasm** — releases carry no assets and no deployed instance is blessed,
so these are our reproducible builds of their source, and the registry entries say exactly
that rather than claiming an upstream-signed artifact.

### MCP server

`docs/MCP-WALKTHROUGH.md` is how to use this server: build it once and Claude Code picks it
up from `.mcp.json` — a stdio server is spawned by the client per session, so there is nothing
to start or connect to. That page also covers what each tool needs, the two answers that look
like bugs and are not, and, in an appendix, the raw JSON-RPC for when you want the wire.

```bash
cargo build -r -p ozpb-mcp-server
# stdio (Claude Code, default) — see .mcp.json; the agent skill it pairs with is Tranche 2
target/release/ozpb-mcp-server
# streamable HTTP (self-hostable endpoint)
target/release/ozpb-mcp-server --http 127.0.0.1:8080   # → /v1/mcp
```

The tools, each with a JSON output schema generated from `crates/api-types`:

- **Tranche 1** — `record_transaction`, `record_simulation`, `import_recording`,
  `synthesize_policy`, `evaluate_spec`, `generate_code`.
- **Tranche 2** — `dry_run`, `verify`, `check_against_policy`,
  `check_policy_call_surface`, `prepare_install_intent`. The dry-run harness, the
  reproduce-and-verify surface, the authority-surface check and the install intent are
  second-milestone deliverables, so a Tranche 1 delivery is not reviewed against these.

`crates/mcp-server/tests/mcp_stdio.rs` asserts the served set against the Tranche-1 names
above, so the list is checked rather than merely written down. Errors carry stable
machine-readable codes (`E_*`). The server never deploys, signs, or holds keys.

`--http` mode is **localhost-only** and refuses to start unless `OZPB_HTTP_BEARER_TOKEN`
(≥32 bytes) and `OZPB_RPC_ALLOWLIST` are set; it applies bearer auth, a request-size bound,
and a global rate limit. The allowlist is a comma-separated list of the full `https://` URLs
the record tools may reach: each entry is parsed as a URL, so a bare hostname is refused at
startup rather than at first use. Terminate TLS
and add per-client authorization at a reverse proxy in front of it. OS-level compile
isolation, a no-secrets worker role, and per-tool quotas are still owed before genuine
multi-tenant public hosting.

## 2. How the synthesizer decides scope

`crates/synthesizer` is a pure function `RecordingBundle(s) + UserDecisions → PolicySpec`.
Its rules (all fail-closed — ambiguity is an error, never a guess):

- **Exact-by-default.** Every observed argument becomes a *deep exact-equality* constraint
  on the complete tuple (exact arg count; nested `ScVal` validated). This is the true
  minimum permission.
- **`SELF` resolution.** An observed address equal to the selected authorizer becomes the
  `SELF` marker (resolved at runtime), so generated wasm is account-independent.
- **Widening is never heuristic.** A bound (`<=`, `>=`) or a wildcard (`any_value`) enters
  a spec *only* through an explicit `Widening` decision carrying intent + blast radius, or
  an adapter (`crates/synthesizer/src/adapters.rs`) bound to a verified target code hash.
  The XDR type alone never implies a direction (lowering a `min_output` makes a swap
  *less* safe).
- **Signers are a required decision.** The delegate signer set + predicate can't be
  inferred from a recording; named-identity predicates are strict (a later `add_signer`
  can't silently broaden the grant).
- **Compose-first.** Where an audited OZ prebuilt (`spending_limit`, thresholds) expresses
  the constraint, it is configured rather than generated; the generated policy carries only
  what no prebuilt expresses (function/argument scope, call count, recipient/path).
- **Sequences → permission bundles, not workflows.** Multiple recorded contracts yield
  independent rules (one per contract); ordering/atomicity are not enforced and the spec
  says so.

The `PolicySpec` is validated into a `ValidatedSpec` typestate (`crates/policy-spec`); only
that typestate reaches codegen and the evaluator.

## 3. Extending the toolkit with a new policy primitive

Say you want a new constraint — e.g. a `MemoEquals` check. Touch these, in order, and let
the tests guide you (TDD: add the failing test first):

1. **`crates/policy-spec`** — add the `Constraint` variant. Update `is_widening()` if it's a
   relaxation, and add validation if it has provenance rules. Add it to a fixture.
2. **`crates/evaluator`** — handle the variant in `constraint_satisfied` (the independent
   reference semantics). This is the executable spec.
3. **`crates/codegen`** — emit the check in `emit_lib`'s per-arg match, embedding values as
   validated literals (never interpolated into identifiers); add pre-emission validation in
   `generate`. Regenerate goldens with `UPDATE_GOLDEN=1 cargo test -p ozpb-codegen golden`.
4. **`crates/synthesizer`** — decide how it enters a spec (observed-exact by default, or via
   a `Widening`/adapter). Never let it in heuristically.
5. **`contracts/`** — the Tranche 1 differential suite drives the generated policy contract
   directly in the Soroban environment and asserts that the reference evaluator and the
   compiled policy agree on verdict *and* deny code. Add the permit case and the adjacent
   denial for the new constraint there; agreement is what makes step 2's semantics binding
   rather than merely written down. Full `stellar-accounts::__check_auth` integration
   belongs to Tranche 2.

Adding a new *template family* or reviewed prebuilt hash also means a
`crates/registry` capability entry (keyed by reviewed wasm hash) so validation can prove
what it enforces — an address or claimed kind is never sufficient.

### Invariants CI enforces (don't break these)

- `scripts/check-dep-rules.sh`: the evaluator never depends on codegen (differential
  independence); cores stay transport/async-free.
- Every generated crate builds standalone (`[profile.release]` with `overflow-checks`) and
  passes the same `rustfmt`/`clippy -D warnings` as handwritten code.
- Determinism: same `ValidatedSpec` ⇒ byte-identical source/wasm.
- `scripts/check-publication-allowlist.sh`: no confidential material in the public tree.
