# Static-analysis triage

This file covers the 39 static-analysis (SAST) and leaked-secret items that Aikido reported open
for this repository on 2026-11-19. Each one was checked against the code that uses the flagged
value. An item counts as real when that value can come from untrusted input: a request to the
wallet backend, an agent proposal, an RPC response, or a recording, bundle or spec file someone
imports. An item counts as not exploitable when the value is a constant, or configuration the
operator chose for their own machine.

| Disposition | Items |
| --- | ---: |
| Fixed in this tree | 4 |
| Not exploitable | 34 |
| False positive | 1 |

Aikido rated none of them critical, 4 high, 15 medium and 20 low. All 19 high and medium items are
not exploitable, each for the reason in its row; the four fixed items were rated low. The
*Severity* column gives Aikido's rating for each ID in the order the row lists them, or once when
they agree.

Of the files below, `wallet/server/network.mjs` and `wallet/server/tool.mjs` are in audit scope
([Tier 2](AUDIT-SCOPE.md#tier-2--paths-that-feed-trust-decisions)). The rest of `wallet/server`,
the testnet harness, the fixture scripts and CI are informational
([AUDIT-SCOPE.md](AUDIT-SCOPE.md#informational--not-in-scope)). The harness scripts are
command-line tools with no network listener. `run.sh` creates the run directory (under
`testnet-harness/runs/`, or `OZPB_HARNESS_OUT`) and passes it to each script as `--run-dir`.
Inside that directory the scripts open fixed file names. Where a script follows the spec path
recorded in `run.json`, it first checks that the path is `<run-dir>/spec.json` (`runSpecPath` in
`rpc.mjs`). Every other path comes from a command-line argument or environment variable the
operator sets (`--trust`, `--wasm`, `--bundle`, `--evidence`, `--decisions`, the registry files).
Aikido's line numbers move with edits, so the rows below name the function instead.

If someone shows that a value marked not exploitable can be reached from untrusted input, that is
a finding.

| Aikido ID | Severity | File · rule | Disposition | Why: where the value comes from | Ignore reason for Aikido |
| --- | --- | --- | --- | --- | --- |
| 868502071 | low | `testnet-harness/scripts/rpc.mjs` `fund` · SSRF (CWE-918) | Fixed in this tree | `fund` used to request the `friendbotUrl` that the RPC endpoint reports. It now always uses `https://friendbot.stellar.org`, the URL the wallet's testnet profile pins. Test: `rpc.test.mjs`, "Friendbot is the pinned testnet service…" | — |
| 546339298, 546339299, 938294599 | low | `.github/workflows/ci.yml`, `nightly-live.yml`, `self-hosted.yml` · checkout persists credentials (CWE-522) | Fixed in this tree | Every `actions/checkout` step now sets `persist-credentials: false`. Exposure was already small: each workflow grants only `contents: read` on a public repository, and no job pushes. | — |
| 917984518 | low | `docs/evidence/testnet-subscription-2026-10-20.json` `transactions.create_control_token` · leaked secret (CWE-540) | False positive | The value is the hash of the testnet transaction that created the run's control-token contract (`setup-subscription.mjs` records `created.hash`; `evidence.mjs` exports only 64-hex transaction hashes under `transactions`). It is public ledger data, not a credential. | False positive: public Stellar testnet transaction hash (the transaction that created a test token contract), not a credential. |
| 993334733 | high | `wallet/server/toolchain.mjs` `save` · file inclusion (CWE-23) | Not exploitable | Every path is a fixed file name: either the network marker directly in `workRoot`, or a file inside a `mkdtemp` session or operation directory under it. `workRoot` comes from the operator's configuration (`config.mjs`: absolute, not a symlink, owner-only). Generated file names must equal the fixed `FILES` list, and every write uses `wx` (O_EXCL). | Not exploitable: fixed file names in the operator-configured work root or a mkdtemp directory under it; no request value reaches the path; writes use O_EXCL. |
| 874346191 | high | `wallet/server/network.mjs` `#save` · file inclusion (CWE-23) | Not exploitable | The journal file name is the backend's own serial counter plus a phase name written in the code. The directory is the session directory that `main.mjs` creates. Writes use `wx`. | Not exploitable: journal file name is an internal counter and a literal phase name in a backend-created session directory; no request value reaches the path. |
| 938298424 | medium | `wallet/server/tool.mjs` `runTool` · command injection (CWE-78) | Not exploitable | `spawn` gets an argument array and no shell. The executable is the absolute path in the operator's configuration (`config.mjs` refuses symlinks and files that group or others can write). Arguments are literals, paths the backend created, operator configuration (the RPC URL, the published registry path), and request values checked first (64-hex hashes, `StrKey` addresses). | Not exploitable: spawn without a shell; executable is the operator-configured absolute path; arguments are literals, backend-created paths, operator configuration and validated hashes/addresses. |
| 938298410 | medium | `wallet/server/native-process.mjs` `runNative` · command injection (CWE-78) | Not exploitable | `spawn` runs with `shell: false`. The executable is the operator's configured `nativeExecutable`. The arguments select one of four modes written in the code (three flags, or none), and the job goes over stdin. | Not exploitable: spawn with shell false; operator-configured executable; arguments are fixed mode flags; job data goes over stdin. |
| 868502078, 938298098 | high, medium | `testnet-harness/scripts/rpc.mjs` `readJson`, `writeJson` · file inclusion (CWE-23) | Not exploitable | Shared helpers. Callers pass the run directory plus a fixed name, or a path the operator gives on the command line (`--trust` to read, `--bundle` to write). `writeJson` writes a randomly named temporary file with `wx`, then renames it. | Not exploitable: local testnet harness CLI with no listener; path is the operator's run directory plus a fixed file name. |
| 993334548 | high | `testnet-harness/scripts/deploy-live-helper.mjs` `writeEvidence` · file inclusion (CWE-23) | Not exploitable | The path is the operator's `--evidence` argument, or `docs/evidence/atomic-live-helper-testnet-<date>.json`. The script refuses an existing file and writes with `wx`. | Not exploitable: output path is the operator's --evidence argument or a fixed docs/evidence name; existing files are refused (O_EXCL). |
| 868502103 | medium | `testnet-harness/scripts/run-provenance.mjs` `startRun` · file inclusion (CWE-23) | Not exploitable | Writes `provenance.json` into the run directory that `run.sh` passes. The directory must be empty, and the write uses `wx`. | Not exploitable: fixed file name in the run directory run.sh creates; written with O_EXCL. |
| 938297487, 938297517, 938297521, 938297526 | medium, low, low, low | `testnet-harness/scripts/bundle-command.mjs` `loadBundleFiles`, `bundleCommand` · file inclusion (CWE-23) | Not exploitable | Reads `run.json`, `spec.json`, `recording.json` and `policies/rule-N/` from `--run-dir`. The Wasm name comes from listing that directory. Paths recorded in `run.json` are compared with these, never opened. | Not exploitable: local testnet harness CLI; fixed names under the operator's --run-dir; paths recorded in the journal are compared, never opened. |
| 938297568, 938297584, 938297586, 938297590, 938297593 | medium, low, medium, medium, medium | `testnet-harness/scripts/derived-denials.mjs` `runDerivedDenials`, `cliRunner` · file inclusion (CWE-23) | Not exploitable | Fixed names under `--run-dir`. `run.spec` must resolve to `<run-dir>/spec.json`. | Not exploitable: local testnet harness CLI; fixed file names under the operator's --run-dir. |
| 938297649, 938297663 | low, medium | `testnet-harness/scripts/failure-cleanup.mjs` `cleanupAfterFailure` · file inclusion (CWE-23) | Not exploitable | `run.json` and `cleanup-termination.json` (`wx`) under `--run-dir`. | Not exploitable: local testnet harness CLI; fixed file names under the operator's --run-dir. |
| 938297714 | medium | `testnet-harness/scripts/lifecycle.mjs` `revokePolicy` · file inclusion (CWE-23) | Not exploitable | `run.json` and `spec.json` under `--run-dir`. | Not exploitable: local testnet harness CLI; fixed file names under the operator's --run-dir. |
| 938297759, 938297768 | medium, low | `testnet-harness/scripts/protocol-finish.mjs` `finishProtocolBundle` · file inclusion (CWE-23) | Not exploitable | `run.json` under `--run-dir`. | Not exploitable: local testnet harness CLI; fixed file names under the operator's --run-dir. |
| 938297868, 993334672 | low | `testnet-harness/scripts/protocol-flow.mjs` `read`, `save` · file inclusion (CWE-23) | Not exploitable | Fixed names under `--run-dir`, the CLI's own output under `policies/`, and registry files named by operator environment variables. | Not exploitable: local testnet harness CLI; fixed names under the operator's --run-dir and operator-named registry files. |
| 938298161, 993334709, 938298200, 938298299 | medium, low, low, low | `testnet-harness/scripts/synthesis-flow.mjs` `read`, `save`, `cli`, and the Wasm read in `runSynthesisFlow` · file inclusion (CWE-23) | Not exploitable | As in `protocol-flow.mjs`. Log names are `<stage>.log`, where the stage is a CLI command name written in the code. The Wasm is the single `.wasm` file found by listing `<run-dir>/policy`. | Not exploitable: local testnet harness CLI; fixed names under the operator's --run-dir and operator-named registry files. |
| 938298130 | medium | `testnet-harness/scripts/soroswap-preflight.mjs` `readSoroswapDecisions` · file inclusion (CWE-23) | Not exploitable | The operator's `--decisions` file, which `run.sh` takes from `OZPB_SOROSWAP_DECISIONS`. A symlink or non-regular file is refused, a file over 4 KiB is refused once read, and its hash is journaled. | Not exploitable: operator-named decisions file; symlinks and non-regular files refused, oversize refused, hash journaled. |
| 993334633 | medium | `testnet-harness/scripts/protocol-dry-run.mjs` `save` · file inclusion (CWE-23) | Not exploitable | A `mkdtemp` directory beside the run's secrets file, and indexed fixed names under `--run-dir`. Writes use `wx`. | Not exploitable: local testnet harness CLI; fixed names in a mkdtemp directory and the operator's --run-dir; O_EXCL writes. |
| 868501979 | low | `scripts/test-check-unmodeled-acknowledged.py` · file inclusion (CWE-23) | Not exploitable | A test writes its own case file names into a `tempfile.TemporaryDirectory`. | Not exploitable: test code writing its own fixture names into a temporary directory. |
| 874346057, 874346064, 874346070 | low | `scripts/atomic-live-helper-fixture.py`, `scripts/native-execution-fixture.py` · use of assert (CWE-703) | Not exploitable | These scripts build test fixtures. Only the repository's test scripts run them, with plain `python3`, so the asserts stay active. Their inputs are the test's own `mktemp` directory and committed examples, and the asserts gate no trust decision. | Not exploitable: test-fixture generator run only by the repository's test scripts with python3 (asserts active); gates no trust decision. |

## Reported by pull-request scans after 19 November 2026

Aikido's pull-request scan reports only items new against `main`, and gives a scan link rather
than an issue ID until the code reaches `main`.

| Scan | Severity | File · rule | Disposition | Why: where the value comes from | Ignore reason for Aikido |
| --- | --- | --- | --- | --- | --- |
| Pull-request scan, 26 Nov 2026 | critical | `crates/cli/src/registry.rs` `load_roots` (and `read_json`) · path traversal (CWE-23) | Not exploitable | `ozpb registry` is the custodians' governance CLI on their own machine; it serves no network request. Every path is an argument the custodian types (`--registry-roots`, `--snapshot`, `--out`, the log directory) or a file name read from that directory. Reading the file the operator names is the command's purpose; writes use `create_new` and never replace a file. | Not exploitable: local governance CLI; paths are the operator's own command-line arguments, no network input. |
