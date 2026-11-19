# Self-hosted MCP

This package runs the versioned MCP endpoint for **one operator and trusted clients**. It
works on a Linux Docker host independently of any hosting provider. It does not provision
cloud infrastructure or establish that an endpoint has been deployed. Releases made after the
publishing workflows were added also publish images and binaries; see
[Production release](#production-release).

The hosted testnet deliverable means running the MCP tools behind an authenticated HTTPS
address for authorized remote clients. It is not a wallet or a Stellar validator/RPC node:
it records, synthesizes, builds and verifies policies through operator-allowed testnet RPC
sources. User signing and installation approval remain in the wallet. A working local image
or this guide alone does not establish that the hosted service is running.

For a reference deployment offered during a testnet review, publish its access window and
shutdown condition alongside its HTTPS address. Keep the self-hostable image and instructions
available for use after that window. A temporary testnet instance is not evidence of a
production endpoint or an ongoing availability commitment.

Use the disposable-worker mode below when preparing the hosted testnet deployment. Choosing
its hosting provider is an operational decision, not a separate milestone requirement.
Present the actual account, hostname/TLS plan, image digest, client access boundary, cost,
budget alert and stop condition before creating paid resources. Tranche 3 delivers a production
versioned release that operators run themselves; Gateway operates no production service. The
testnet deployment still needs its own security and operational acceptance checks.

**The API and compiler still share a trust domain.** Container resource limits, Cargo's
offline setting and environment filtering are useful bounds, but they do not isolate each
compilation from API secrets, other jobs or RPC networking. Do not use this package as a
public multi-tenant compilation service. A disposable, no-secrets worker boundary remains
required for that use. The offline image test proves compilation with networking disabled;
the API service itself needs network access to its operator-configured RPC endpoints.

For a separate Linux host API with a disposable rootless container for each build, see
[Disposable build workers](ISOLATED-BUILDS.md). That mode has its own deployment and
containment acceptance checks; it does not add runtime access to this Compose service.

## Production release

A release is software you run yourself; Gateway operates no service for it. What its version
number keeps stable, and for how long, is [VERSIONING.md](VERSIONING.md). Each published GitHub
Release carries:

- the API and TLS proxy images ([below](#build-the-reviewed-revision));
- for Linux x86_64, Linux aarch64 and macOS arm64, one archive per binary with the licence files:
  `ozpb` (the CLI), `ozpb-mcp-server` (stdio, or `--http` for this endpoint) and
  `ozpb-execution-runtime` (the [native worker](NATIVE-EXECUTION.md) behind `ozpb dry-run`);
- `ozpb-wire-contract-<tag>.json`: every tool the server lists, with its input and output JSON
  Schema, and the `E_*` codes;
- `SHA256SUMS`, and a GitHub build-provenance attestation for every asset, `SHA256SUMS` included.

### Obtain and verify

```sh
tag=vX.Y.Z    # the release you are installing
gh release download "$tag" --repo gateway-fm/oz-policy-builder \
  --pattern '*-x86_64-unknown-linux-gnu.tar.gz' --pattern SHA256SUMS
# On macOS, `shasum -a 256 --check` in place of `sha256sum --check`.
grep -- '-x86_64-unknown-linux-gnu.tar.gz$' SHA256SUMS | sha256sum --check
# A subshell, so the first failure stops the loop without closing your shell.
( set -e
  for asset in *.tar.gz SHA256SUMS; do
    gh attestation verify "$asset" --repo gateway-fm/oz-policy-builder \
      --signer-workflow gateway-fm/oz-policy-builder/.github/workflows/release-binaries.yml \
      --source-ref "refs/tags/$tag" --deny-self-hosted-runners
  done )
```

`--repo` alone accepts an attestation from any workflow in the repository; the other three
flags require the one that publishes releases, run for this tag on a GitHub-hosted runner.
Verify images the same way, by digest (below). The Linux
binaries are built on Ubuntu 24.04 and may need a glibc as new as its; on an older host, build
from the tag instead (`cargo build --locked --release -p ozpb-cli -p ozpb-mcp-server`, and the
worker as its [guide](NATIVE-EXECUTION.md#machine-protocol) says). The macOS binaries are not
signed or notarized: `gh` and `curl` downloads run as they are, while a browser download is
quarantined until you remove the attribute (`xattr -d com.apple.quarantine <binary>`), which you
should do only after the checks above. Unpacked as you, the worker is owned by you and not
writable by others, which `ozpb dry-run` requires of it.

The binaries do not include a compiler. Generating or verifying a policy (`ozpb generate`,
`ozpb verify`, the `generate_code` and `verify` tools) runs `stellar contract build`, so a host
install needs the Rust and Stellar CLI versions the release records
(`bash scripts/recorded-build-inputs.sh rust` and `stellar-cli`, from the tag) with the
`wasm32v1-none` target, and `OZPB_STELLAR_BINARY` if `stellar` is not on the path
([build configuration](DEVELOPERS.md#build-configuration-operator-side)). Any other version builds
different Wasm, and the [`verify` reproduction](VERSIONING.md#what-is-versioned) then fails. The
API image includes both.

### Mainnet configuration

- **Registry.** The committed development root is refused for every network but testnet
  (`E_REGISTRY_ROOT_POLICY`). Use the mainnet root policy and signed head published with
  [the mainnet registry](../registry/mainnet/README.md); until its custodians sign the first
  version there is none, and every mainnet trust check refuses. Persist the checkpoint in the
  roots file and set the floor to its version
  ([pinning roots and persisting checkpoints](REGISTRY-GOVERNANCE.md#consumers-pinning-roots-and-persisting-checkpoints)).
  In this deployment that is `registry-roots.json` and `registry.signed.json` in the
  configuration directory and `OZPB_REGISTRY_MIN_VERSION`; for the CLI, `--registry-roots` and
  `--registry-min-version`.
  Then [schedule the monitor](REGISTRY-GOVERNANCE.md#scheduling-the-monitor).
- **RPC.** Name a mainnet source in `rpc-sources.json`, with the network passphrase
  `Public Global Stellar Network ; September 2015`, and put its exact HTTPS URL in
  `OZPB_RPC_ALLOWLIST`. The network must run protocol 30, and installation's live check needs an
  endpoint that returns diagnostic events, which stellar-rpc 30.0.1 does only when run with
  `--preflight-enable-debug` ([mainnet prerequisites](MAINNET-INSTALL.md#prerequisites),
  [live use](ATOMIC-LIVE-HELPER.md#how-live-use-is-meant-to-work)).
- **Authentication.** `--http` refuses to start without a bearer token of at least 32 bytes and
  an RPC allowlist. Serve it through the TLS proxy or your own ingress only
  ([operator boundary](#configure-the-operator-boundary),
  [ingress](#behind-your-own-ingress-instead-of-the-proxy)). Over stdio the server is a local
  process of the client and takes no token.

The endpoint never signs or installs: the owner does, in the wallet, by the
[mainnet runbook](MAINNET-INSTALL.md).

### Upgrading between versions

Read the release notes of every release from yours to the new one. Within 1.x during the grant,
nothing there breaks the [versioned contracts](VERSIONING.md#breaking-and-additive) except a
security fix or a network-forced change, which the notes list as breaking with what to do. A
document that uses a field a newer release added is not readable by an older one, so upgrade
every component that exchanges documents (CLI, server, native worker, wallet) together, and take
each from one release. With [disposable build workers](ISOLATED-BUILDS.md), the API binary and
`deployment/worker-launcher.py` must come from the same release (the API refuses to start with
a launcher that speaks another protocol): take the launcher from the release's tag, not from
`main`. Deploy new images by digest and recreate the containers; this discards in-memory session
references, as described under
[data handling](#data-handling-and-handover). An upgrade does not move your registry checkpoint
or floor: they advance only when you accept a newer registry version.

## Build the reviewed revision

Use Python 3 and Docker with BuildKit. The image supports Linux amd64 and arm64. Building
needs internet access for the checksum-pinned Stellar CLI, Rust components and locked Cargo
dependencies. Allow at least 12 GiB of free build storage. Runtime policy builds use vendored
dependencies and refuse downloads.

```sh
revision=$(git rev-parse --verify 'HEAD^{commit}'); echo "$revision"
python3 scripts/hosted-context.py "$revision" > /tmp/ozpb-context.tar
docker build --target proxy --file deployment/Dockerfile --tag ozpb-proxy:reviewed - < /tmp/ozpb-context.tar
docker build --file deployment/Dockerfile --build-arg OZPB_TOOLKIT_SOURCE="$revision" \
  --tag ozpb-self-host:reviewed - < /tmp/ozpb-context.tar
docker image inspect ozpb-self-host:reviewed --format '{{.Id}}'
docker image inspect ozpb-proxy:reviewed --format '{{.Id}}'
```

The exporter reads only allowlisted files from the selected Git tree. Untracked files and
working-copy edits are ignored, including edits to the Dockerfile: commit and review changes
before selecting their revision. Symlinks, crate submodules and missing required files fail
the export. Source review and the publication gate remain necessary; an allowlist cannot
decide whether a Rust source file contains confidential information.

The context carries no `.git`, so the image cannot ask which commit it is built from: the
`OZPB_TOOLKIT_SOURCE` build argument tells it, and every BuildManifest the image writes records
that commit as `producer.toolkit_source`. Without the argument, they record none. Like every
manifest field it is the builder's statement, not something `verify` checks.

The base image and TLS proxy are pinned by digest. Rust and Stellar CLI match the recorded
Wasm build inputs; Stellar downloads are checked by SHA-256. OS packages resolve during
image construction, so an image build is not claimed byte-reproducible. Record the resulting
image digest, source revision, package inventory and test result. When publishing through
your own registry, deploy the resulting immutable `repository@sha256:…` reference rather
than a mutable tag. `self-hosted.yml` builds and tests in CI and never pushes.

For each published GitHub Release whose tag (`v` plus the workspace version in `Cargo.toml`)
contains it, `publish-image.yml` builds both images for amd64 and arm64 from the release tag,
runs every check `self-hosted.yml` runs on each, and publishes them to
`ghcr.io/gateway-fm/oz-policy-builder` and `ghcr.io/gateway-fm/oz-policy-builder-proxy` under
the release tag, with a GitHub build-provenance attestation. The workflow summary lists both
`@sha256` references; use those, and check each with

```sh
gh attestation verify "oci://<reference>" --repo gateway-fm/oz-policy-builder \
  --signer-workflow gateway-fm/oz-policy-builder/.github/workflows/publish-image.yml \
  --source-ref "refs/tags/<tag>" --deny-self-hosted-runners
```

A published
image is software for operators to run; it does not mean an endpoint is running.

GHCR creates a new package as private. After the first publication an organization owner makes
both packages public once, under the package's settings; GitHub does not allow making a public
package private again. Until then, pulls and attestation checks from outside the organization
are refused. `v0.1.0` predates the workflow and has no images.

## Configure the operator boundary

Copy `deployment/example.env` to a private location outside the checkout. Set `OZPB_IMAGE`
and `OZPB_PROXY_IMAGE` to your built image IDs or registry digests and `OZPB_CONFIG_DIR` to an absolute private
directory. The directory must contain these files:

| File | Meaning |
| --- | --- |
| `bearer-token` | A newly generated 32–128-character URL-safe token; shared only with the trusted clients. |
| `registry-roots.json` | The registry roots the operator trusts. |
| `registry.signed.json` | A signed snapshot accepted by those roots and the minimum version. |
| `rpc-sources.json` | Named sources, such as `{"testnet":{"rpc_url":"https://soroban-testnet.stellar.org","network_passphrase":"Test SDF Network ; September 2015"}}`. |
| `tls.crt`, `tls.key` | A certificate and its private key for `OZPB_HOSTNAME`. Only the proxy receives them. |

Keep the parent directory mode `0700`; make the individual mounted files readable by
container UID 10001 (for example `0444` inside that private directory). Docker Compose uses
read-only file mounts and refuses missing files. Create the bearer token without printing it:

```sh
umask 077
openssl rand -hex 32 > /absolute/private/ozpb-config/bearer-token
```

The committed registry fixtures are **development trust only**. They can support an isolated
testnet demonstration; they are not production governance roots. Set
`OZPB_REGISTRY_MIN_VERSION` explicitly. The server rejects a named RPC source whose exact
HTTPS URL is absent from `OZPB_RPC_ALLOWLIST`; clients cannot add endpoints. Configure the
allowlist and source map together. A new operator chooses these settings, the host name,
certificate, image digest and deployment environment; no provider account is embedded.

Keep credentials out of command-line arguments, the environment file and build context.
The entrypoint reads the mounted bearer token into the environment only because the current
server requires that interface. Compiler subprocesses clear it, but this is not an OS
isolation guarantee. The Docker daemon and host administrators remain trusted.

## Start, check and stop

```sh
docker compose --env-file /absolute/private/ozpb.env -f deployment/compose.yaml config --quiet
docker compose --env-file /absolute/private/ozpb.env -f deployment/compose.yaml up -d
docker compose --env-file /absolute/private/ozpb.env -f deployment/compose.yaml down --remove-orphans
```

Only TLS port 8443 is published, to host loopback by default. The API remains on container
loopback at `/v1/mcp`; the proxy shares its network namespace. An operator may change
`OZPB_BIND_IP` and `OZPB_TLS_PORT` after deciding who can reach the trusted-client service.
Use a certificate trusted by the clients; never disable certificate verification. The proxy
rejects other host names, browser-origin requests and paths outside `/v1/mcp`. Native MCP
clients send the bearer token over TLS. Browser integration and separate per-client quotas
are not supplied by this shared-token configuration.

### Behind your own ingress instead of the proxy

A platform that terminates TLS itself, such as a Kubernetes ingress, can reach the API directly
and leave the proxy out. Set `OZPB_HTTP_LISTEN` (for example `0.0.0.0:8080`) and
`OZPB_HTTP_ALLOWED_HOSTS` to the public host names the ingress forwards (comma-separated
`host[:port]`, no wildcards or IPv6 literals). The Compose file passes neither: it runs the
proxy mode above. The server refuses a routable listen address unless the list names a host
that is not loopback, and then answers authenticated requests for those hosts only (`403` for
any other `Host`, loopback names included). It refuses any request carrying an `Origin` header
(`403`) in either mode, as the proxy does. The bearer token, request quota, body bound and build
limits apply unchanged.

The `Host` check is not access control: whoever reaches the listen address can name the public
host. Between the ingress and the API the token travels in plain HTTP and is the only control,
so allow only the ingress controller to reach that port (on Kubernetes, a NetworkPolicy). What
the proxy did becomes the ingress's job: TLS with a certificate the clients trust, refusing paths
other than `/v1/mcp`, and keeping request bodies and headers out of its access logs.

The API has a 2-CPU, 4-GiB memory, 256-process ceiling; the proxy has 0.5 CPU, 128 MiB and
64 processes. Both run as UID 10001 with no added capabilities, no privilege escalation and
a read-only root filesystem. The API's temporary build data and cache occupy bounded tmpfs
mounts (512 MiB and 2 GiB), charged to its memory limit. A cold build may hit these bounds;
size them using your measured workload. One build slot and one compiler job are configured.
These are service-level limits, not per-job containment. Replacing the container discards
the writable cache and temporary files.

Run the disposable integration check against a locally built image:

```sh
OZPB_IMAGE="$(docker image inspect ozpb-self-host:reviewed --format '{{.Id}}')" \
OZPB_PROXY_IMAGE="$(docker image inspect ozpb-proxy:reviewed --format '{{.Id}}')" \
  bash scripts/test-hosted-container.sh
```

It generates a local test certificate, verifies it, checks authentication, host/origin/path
guards, initialization, body limits and the request quota, then tears that endpoint down.
Fresh service containers then run real MCP `generate_code` and `verify` through TLS, checking
the returned Wasm digest and explicit source/Wasm/manifest reproduction dimensions.
A separate container also runs real `generate` and `verify` with `--network none` and no mounted
credentials. The standalone `check-hosted-endpoint.py` exhausts its supplied quota on
purpose: use it only against a fresh isolated endpoint, not another operator's active service.

## Data handling and handover

Access logging and container log retention are disabled. The proxy discards error logs too,
so URLs or request-derived details are not retained accidentally. Do not enable debug
tracing, body logging, crash uploads or request analytics. This reduces diagnostics: an
operator investigating startup failure should reproduce with synthetic input in an isolated
environment and review any output before retaining it. `scripts/check-log-redaction.py` fails
CI if a file of this package turns a log back on, prints the bearer token or the trust inputs,
or links a log subscriber into the server; it does not cover your ingress or host.

Request data is processed in memory and temporary files. Each MCP session also retains up to
eight generated artifacts in memory for verification by reference. This is a count limit,
not a one-megabyte cap. References are confined to that session and backend instance and are
lost when the session ends or the server restarts; route an existing session to the same
backend. Build artifacts and cache data can remain in tmpfs until container removal; there
is no configured backup or durable request storage. Deletion means removing both containers and their tmpfs, and removing any operator
exports separately. Host swap, host crash dumps and external proxy/monitoring retention are
the host operator's responsibility. Treat unsigned simulations and generated source as
confidential, and offer local stdio processing for material that should never leave a client.

Before handing a deployment to another operator, record the tested source revision and image
digest, trusted roots/version, RPC configuration, certificate ownership/renewal, authorized
clients, retention and incident contacts, and the successful isolated smoke result. On a
credential incident, stop the service, replace the token and review host access before
restarting. On a build compromise, replace containers and caches from the reviewed image;
the shared compiler boundary is why public multi-tenant use remains unsupported.

An actual cloud deployment also needs the chosen provider's cost estimate, budget alerts and
an implemented stop condition. This configuration has `restart: "no"`, no scheduled jobs and
no recurring uptime probe. `compose down` stops these containers; it does not stop billing
for an independently provisioned VM, load balancer, registry or other provider resources.

The [architecture](architecture.md#46-mcp-server-cratesmcp-server) describes the separate
isolated-worker target. Docker's [Compose service reference](https://docs.docker.com/reference/compose-file/services/)
documents namespace sharing and limits; Caddy's [server options](https://caddyserver.com/docs/caddyfile/options#server-options)
document the TLS proxy's host and connection controls.
