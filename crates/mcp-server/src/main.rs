//! rmcp stdio MCP server (architecture §4.6, §4.11).
//!
//! A thin shell: every `#[tool]` is a wrapper over `ozpb_toolkit`, with types from
//! `ozpb_api_types` so input/output JSON Schemas are generated from the same structs the
//! core consumes. No domain logic lives here. Tools are stateless; annotations mark the
//! read/pure/mutating nature per §4.6 (record_* touch the network; the rest are pure).
//!
//! Deployment and signing are deliberately NOT capabilities of this server.

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{CallToolResult, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ServerHandler, ServiceExt};

use ozpb_api_types::{
    EvaluateSpecInput, EvaluateSpecOutput, GenerateCodeInput, GenerateCodeOutput,
    ImportRecordingInput, RecordOutput, RecordSimulationInput, RecordTransactionInput,
    SynthesizeInput, SynthesizeOutput, ToolError,
};
use ozpb_recorder_core::RecordOptions;
use ozpb_source_bundle::import_json;
use ozpb_source_rpc::HttpTransport;
use std::collections::BTreeSet;
use std::sync::Arc;

#[derive(Clone)]
struct RpcEndpointPolicy {
    allowed: Arc<BTreeSet<String>>,
}

impl RpcEndpointPolicy {
    fn from_csv(csv: &str) -> anyhow::Result<Self> {
        let mut allowed = BTreeSet::new();
        for candidate in csv.split(',').map(str::trim).filter(|url| !url.is_empty()) {
            allowed.insert(Self::normalize(candidate)?);
        }
        if allowed.is_empty() {
            anyhow::bail!("OZPB_RPC_ALLOWLIST must contain at least one HTTPS endpoint");
        }
        Ok(Self {
            allowed: Arc::new(allowed),
        })
    }

    fn normalize(candidate: &str) -> anyhow::Result<String> {
        let url = url::Url::parse(candidate)
            .map_err(|error| anyhow::anyhow!("invalid RPC URL '{candidate}': {error}"))?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
        {
            anyhow::bail!(
                "hosted RPC endpoints must be absolute HTTPS URLs without credentials or fragments"
            );
        }
        Ok(url.to_string())
    }

    fn authorize(&self, requested: &str) -> Result<String, ToolError> {
        let normalized = Self::normalize(requested)
            .map_err(|error| ToolError::new(ozpb_api_types::ErrorCode::ERpc, error.to_string()))?;
        if !self.allowed.contains(&normalized) {
            return Err(ToolError::new(
                ozpb_api_types::ErrorCode::ERpc,
                "RPC endpoint is not in the hosted server allowlist",
            ));
        }
        Ok(normalized)
    }
}

#[derive(Clone)]
struct PolicyBuilderServer {
    tool_router: ToolRouter<Self>,
    registry_trust: Option<ozpb_toolkit::RegistryTrust>,
    rpc_policy: Option<RpcEndpointPolicy>,
    /// Operator-side build settings. Unlike `rpc_policy` this is not optional: every
    /// transport needs a builder, and the wire contract carries no build fields — a
    /// caller-chosen timeout would be resource exhaustion and a caller-chosen builder path
    /// arbitrary execution.
    build_config: ozpb_toolkit::BuildConfig,
}

impl PolicyBuilderServer {
    fn new(
        registry_trust: Option<ozpb_toolkit::RegistryTrust>,
        rpc_policy: Option<RpcEndpointPolicy>,
        build_config: ozpb_toolkit::BuildConfig,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            registry_trust,
            rpc_policy,
            build_config,
        }
    }

    fn authorized_rpc_url(&self, requested: &str) -> Result<String, ToolError> {
        match &self.rpc_policy {
            Some(policy) => policy.authorize(requested),
            None => Ok(requested.to_string()),
        }
    }
}

/// Map a toolkit ToolError into an rmcp tool-execution error carrying the structured
/// payload (stable code + message + details) as JSON data — the agent-recoverable
/// channel (§4.6).
fn tool_err(e: ToolError) -> CallToolResult {
    let data = serde_json::to_value(&e).unwrap_or_else(|_| {
        serde_json::json!({
            "code": "E_INTERNAL",
            "message": "could not serialize tool error"
        })
    });
    CallToolResult::structured_error(data)
}

fn internal_tool_err(error: impl std::fmt::Display) -> CallToolResult {
    tool_err(ToolError::new(
        ozpb_api_types::ErrorCode::EInternal,
        error.to_string(),
    ))
}

fn rpc_tool_err(error: ozpb_source_rpc::RpcError) -> ToolError {
    let code = match error {
        ozpb_source_rpc::RpcError::NotFound(_) => ozpb_api_types::ErrorCode::ETxNotFound,
        ozpb_source_rpc::RpcError::NetworkMismatch { .. } => {
            ozpb_api_types::ErrorCode::ENetworkMismatch
        }
        _ => ozpb_api_types::ErrorCode::ERpc,
    };
    ToolError::new(code, error.to_string())
}

#[tool_router(router = tool_router)]
impl PolicyBuilderServer {
    /// Record an executed on-chain transaction (by hash) into an authorization
    /// fingerprint. NETWORK READ. Retention is short — outside it, use import.
    #[tool(
        name = "record_transaction",
        description = "Record an executed Stellar transaction (by hash, via Soroban RPC) \
                       into a RecordingBundle: the authorization tree, token movements, \
                       and dual hashes. Network read."
    )]
    async fn record_transaction(
        &self,
        Parameters(input): Parameters<RecordTransactionInput>,
    ) -> Result<Json<RecordOutput>, CallToolResult> {
        let rpc_url = self.authorized_rpc_url(&input.rpc_url).map_err(tool_err)?;
        let out = tokio::task::spawn_blocking(move || {
            let transport = HttpTransport::new(rpc_url);
            let snapshot = ozpb_source_rpc::get_transaction(
                &transport,
                &input.network_passphrase,
                &input.tx_hash,
            )
            .map_err(rpc_tool_err)?;
            let options = RecordOptions {
                operation_index: input.operation_index,
                allow_failed: input.allow_failed,
            };
            ozpb_toolkit::record_snapshot(&snapshot, options)
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Record a locally simulated (unsigned) transaction via RPC record mode. NETWORK
    /// READ. The envelope may encode private intent — confidential input (§6.5).
    #[tool(
        name = "record_simulation",
        description = "Record an unsigned transaction envelope via simulateTransaction in \
                       record mode into a RecordingBundle. Network read; the envelope is \
                       confidential input."
    )]
    async fn record_simulation(
        &self,
        Parameters(input): Parameters<RecordSimulationInput>,
    ) -> Result<Json<RecordOutput>, CallToolResult> {
        let rpc_url = self.authorized_rpc_url(&input.rpc_url).map_err(tool_err)?;
        let out = tokio::task::spawn_blocking(move || {
            let transport = HttpTransport::new(rpc_url);
            let snapshot = ozpb_source_rpc::simulate_transaction(
                &transport,
                &input.network_passphrase,
                &input.envelope_xdr_base64,
            )
            .map_err(rpc_tool_err)?;
            ozpb_toolkit::record_snapshot(&snapshot, RecordOptions::default())
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Synthesize a minimum-permission PolicySpec from recordings + explicit user
    /// decisions. PURE and deterministic. Exact-by-default; widening only via decisions.
    #[tool(
        name = "synthesize_policy",
        description = "Synthesize a minimum-permission PolicySpec from RecordingBundle(s) \
                       plus explicit user decisions (signer set, lifetime, widenings). \
                       Pure, deterministic, exact-by-default, fail-closed."
    )]
    async fn synthesize_policy(
        &self,
        Parameters(input): Parameters<SynthesizeInput>,
    ) -> Result<Json<SynthesizeOutput>, CallToolResult> {
        let trust = self.registry_trust.as_ref().ok_or_else(|| {
            tool_err(ToolError::new(
                ozpb_api_types::ErrorCode::ERegistryEmpty,
                "synthesize_policy is disabled until OZPB_REGISTRY_ROOTS_JSON and \
                 OZPB_REGISTRY_MIN_VERSION are configured",
            ))
        })?;
        let out = ozpb_toolkit::synthesize_policy(&input, trust).map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Evaluate a candidate invocation against a PolicySpec using the independent
    /// reference evaluator. PURE. Lets an agent pre-flight an action safely.
    #[tool(
        name = "evaluate_spec",
        description = "Evaluate whether a candidate invocation would be permitted under a \
                       PolicySpec, using the independent reference evaluator. Pure; \
                       returns permit or deny + machine-readable reason."
    )]
    async fn evaluate_spec(
        &self,
        Parameters(input): Parameters<EvaluateSpecInput>,
    ) -> Result<Json<EvaluateSpecOutput>, CallToolResult> {
        let out = ozpb_toolkit::evaluate_spec(&input).map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Generate and reproducibly build the immutable Soroban policy artifact. Resource
    /// consuming, deterministic, and non-deploying — code-first, deploy-second (§6.2).
    #[tool(
        name = "generate_code",
        description = "Generate and build the deterministic, immutable Soroban policy \
                       artifact for a PolicySpec rule: locked Rust source, Wasm, and a \
                       binding BuildManifest. Resource-consuming; never deploys or signs."
    )]
    async fn generate_code(
        &self,
        Parameters(input): Parameters<GenerateCodeInput>,
    ) -> Result<Json<GenerateCodeOutput>, CallToolResult> {
        let build = self.build_config.clone();
        let out = tokio::task::spawn_blocking(move || {
            ozpb_toolkit::generate_code_with_build_config(&input, &build)
        })
        .await
        .map_err(internal_tool_err)?
        .map_err(tool_err)?;
        Ok(Json(out))
    }

    /// Import a raw-XDR evidence bundle (offline) into a RecordingBundle. PURE. For
    /// transactions outside RPC retention; the result is `self_supplied` trust.
    #[tool(
        name = "import_recording",
        description = "Record from a self-contained raw-XDR evidence bundle (offline). \
                       Pure; the result carries self_supplied trust (internally consistent \
                       but not network-verified)."
    )]
    async fn import_recording(
        &self,
        Parameters(input): Parameters<ImportRecordingInput>,
    ) -> Result<Json<RecordOutput>, CallToolResult> {
        let bundle_json = serde_json::json!({
            "network_passphrase": input.network_passphrase,
            "envelope_xdr_base64": input.envelope_xdr_base64,
            "result_meta_xdr_base64": input.result_meta_xdr_base64,
            "ledger": input.ledger,
            "created_at_unix": input.created_at_unix,
            "successful": input.successful,
        })
        .to_string();
        let snapshot = import_json(&bundle_json).map_err(|error| {
            tool_err(ToolError::new(
                ozpb_api_types::ErrorCode::EImportParse,
                error.to_string(),
            ))
        })?;
        let out =
            ozpb_toolkit::record_snapshot(&snapshot, RecordOptions::default()).map_err(tool_err)?;
        Ok(Json(out))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for PolicyBuilderServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "OZ Accounts Policy Builder. Record a Stellar transaction, synthesize a \
             minimum-permission OpenZeppelin smart-account policy, evaluate it, and \
             generate reviewable Rust. Deterministic and fail-closed: this server never \
             deploys, signs, or holds keys — code-first, deploy-second. Widening a grant \
             beyond exactly what was observed requires explicit user decisions.",
        )
    }
}

/// Transport is stdio by default (Claude Code, one process in the user's trust domain);
/// `--http <addr>` serves the same handler over streamable HTTP — the transport a hosted,
/// self-hostable endpoint uses (§4.6). The handler is transport-agnostic: both paths wrap
/// the identical `PolicyBuilderServer`.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let registry_trust = configured_registry_trust()?;
    // Parsed before the transport branch so stdio and HTTP are configured identically, and
    // fail-closed: a rejected setting stops startup rather than silently using a default.
    let build_config = ozpb_toolkit::BuildConfig::from_env()?;
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--http") => {
            let addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
            serve_http(&addr, registry_trust, build_config).await
        }
        _ => {
            let service = PolicyBuilderServer::new(registry_trust, None, build_config)
                .serve(rmcp::transport::stdio())
                .await?;
            service.waiting().await?;
            Ok(())
        }
    }
}

fn configured_registry_trust() -> anyhow::Result<Option<ozpb_toolkit::RegistryTrust>> {
    let roots = std::env::var("OZPB_REGISTRY_ROOTS_JSON");
    let minimum = std::env::var("OZPB_REGISTRY_MIN_VERSION");
    match (roots, minimum) {
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => Ok(None),
        (Ok(roots), Ok(minimum)) => {
            let minimum = minimum
                .parse::<u64>()
                .map_err(|error| anyhow::anyhow!("invalid OZPB_REGISTRY_MIN_VERSION: {error}"))?;
            ozpb_toolkit::registry_trust_from_roots_json(&roots, minimum)
                .map(Some)
                .map_err(anyhow::Error::from)
        }
        (Err(error), _) if !matches!(error, std::env::VarError::NotPresent) => {
            Err(anyhow::Error::new(error))
        }
        (_, Err(error)) if !matches!(error, std::env::VarError::NotPresent) => {
            Err(anyhow::Error::new(error))
        }
        _ => Err(anyhow::anyhow!(
            "OZPB_REGISTRY_ROOTS_JSON and OZPB_REGISTRY_MIN_VERSION must be configured together"
        )),
    }
}

/// Parse a bind address and require it to be loopback. Public exposure must go through a
/// TLS-terminating, authenticating reverse proxy; the server itself never binds a routable
/// interface. Extracted so the guard is unit-testable without starting a listener.
fn require_loopback_bind(addr: &str) -> anyhow::Result<std::net::SocketAddr> {
    let socket: std::net::SocketAddr = addr
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid HTTP listen address '{addr}': {error}"))?;
    if !socket.ip().is_loopback() {
        anyhow::bail!(
            "HTTP listener must bind to loopback; terminate TLS at an authenticated reverse proxy"
        );
    }
    Ok(socket)
}

async fn serve_http(
    addr: &str,
    registry_trust: Option<ozpb_toolkit::RegistryTrust>,
    build_config: ozpb_toolkit::BuildConfig,
) -> anyhow::Result<()> {
    use axum::extract::{DefaultBodyLimit, Request, State};
    use axum::http::{header, StatusCode};
    use axum::middleware::{self, Next};
    use axum::response::{IntoResponse, Response};
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpService,
    };
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[derive(Clone)]
    struct HttpSecurity {
        bearer: Arc<str>,
        requests: Arc<Mutex<(Instant, u32)>>,
        max_requests_per_minute: u32,
        concurrency: Arc<tokio::sync::Semaphore>,
    }

    async fn enforce_http_security(
        State(security): State<HttpSecurity>,
        request: Request,
        next: Next,
    ) -> Response {
        let expected = format!("Bearer {}", security.bearer);
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|provided| constant_time_eq(provided.as_bytes(), expected.as_bytes()));
        if !authorized {
            return (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response();
        }

        let within_quota = match security.requests.lock() {
            Ok(mut window) => {
                if window.0.elapsed() >= Duration::from_secs(60) {
                    *window = (Instant::now(), 0);
                }
                if window.1 >= security.max_requests_per_minute {
                    false
                } else {
                    window.1 += 1;
                    true
                }
            }
            Err(_) => false,
        };
        if !within_quota {
            return (StatusCode::TOO_MANY_REQUESTS, "request quota exceeded").into_response();
        }
        let Ok(permit) = security.concurrency.clone().try_acquire_owned() else {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "server concurrency limit reached",
            )
                .into_response();
        };
        let response = next.run(request).await;
        drop(permit);
        response
    }

    fn parse_positive_env(name: &str, default: u32) -> anyhow::Result<u32> {
        match std::env::var(name) {
            Ok(value) => {
                let parsed = value
                    .parse::<u32>()
                    .map_err(|error| anyhow::anyhow!("invalid {name}: {error}"))?;
                if parsed == 0 {
                    anyhow::bail!("{name} must be positive");
                }
                Ok(parsed)
            }
            Err(std::env::VarError::NotPresent) => Ok(default),
            Err(error) => Err(anyhow::Error::new(error)),
        }
    }

    let socket = require_loopback_bind(addr)?;
    let bearer = std::env::var("OZPB_HTTP_BEARER_TOKEN")
        .map_err(|_| anyhow::anyhow!("OZPB_HTTP_BEARER_TOKEN is required for HTTP mode"))?;
    if bearer.len() < 32 {
        anyhow::bail!("OZPB_HTTP_BEARER_TOKEN must contain at least 32 bytes");
    }
    let rpc_allowlist = std::env::var("OZPB_RPC_ALLOWLIST")
        .map_err(|_| anyhow::anyhow!("OZPB_RPC_ALLOWLIST is required for HTTP mode"))?;
    let rpc_policy = RpcEndpointPolicy::from_csv(&rpc_allowlist)?;
    let max_requests = parse_positive_env("OZPB_HTTP_REQUESTS_PER_MINUTE", 60)?;
    // Builds are CPU- and memory-heavy. The request semaphore and Cargo's worker count form one
    // resource budget; validating their product prevents four simultaneous requests from each
    // starting an almost-machine-wide compile. Operators can trade request concurrency for
    // per-build parallelism explicitly.
    let max_concurrency = parse_positive_env("OZPB_HTTP_MAX_CONCURRENCY", 1)?;
    let available_cpus = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let build_workers = usize::try_from(build_config.jobs).unwrap_or(usize::MAX);
    let requested_workers = usize::try_from(max_concurrency)
        .unwrap_or(usize::MAX)
        .checked_mul(build_workers)
        .ok_or_else(|| anyhow::anyhow!("HTTP/build concurrency budget overflows"))?;
    if requested_workers > available_cpus {
        anyhow::bail!(
            "OZPB_HTTP_MAX_CONCURRENCY ({max_concurrency}) × OZPB_BUILD_JOBS ({build_workers}) \
             exceeds available parallelism ({available_cpus})"
        );
    }
    let max_body_bytes = parse_positive_env("OZPB_HTTP_MAX_BODY_BYTES", 1_048_576)? as usize;
    if max_body_bytes > 24 * 1024 * 1024 {
        anyhow::bail!("OZPB_HTTP_MAX_BODY_BYTES must not exceed 25165824");
    }
    let security = HttpSecurity {
        bearer: Arc::from(bearer),
        requests: Arc::new(Mutex::new((Instant::now(), 0))),
        max_requests_per_minute: max_requests,
        concurrency: Arc::new(tokio::sync::Semaphore::new(max_concurrency as usize)),
    };

    let ct = tokio_util::sync::CancellationToken::new();
    let service = StreamableHttpService::new(
        move || {
            Ok(PolicyBuilderServer::new(
                registry_trust.clone(),
                Some(rpc_policy.clone()),
                build_config.clone(),
            ))
        },
        LocalSessionManager::default().into(),
        Default::default(),
    );
    let router = axum::Router::new()
        .nest_service("/v1/mcp", service)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn_with_state(
            security,
            enforce_http_security,
        ));
    let listener = tokio::net::TcpListener::bind(socket).await?;
    eprintln!("ozpb MCP streamable-HTTP endpoint on http://{addr}/v1/mcp");
    let ct2 = ct.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct2.cancel();
        })
        .await?;
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max = left.len().max(right.len());
    for index in 0..max {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_bind_is_required() {
        // Loopback binds (v4 and v6) are accepted.
        assert!(require_loopback_bind("127.0.0.1:8080").is_ok());
        assert!(require_loopback_bind("[::1]:8080").is_ok());
        // Routable interfaces are refused — no accidental public exposure.
        assert!(require_loopback_bind("0.0.0.0:8080").is_err());
        assert!(require_loopback_bind("192.168.1.10:8080").is_err());
        assert!(require_loopback_bind("203.0.113.5:8080").is_err());
        // Garbage is a parse error, not a bind.
        assert!(require_loopback_bind("not-an-addr").is_err());
    }

    #[test]
    fn rpc_allowlist_blocks_ssrf_vectors() {
        let policy = RpcEndpointPolicy::from_csv(
            "https://rpc.testnet.stellar.gateway.fm, https://soroban.example/rpc",
        )
        .unwrap();
        // Exact allowlisted HTTPS endpoints are authorized.
        assert!(policy
            .authorize("https://rpc.testnet.stellar.gateway.fm")
            .is_ok());
        // A host not on the allowlist is refused — including the cloud metadata endpoint,
        // the classic SSRF target.
        assert!(policy.authorize("https://evil.example/rpc").is_err());
        assert!(policy
            .authorize("https://169.254.169.254/latest/meta-data")
            .is_err());
        // Non-HTTPS, credentialed, fragment, or non-web schemes never normalize.
        assert!(policy
            .authorize("http://rpc.testnet.stellar.gateway.fm")
            .is_err());
        assert!(policy
            .authorize("https://user:pass@rpc.testnet.stellar.gateway.fm")
            .is_err());
        assert!(policy
            .authorize("https://rpc.testnet.stellar.gateway.fm#frag")
            .is_err());
        assert!(policy.authorize("file:///etc/passwd").is_err());
    }

    #[test]
    fn rpc_allowlist_must_be_nonempty_and_https() {
        assert!(RpcEndpointPolicy::from_csv("").is_err());
        assert!(RpcEndpointPolicy::from_csv("   ,  ").is_err());
        assert!(RpcEndpointPolicy::from_csv("http://insecure.example").is_err());
    }

    #[test]
    fn constant_time_eq_matches_only_equal_slices() {
        assert!(constant_time_eq(
            b"Bearer secret-token",
            b"Bearer secret-token"
        ));
        // Same length, differing content.
        assert!(!constant_time_eq(
            b"Bearer secret-token",
            b"Bearer wrong-token!"
        ));
        // Different length.
        assert!(!constant_time_eq(b"short", b"a-much-longer-value"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
