//! HTTP API for wallets, peer hubs, and AI agents.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::require_api_token;
use crate::channel_activation::SignedChannelActivationV1;
use crate::channel_state::SignedChannelStateV2;
use crate::config::HubArgs;
use crate::crypto::{BILL_MSG_DOMAIN, PAYMENT_MSG_DOMAIN};
use crate::discover::{build_directory, recommend_for_agent, recommend_for_wallet};
use crate::fullnode::FullnodeClient;
use crate::net::{bootstrap_peer, NetClient};
use crate::state::HubState;
use crate::types::{
    AgentCapabilities, AgentEndpoint, AnnounceRequest, BillRules, BootstrapPeerRequest,
    BootstrapSeedsRequest, CreateDeferredRequest, CreatePaymentRequest, HubStatus,
    PaymentCryptoRules, PaymentRules, PeerHello, ProposeBillRequest, ProposeRebalanceRequest,
    RebalanceStatus, RegisterChannelRequest, RemotePaymentNotify, SignBillRequest,
    SignPaymentRequest,
};

#[derive(Clone)]
pub struct AppState {
    pub args: HubArgs,
    pub fullnode: FullnodeClient,
    pub hub: Arc<HubState>,
    pub net: NetClient,
    /// Durable cross-hub prepare/commit/abort coordinator and participant journal.
    pub distributed: Arc<crate::distributed_tx::DistributedTxManager>,
    pub webhooks: crate::webhook::WebhookClient,
    pub metrics: Arc<crate::metrics::HubMetrics>,
    /// Serializes periodic and request-triggered snapshot replacement.
    pub persist_lock: Arc<tokio::sync::Mutex<()>>,
    pub rate_limit: Arc<crate::ratelimit::RateLimiter>,
}

pub fn router(state: AppState) -> Router {
    let body_limit = state.args.max_body_bytes.max(1024);
    Router::new()
        .route("/", get(root))
        .route("/_server_", get(root))
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/metrics", get(metrics_text))
        .route("/dashboard", get(dashboard_html))
        .route("/v1/wallet/ui", get(wallet_html))
        .route("/v1/seeds", get(community_seeds))
        .route("/v1/l1/submit", post(l1_submit_tx))
        .route("/v1/agent/v1/x402/challenge", post(x402_challenge))
        .route("/v1/agent/v1/x402/verify", post(x402_verify))
        .route("/v1/agent/v1/escrow", post(escrow_create).get(escrow_list))
        .route("/v1/agent/v1/hvm/roadmap", get(hvm_roadmap))
        .route(
            "/v1/agent/v1/micro/:id/settle-summary",
            get(crate::agent_api::micro_settle_summary),
        )
        // channels
        .route("/v1/channels", get(list_channels).post(register_channel))
        .route("/v1/channels/:id", get(get_channel))
        .route("/v1/channels/:id/refresh", post(refresh_channel_from_l1))
        .route(
            "/v1/channels/:id/state-v2/shadow",
            get(get_channel_state_shadow_v2),
        )
        .route("/v1/l1/channel/:id", get(query_l1_channel))
        .route(
            "/v1/channels/:id/l1-exit/readiness",
            get(get_l1_exit_readiness),
        )
        // V3 shadow verification: durable evidence only, no settlement authority.
        .route(
            "/v1/channels/:id/state-v2/observe",
            post(observe_channel_state_v2),
        )
        .route(
            "/v1/channels/:id/state-v2/activation-draft/:state_hash",
            get(get_channel_activation_draft_v1),
        )
        .route(
            "/v1/channels/:id/state-v2/activate",
            post(activate_channel_v2),
        )
        .route(
            "/v1/channels/:id/state-v2/activation",
            get(get_channel_activation_v1),
        )
        .route(
            "/v1/channels/:id/state-v2/observations",
            get(list_channel_state_observations_v2),
        )
        .route(
            "/v1/channels/:id/state-v2/equivocations",
            get(list_channel_state_proofs_v2),
        )
        .route(
            "/v1/channels/:id/state-v2/equivocations/:proof_id",
            get(get_channel_state_proof_v2),
        )
        // Phase C — last reconciliation bill per channel
        .route("/v1/bills", get(list_bills))
        .route("/v1/channels/:id/bill", get(get_bill).post(propose_bill))
        .route("/v1/channels/:id/bill/message", get(bill_message))
        .route("/v1/channels/:id/bill/sign", post(sign_bill))
        .route("/v1/channels/:id/bill/export", get(export_dispute))
        .route("/v1/channels/:id/dispute", get(export_dispute))
        // payments
        .route("/v1/payments", get(list_payments).post(create_payment))
        .route("/v1/payments/:id", get(get_payment))
        .route("/v1/payments/:id/message", get(payment_message))
        .route("/v1/payments/:id/sign", post(sign_payment))
        .route("/v1/payments/:id/fail", post(fail_payment))
        // hub network (global mesh)
        .route("/v1/net/hello", post(net_hello))
        .route("/v1/net/peers", get(net_peers))
        .route("/v1/net/bootstrap", post(net_bootstrap))
        .route("/v1/net/bootstrap/seeds", post(net_bootstrap_seeds))
        .route("/v1/net/announce", post(net_announce))
        .route("/v1/net/graph", get(net_graph))
        .route("/v1/net/fees", get(net_fees))
        .route("/v1/net/capacity", get(net_capacity))
        .route("/v1/net/self", get(net_self_hello))
        .route("/v1/net/payment-notify", post(net_payment_notify))
        .route("/v1/net/foreign-payments", get(net_foreign_payments))
        .route("/v1/net/tx/prepare", post(net_tx_prepare))
        .route("/v1/net/tx/commit", post(net_tx_commit))
        .route("/v1/net/tx/abort", post(net_tx_abort))
        .route("/v1/net/transactions", get(net_distributed_transactions))
        // Whitepaper: rebalance + deferred
        .route(
            "/v1/rebalance",
            get(list_rebalances).post(propose_rebalance),
        )
        .route("/v1/rebalance/:id", get(get_rebalance))
        .route("/v1/rebalance/:id/complete", post(complete_rebalance))
        .route("/v1/rebalance/:id/cancel", post(cancel_rebalance))
        .route("/v1/deferred", get(list_deferred).post(create_deferred))
        .route("/v1/deferred/:id", get(get_deferred))
        .route("/v1/deferred/:id/promote", post(promote_deferred))
        .route("/v1/deferred/:id/cancel", post(cancel_deferred))
        // Phase 3 discovery (wallet Find hubs + AI agent attach)
        .route("/v1/discover", get(discover_hubs))
        .route("/v1/discover/recommend", get(discover_recommend))
        .route("/v1/net/directory", get(net_directory))
        // agent discovery
        .route("/v1/agent/capabilities", get(agent_capabilities))
        .route("/v1/agent/connect", get(agent_connect_hint))
        .route("/v1/agent/start", get(agent_start))
        .route("/v1/agent/intent", post(agent_intent))
        // Hacash Agent Pay Protocol v1 — best path for AI agents
        .route(
            "/v1/agent/v1/manifest",
            get(crate::agent_api::agent_manifest),
        )
        .route("/v1/agent/v1/tools", get(crate::agent_api::agent_tools))
        .route("/v1/agent/v1/quote", post(crate::agent_api::agent_quote))
        .route("/v1/agent/v1/pay", post(crate::agent_api::agent_pay))
        .route("/v1/agent/v1/sign", post(crate::agent_api::agent_sign))
        .route(
            "/v1/agent/v1/payment/:id",
            get(crate::agent_api::agent_payment_status),
        )
        .route("/v1/agent/v1/inbox", get(crate::agent_api::agent_inbox))
        .route(
            "/v1/agent/v1/receipt/:id",
            get(crate::agent_api::agent_receipt),
        )
        .route("/v1/agent/v1/watch/:id", get(crate::agent_api::agent_watch))
        .route(
            "/v1/agent/v1/invoice",
            post(crate::agent_api::agent_create_invoice),
        )
        .route(
            "/v1/agent/v1/invoice/:id",
            get(crate::agent_api::agent_get_invoice),
        )
        .route(
            "/v1/agent/v1/invoice/:id/cancel",
            post(crate::agent_api::agent_cancel_invoice),
        )
        .route(
            "/v1/agent/v1/invoices",
            get(crate::agent_api::agent_list_invoices),
        )
        .route(
            "/v1/agent/v1/pay-invoice",
            post(crate::agent_api::agent_pay_invoice),
        )
        .route(
            "/v1/agent/v1/payment/:id/cancel",
            post(crate::agent_api::agent_cancel_payment),
        )
        .route("/v1/agent/v1/ledger", get(crate::agent_api::agent_ledger))
        .route("/v1/agent/v1/policy", get(crate::agent_api::agent_policy))
        .route(
            "/v1/agent/v1/close-plan/:channel_id",
            get(crate::agent_api::agent_close_plan),
        )
        .route(
            "/v1/agent/v1/openapi.json",
            get(crate::agent_api::agent_openapi),
        )
        // Agent identity
        .route(
            "/v1/agent/v1/identity/register",
            post(crate::agent_api::identity_register),
        )
        .route(
            "/v1/agent/v1/identity/challenge",
            get(crate::agent_api::identity_challenge),
        )
        .route(
            "/v1/agent/v1/identity/verify",
            post(crate::agent_api::identity_verify),
        )
        .route(
            "/v1/agent/v1/identity/:id",
            get(crate::agent_api::identity_get),
        )
        .route(
            "/v1/agent/v1/identity/:id/scopes",
            post(crate::agent_api::identity_set_scopes),
        )
        .route(
            "/v1/agent/v1/identity/:id/revoke",
            post(crate::agent_api::identity_revoke),
        )
        .route(
            "/v1/agent/v1/identities",
            get(crate::agent_api::identity_list),
        )
        // Micropayment streams
        .route(
            "/v1/agent/v1/micro/open",
            post(crate::agent_api::micro_open),
        )
        .route(
            "/v1/agent/v1/micro/push",
            post(crate::agent_api::micro_push),
        )
        .route("/v1/agent/v1/micro/:id", get(crate::agent_api::micro_get))
        .route(
            "/v1/agent/v1/micro/:id/close",
            post(crate::agent_api::micro_close),
        )
        .route("/v1/agent/v1/micro", get(crate::agent_api::micro_list))
        // Amount helpers
        .route(
            "/v1/agent/v1/amounts/normalize",
            post(crate::agent_api::amounts_normalize),
        )
        .route("/v1/address/format", get(address_format_help))
        // Smart UX — wallet & agent (hide multi-step complexity)
        .route("/v1/wallet/start", get(wallet_start))
        .route("/v1/wallet/me", get(wallet_me))
        .route("/v1/wallet/pay", post(wallet_pay))
        .route("/v1/wallet/payment/:id", get(wallet_payment))
        .route("/v1/wallet/sign/:id", post(wallet_sign))
        .route(
            "/v1/wallet/bill/:id",
            get(wallet_bill_get).post(wallet_bill_propose),
        )
        .route("/v1/wallet/bill/:id/sign", post(wallet_bill_sign))
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            durable_checkpoint,
        ))
        .with_state(state)
}

/// Do not acknowledge critical state-changing API calls until their updated
/// snapshot has been flushed and atomically activated. Idempotent retries make
/// the 503 path safe when the in-memory mutation succeeded but disk sync failed.
async fn durable_checkpoint(
    State(st): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let should_checkpoint = requires_durable_checkpoint(request.method(), request.uri().path());
    let response = next.run(request).await;
    if !should_checkpoint || !response.status().is_success() {
        return response;
    }
    let Some(path) = st.args.state_path_opt() else {
        return response;
    };

    let _guard = st.persist_lock.lock().await;
    let hub = st.hub.clone();
    let provider_id = st.args.provider_id.clone();
    let persisted =
        tokio::task::spawn_blocking(move || crate::persist::save_from(&hub, &path, &provider_id))
            .await;
    match persisted {
        Ok(Ok(())) => {
            crate::metrics::HubMetrics::inc(&st.metrics.durable_checkpoints);
            response
        }
        Ok(Err(error)) => {
            crate::metrics::HubMetrics::inc(&st.metrics.durable_checkpoint_failures);
            tracing::error!(%error, "durable checkpoint failed after critical mutation");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "err": "durable_checkpoint_failed",
                    "detail": error,
                    "retryable": true,
                    "warning": "The mutation may exist in memory; retry with the same idempotency key."
                })),
            )
                .into_response()
        }
        Err(error) => {
            crate::metrics::HubMetrics::inc(&st.metrics.durable_checkpoint_failures);
            tracing::error!(%error, "durable checkpoint worker failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "err": "durable_checkpoint_worker_failed",
                    "retryable": true,
                    "warning": "Retry with the same idempotency key."
                })),
            )
                .into_response()
        }
    }
}

fn requires_durable_checkpoint(method: &Method, path: &str) -> bool {
    if !matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        return false;
    }
    [
        "/v1/channels",
        "/v1/bills",
        "/v1/payments",
        "/v1/rebalance",
        "/v1/deferred",
        "/v1/agent/v1/pay",
        "/v1/agent/v1/sign",
        "/v1/agent/v1/invoice",
        "/v1/agent/v1/micro",
        "/v1/agent/v1/identity",
        "/v1/agent/v1/escrow",
        "/v1/wallet/pay",
        "/v1/wallet/sign",
        "/v1/wallet/bill",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}
async fn root(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "service": "hacash-l2-hub",
        "phase": "p0-p4-complete",
        "name": st.args.name,
        "provider_id": st.args.provider_id,
        "public_url": st.args.resolved_public_url(),
        "l2": "channel-chain",
        "easy": {
            "wallet": "GET /v1/wallet/ui or /v1/wallet/start",
            "agent": "GET /v1/agent/v1/manifest",
            "dashboard": "GET /dashboard",
            "metrics": "GET /metrics",
        },
        "features": [
            "hap-pay", "invoices", "micro-streams", "identity", "auto-bill",
            "x402", "webhooks-hmac", "policy", "ledger", "l1-submit",
            "escrow-intent", "seeds", "dashboard",
            "signed-hello", "capacity-advertise", "fee-schedule",
            "rebalance", "deferred-pay", "close-package", "global-mesh",
            "durable-txlog", "distributed-2pc", "l1-incarnation-anchor",
            "channel-state-v2-shadow"
            , "channel-state-v2-negotiated-activation"
            , "l1-exit-capability-gate"
        ],
        "docs": [
            "https://hacash.org/layer-2",
            "GET /v1/agent/v1/manifest",
            "AGENT-PAYMENTS.md",
            "NETWORK-GLOBAL.md",
            "ROADMAP.md",
        ],
        "wallet_entry": "GET /v1/wallet/start",
        "agent_entry": "GET /v1/agent/v1/manifest",
        "agent_protocol": "hacash-agent-pay/1",
    }))
}

async fn metrics_text(State(st): State<AppState>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        format!(
            "{}{}",
            st.metrics
                .render_with_operational(&st.hub.operational_stats()),
            st.distributed.prometheus_metrics(),
        ),
    )
}

async fn dashboard_html() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../static/dashboard.html"),
    )
}

async fn wallet_html() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../static/wallet.html"),
    )
}

async fn community_seeds(State(st): State<AppState>) -> impl IntoResponse {
    let path = if st.args.seeds_path.trim().is_empty() {
        "seeds.example.json".to_string()
    } else {
        st.args.seeds_path.clone()
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => Json(json!({ "ok": true, "path": path, "seeds": v })).into_response(),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "err": e.to_string() })),
            )
                .into_response(),
        },
        Err(_) => Json(json!({
            "ok": true,
            "path": path,
            "seeds": { "version": 1, "seeds": [], "note": "no seeds file; copy seeds.example.json" },
            "local": {
                "provider_id": st.args.provider_id,
                "public_url": st.args.resolved_public_url(),
            }
        }))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct SubmitTxBody {
    tx_hex: String,
    #[serde(default)]
    path: String,
}

async fn l1_submit_tx(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SubmitTxBody>,
) -> impl IntoResponse {
    // Prefer operator api_token; fall back to agent key if only that is set.
    let token = if !st.args.api_token.trim().is_empty() {
        st.args.api_token.as_str()
    } else {
        st.args.agent_api_key.as_str()
    };
    if let Err(r) = require_api_token(&headers, token) {
        return r;
    }
    let path = if body.path.is_empty() {
        st.args.submit_tx_path.clone()
    } else {
        body.path
    };
    match st.fullnode.submit_tx_hex(&body.tx_hex, &path).await {
        Ok(v) => Json(json!({
            "ok": true,
            "result": v,
            "note": "Submitted to fullnode; confirm via explorer/query"
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "err": e,
                "hint": "Fullnode must expose submit path; wallet can broadcast ChannelClose hex"
            })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct X402Body {
    payee: String,
    #[serde(default)]
    amount_hac: String,
    #[serde(default)]
    amount_satoshi: u64,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    invoice_id: String,
}

async fn x402_challenge(
    State(st): State<AppState>,
    Json(body): Json<X402Body>,
) -> impl IntoResponse {
    crate::metrics::HubMetrics::inc(&st.metrics.x402_challenges);
    crate::x402::payment_required(
        &st.args.resolved_public_url(),
        &body.payee,
        &body.amount_hac,
        body.amount_satoshi,
        if body.resource.is_empty() {
            "resource"
        } else {
            &body.resource
        },
        if body.invoice_id.is_empty() {
            None
        } else {
            Some(&body.invoice_id)
        },
    )
}

#[derive(Deserialize)]
struct X402VerifyBody {
    receipt_hash_hex: String,
}

async fn x402_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: Option<Json<X402VerifyBody>>,
) -> impl IntoResponse {
    let hash = body
        .map(|b| b.0.receipt_hash_hex)
        .or_else(|| crate::x402::receipt_from_headers(&headers))
        .unwrap_or_default();
    if hash.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "receipt_hash_hex or X-Hacash-Payment-Receipt required" })),
        )
            .into_response();
    }
    match st.hub.get_receipt_by_hash(&hash) {
        Some(r) if r.status == "settled" => Json(json!({
            "ok": true,
            "verified": true,
            "payment_id": r.payment_id,
            "receipt": r,
            "note": "Hub coordination receipt verified — not L1 final"
        }))
        .into_response(),
        Some(r) => (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "ok": false, "verified": false, "status": r.status })),
        )
            .into_response(),
        None => (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "ok": false, "verified": false, "err": "unknown receipt" })),
        )
            .into_response(),
    }
}

async fn escrow_create(
    State(st): State<AppState>,
    Json(body): Json<crate::hvm_stub::CreateEscrowRequest>,
) -> impl IntoResponse {
    match st.hub.create_escrow(body) {
        Ok(e) => Json(json!({
            "ok": true,
            "escrow": e,
            "hvm": crate::hvm_stub::roadmap(),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn escrow_list(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({ "ok": true, "escrows": st.hub.list_escrows(), "hvm": crate::hvm_stub::roadmap() }))
}

async fn hvm_roadmap() -> impl IntoResponse {
    Json(json!({ "ok": true, "roadmap": crate::hvm_stub::roadmap() }))
}

async fn health(State(st): State<AppState>) -> impl IntoResponse {
    // Hub liveness is always OK if we answer. Fullnode is optional for pure L2 coord.
    let fullnode_ok = st.fullnode.ping_quick().await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "hub_ok": true,
            "fullnode_ok": fullnode_ok,
            "fullnode": st.args.fullnode,
            "provider_id": st.args.provider_id,
            "public_url": st.args.resolved_public_url(),
            "peers": st.hub.peer_counts().0,
            "note": if fullnode_ok {
                "hub + fullnode reachable"
            } else {
                "hub up; fullnode unreachable (L1 query/watch degraded)"
            },
        })),
    )
}

async fn status(State(st): State<AppState>) -> impl IntoResponse {
    let reachable = st.fullnode.ping_quick().await;
    let height = if reachable {
        st.fullnode.latest_height().await.ok()
    } else {
        None
    };
    let (open, settled) = st.hub.payment_counts();
    let (peers, peers_ok) = st.hub.peer_counts();
    let (bills_active, bills_collecting) = st.hub.bill_counts();
    Json(HubStatus {
        name: st.args.name.clone(),
        provider_id: st.args.provider_id.clone(),
        bind: st.args.bind.clone(),
        public_url: st.args.resolved_public_url(),
        fullnode: st.args.fullnode.clone(),
        fullnode_reachable: reachable,
        fullnode_height: height,
        channels_registered: st.hub.channel_count(),
        peers_known: peers,
        peers_reachable: peers_ok,
        payments_open: open,
        payments_settled: settled,
        bills_active,
        bills_collecting,
        l2_model: "channel-chain-instant-payments",
        phase: "global-mesh",
        notes: vec![
            "Anyone can run a hub on a VPS; join via --bootstrap or POST /v1/net/bootstrap",
            "Wallet Find hubs: GET /v1/discover (scored public directory)",
            "AI agents: GET /v1/agent/connect picks best hub; or pin public_url",
            "Multi-hop BFS + ordered multi-sig (payee → … → payer)",
            "No custody — wallets/agents hold keys",
            "status settled = hub-coordinated signatures only — NOT L1 ChannelClose finality",
            "Phase B: payment signatures secp256k1-verified over SHA3-256",
            "Phase C: last reconciliation bill per channel + dispute export (hub does not invent balances)",
            "Global mesh: signed hello, capacity/fees advertise, seeds URL, announce, rebalance, deferred pay, close package",
            "Cross-hub settlement: authenticated durable prepare/commit/abort with crash recovery",
            "See NETWORK-GLOBAL.md, SECURITY.md and HVM-EVOLUTION.md",
        ],
    })
}

/// Wallet "Find available hubs" button — public scored directory.
async fn discover_hubs(State(st): State<AppState>) -> impl IntoResponse {
    let self_peer = st.hub.self_as_peer(
        &st.args.resolved_public_url(),
        &st.args.name,
        st.args.hub_meta(),
    );
    let peers = st.hub.list_peers();
    let mut dir = build_directory(&self_peer, &peers);
    // Wallet list: public + accepts_wallets preferred; still show others ranked lower
    dir.retain(|h| h.meta.public || h.is_self);
    let recommended = recommend_for_wallet(&dir);
    Json(json!({
        "ok": true,
        "purpose": "wallet_find_hubs",
        "count": dir.len(),
        "recommended": recommended,
        "hubs": dir,
        "how_to_connect": "Use recommended.public_url as L2 hub base URL for fast pay",
    }))
}

#[derive(Deserialize)]
struct RecommendQuery {
    /// "agent" (default) or "wallet"
    #[serde(default = "default_role")]
    role: String,
}
fn default_role() -> String {
    "agent".into()
}

async fn discover_recommend(
    State(st): State<AppState>,
    Query(q): Query<RecommendQuery>,
) -> impl IntoResponse {
    let self_peer = st.hub.self_as_peer(
        &st.args.resolved_public_url(),
        &st.args.name,
        st.args.hub_meta(),
    );
    let dir = build_directory(&self_peer, &st.hub.list_peers());
    let rec = if q.role == "wallet" {
        recommend_for_wallet(&dir)
    } else {
        recommend_for_agent(&dir)
    };
    Json(json!({
        "ok": true,
        "role": q.role,
        "recommended": rec,
        "note": "Agents may pin this public_url for the session, or re-query periodically",
    }))
}

async fn net_directory(State(st): State<AppState>) -> impl IntoResponse {
    let self_peer = st.hub.self_as_peer(
        &st.args.resolved_public_url(),
        &st.args.name,
        st.args.hub_meta(),
    );
    let dir = build_directory(&self_peer, &st.hub.list_peers());
    Json(json!({ "ok": true, "directory": dir }))
}

/// Agent attach hint: which hub URL to use and next steps.
async fn agent_connect_hint(State(st): State<AppState>) -> impl IntoResponse {
    // Keep for compatibility; prefer /v1/agent/start
    agent_start(State(st)).await
}

/// Smart agent entry — redirects agents to HAP v1 manifest as primary.
async fn agent_start(State(st): State<AppState>) -> impl IntoResponse {
    let self_peer = st.hub.self_as_peer(
        &st.args.resolved_public_url(),
        &st.args.name,
        st.args.hub_meta(),
    );
    let dir = build_directory(&self_peer, &st.hub.list_peers());
    let rec = recommend_for_agent(&dir);
    let base = rec
        .as_ref()
        .map(|r| r.public_url.clone())
        .unwrap_or_else(|| st.args.resolved_public_url());
    // Prefer full HAP manifest
    let mut manifest =
        crate::agent_pay::agent_manifest(&base, &st.args.provider_id, env!("CARGO_PKG_VERSION"));
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert("ok".into(), json!(true));
        obj.insert("role".into(), json!("ai_agent"));
        obj.insert("attach_to".into(), json!(base));
        obj.insert(
            "recommended".into(),
            serde_json::to_value(&rec).unwrap_or(json!(null)),
        );
        obj.insert(
            "legacy_intent_api".into(),
            json!(format!("POST {base}/v1/agent/intent")),
        );
        obj.insert(
            "primary".into(),
            json!("Use /v1/agent/v1/* for production agent payments"),
        );
    }
    Json(manifest)
}

#[derive(Deserialize)]
struct AgentIntentBody {
    /// pay | me | status | find_hubs | sign | bill
    action: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    amount_hac: String,
    #[serde(default)]
    amount_satoshi: u64,
    #[serde(default)]
    payment_id: String,
    #[serde(default)]
    signature_hex: String,
    #[serde(default)]
    public_key_hex: String,
    #[serde(default)]
    channel_id: String,
    #[serde(default)]
    left_hac: String,
    #[serde(default)]
    right_hac: String,
    #[serde(default)]
    local_only: bool,
}

/// Single brain endpoint for agents: one JSON action → smart result.
async fn agent_intent(
    State(st): State<AppState>,
    Json(body): Json<AgentIntentBody>,
) -> impl IntoResponse {
    let action = body.action.trim().to_ascii_lowercase();
    let base = st.args.resolved_public_url();
    match action.as_str() {
        "find_hubs" | "discover" => {
            let self_peer = st
                .hub
                .self_as_peer(&base, &st.args.name, st.args.hub_meta());
            let dir = build_directory(&self_peer, &st.hub.list_peers());
            let rec = recommend_for_agent(&dir);
            Json(json!({
                "ok": true,
                "action": "find_hubs",
                "recommended": rec,
                "hubs": dir,
                "agent": { "done": true, "next_tool": "wallet_pay_or_me", "state": "hubs_listed" },
                "ui": { "title": "Hubs found", "status_emoji": "📡" },
            }))
            .into_response()
        }
        "me" | "home" | "snapshot" => {
            let addr = if body.address.is_empty() {
                body.from.clone()
            } else {
                body.address.clone()
            };
            if addr.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": "address (or from) required for me" })),
                )
                    .into_response();
            }
            let snap = wallet_snapshot_for(&st, addr.trim());
            Json(json!({ "ok": true, "action": "me", "snapshot": snap })).into_response()
        }
        "pay" | "send" => {
            if body.from.trim().is_empty() || body.to.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": "from and to required" })),
                )
                    .into_response();
            }
            if body.amount_hac.trim().is_empty() && body.amount_satoshi == 0 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": "amount_hac or amount_satoshi required" })),
                )
                    .into_response();
            }
            // The convenience intent endpoint has no idempotency-key contract.
            // Keep it local-only; cross-hub agent payments use /v1/agent/v1/pay.
            let created = st.hub.create_payment(CreatePaymentRequest {
                payer: body.from,
                payee: body.to,
                amount_hac: if body.amount_hac.is_empty() {
                    "0".into()
                } else {
                    body.amount_hac
                },
                amount_satoshi: body.amount_satoshi,
                fee_hac: "0".into(),
                route: vec![],
                local_only: body.local_only,
            });
            match created {
                Ok(candidate) => match prepare_created_payment(&st, candidate).await {
                Ok(p) => {
                    let view = crate::smart::smart_payment_view(&p, &base);
                    Json(json!({
                        "ok": true,
                        "action": "pay",
                        "payment": view,
                        "raw": p,
                    }))
                    .into_response()
                }
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "ok": false,
                        "err": e,
                        "retryable": true,
                    })),
                ).into_response(),
                },
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "ok": false,
                        "err": e,
                        "ui": {
                            "title": "Cannot pay",
                            "subtitle": "No route between addresses, or invalid amount. Open/register channels first.",
                            "status_emoji": "⚠️",
                        },
                        "agent": {
                            "done": false,
                            "next_tool": "register_channel_or_fix_route",
                            "hint": "POST /v1/channels to register L1-open channels on this hub",
                        }
                    })),
                )
                    .into_response(),
            }
        }
        "status" | "payment" => {
            let Ok(id) = Uuid::parse_str(body.payment_id.trim()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": "payment_id uuid required" })),
                )
                    .into_response();
            };
            match st.hub.get_payment(id) {
                Some(p) => {
                    let view = crate::smart::smart_payment_view(&p, &base);
                    Json(json!({ "ok": true, "action": "status", "payment": view })).into_response()
                }
                None => (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "ok": false, "err": "payment not found" })),
                )
                    .into_response(),
            }
        }
        "sign" => {
            let Ok(id) = Uuid::parse_str(body.payment_id.trim()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": "payment_id uuid required" })),
                )
                    .into_response();
            };
            let addr = if body.address.is_empty() {
                body.from.clone()
            } else {
                body.address.clone()
            };
            let signed = st.hub.add_signature(
                id,
                SignPaymentRequest {
                    address: addr,
                    signature_hex: body.signature_hex,
                    public_key_hex: body.public_key_hex,
                },
            );
            match signed {
                Ok(candidate) => match commit_signed_payment(&st, candidate).await {
                    Ok(p) => {
                        let view = crate::smart::smart_payment_view(&p, &base);
                        Json(json!({ "ok": true, "action": "sign", "payment": view }))
                            .into_response()
                    }
                    Err(e) => (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "ok": false, "err": e })),
                    )
                        .into_response(),
                },
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": e })),
                )
                    .into_response(),
            }
        }
        "bill" => {
            if body.channel_id.trim().is_empty() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": "channel_id required" })),
                )
                    .into_response();
            }
            match st.hub.propose_bill(
                &body.channel_id,
                ProposeBillRequest {
                    sequence: 0,
                    left_hac: body.left_hac,
                    right_hac: body.right_hac,
                    left_satoshi: 0,
                    right_satoshi: 0,
                    payment_id: Uuid::parse_str(body.payment_id.trim()).ok(),
                    notes: "agent_intent".into(),
                    signatures: vec![],
                },
            ) {
                Ok(b) => Json(json!({
                    "ok": true,
                    "action": "bill",
                    "bill": crate::smart::smart_bill_view(&b, &base),
                }))
                .into_response(),
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": e })),
                )
                    .into_response(),
            }
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "err": format!("unknown action '{other}'"),
                "allowed": ["find_hubs", "me", "pay", "status", "sign", "bill"],
            })),
        )
            .into_response(),
    }
}

// --- Smart wallet API ---

async fn wallet_start(State(st): State<AppState>) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    let self_peer = st
        .hub
        .self_as_peer(&base, &st.args.name, st.args.hub_meta());
    let dir = build_directory(&self_peer, &st.hub.list_peers());
    let mut public: Vec<_> = dir
        .into_iter()
        .filter(|h| h.meta.public || h.is_self)
        .collect();
    public.retain(|h| h.meta.accepts_wallets || h.is_self);
    let recommended = recommend_for_wallet(&public);
    let attach = recommended
        .as_ref()
        .map(|r| r.public_url.clone())
        .unwrap_or_else(|| base.clone());
    Json(json!({
        "ok": true,
        "role": "wallet",
        "ui": {
            "title": "Find L2 hubs",
            "subtitle": "Pick a hub for instant pay — user does not need to know what a hub is",
            "status_emoji": "🔎",
            "primary_button": "Use recommended",
            "secondary_button": "Show all hubs",
        },
        "recommended": recommended,
        "hubs": public,
        "attach_to": attach,
        "next": {
            "id": "open_home",
            "method": "GET",
            "path": "/v1/wallet/me?address=YOUR_ADDRESS",
            "label": "Continue with my address",
            "detail": "After selecting hub, load wallet home for the user's address",
        },
        "simple_flow": [
            "1. GET /v1/wallet/start (this)",
            "2. GET /v1/wallet/me?address=…",
            "3. POST /v1/wallet/pay {from,to,amount_hac}",
            "4. Sign hash in wallet secure enclave",
            "5. POST /v1/wallet/sign/{id} until ui says complete",
        ],
        "copy_for_user": {
            "find_hubs": "Looking for payment network…",
            "pay": "Send instantly",
            "sign": "Confirm payment",
            "done": "Sent (network confirmed)",
            "done_footnote": "Final blockchain close is separate if you close a channel",
        },
    }))
}

#[derive(Deserialize)]
struct MeQuery {
    address: String,
}

fn wallet_snapshot_for(st: &AppState, address: &str) -> crate::smart::AddressSnapshot {
    let base = st.args.resolved_public_url();
    let channels = st.hub.channels_for_address(address);
    let bills = st.hub.bills_for_address(address);
    let payments = st.hub.payments_for_address(address, 50);
    crate::smart::build_address_snapshot(address, channels, bills, payments, &base)
}

async fn wallet_me(State(st): State<AppState>, Query(q): Query<MeQuery>) -> impl IntoResponse {
    if q.address.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "address query required" })),
        )
            .into_response();
    }
    let snap = wallet_snapshot_for(&st, q.address.trim());
    Json(json!({
        "ok": true,
        "snapshot": snap,
        "copy_for_user": {
            "idle": "Ready to send",
            "need_sign": "Waiting for your confirmation",
            "waiting_other": "Waiting for the other party",
        },
    }))
    .into_response()
}

#[derive(Deserialize)]
struct WalletPayBody {
    /// payer
    from: String,
    /// payee
    to: String,
    #[serde(default)]
    amount_hac: String,
    #[serde(default)]
    amount_satoshi: u64,
    #[serde(default)]
    fee_hac: String,
    #[serde(default)]
    local_only: bool,
    /// optional explicit route
    #[serde(default)]
    route: Vec<String>,
    /// Stable retry key. Required whenever the selected route crosses hubs.
    #[serde(default)]
    idempotency_key: String,
}

async fn wallet_pay(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WalletPayBody>,
) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    let header_key = match request_idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "err": error })),
            )
                .into_response();
        }
    };
    let body_key = body.idempotency_key.trim();
    if !body_key.is_empty()
        && header_key
            .as_deref()
            .is_some_and(|header| header != body_key)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "err": "conflicting body and header idempotency keys",
            })),
        )
            .into_response();
    }
    let idempotency_key = if body_key.is_empty() {
        header_key
    } else {
        Some(body_key.to_string())
    };
    let request = CreatePaymentRequest {
        payer: body.from,
        payee: body.to,
        amount_hac: body.amount_hac,
        amount_satoshi: body.amount_satoshi,
        fee_hac: body.fee_hac,
        route: body.route,
        local_only: body.local_only,
    };
    let namespace = request.payer.clone();
    let created = if let Some(key) = idempotency_key.as_deref() {
        st.hub
            .create_distributed_payment_idempotent(request, key, &namespace)
    } else {
        st.hub
            .create_distributed_payment(request)
            .map(|payment| (payment, false))
    };
    match created {
        Ok((candidate, replayed)) => {
            if !candidate.remote_hops.is_empty() && idempotency_key.is_none() {
                let _ = st.hub.fail_payment(
                    candidate.id,
                    "cross-hub create rejected without an idempotency key",
                );
                return (
                    StatusCode::PRECONDITION_REQUIRED,
                    Json(json!({
                        "ok": false,
                        "err": "Idempotency-Key (or body idempotency_key) is required for cross-hub payments",
                        "retryable": true,
                    })),
                )
                    .into_response();
            }
            match prepare_created_payment(&st, candidate).await {
        Ok(p) => {
            let view = crate::smart::smart_payment_view(&p, &base);
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": replayed,
                    "payment": view,
                    "raw": p,
                    "copy_for_user": {
                        "title": "Confirm payment",
                        "body": format!(
                            "Send {} to {}. Signatures needed: {}.",
                            view.amount_hac, view.payee, view.required_signers.len()
                        ),
                    },
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "err": e,
                "ui": {
                    "title": "Network preparation failed",
                    "subtitle": "No funds were committed. Retry safely.",
                    "status_emoji": "⚠️",
                }
            })),
        ).into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "err": e,
                "ui": {
                    "title": "Cannot send",
                    "subtitle": "No path found between addresses on this network. Open a channel or try another hub.",
                    "status_emoji": "⚠️",
                },
                "agent": {
                    "next_tool": "find_hubs_or_register_channel",
                    "hint": "GET /v1/wallet/start or POST /v1/channels",
                }
            })),
        )
            .into_response(),
    }
}

async fn wallet_payment(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid payment id" })),
        )
            .into_response();
    };
    let base = st.args.resolved_public_url();
    match st.hub.get_payment(uuid) {
        Some(p) => {
            let view = crate::smart::smart_payment_view(&p, &base);
            Json(json!({ "ok": true, "payment": view })).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "payment not found" })),
        )
            .into_response(),
    }
}

async fn wallet_sign(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SignPaymentRequest>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid payment id" })),
        )
            .into_response();
    };
    let base = st.args.resolved_public_url();
    let signed = st.hub.add_signature(uuid, req);
    match signed {
        Ok(candidate) => match commit_signed_payment(&st, candidate).await {
            Ok(p) => {
                let view = crate::smart::smart_payment_view(&p, &base);
                Json(json!({
                "ok": true,
                "payment": view,
                "copy_for_user": if view.agent.done && view.agent.success {
                    json!({ "title": "Sent", "body": "Payment completed on the fast network." })
                } else {
                    json!({
                        "title": "Signature saved",
                        "body": format!("Next: {}", view.next_signer.clone().unwrap_or_else(|| "done".into())),
                    })
                },
            }))
            .into_response()
            }
            Err(e) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "ok": false,
                    "err": e,
                    "retryable": true,
                    "warning": "Do not create a replacement payment when status is committing.",
                })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "err": e,
                "ui": { "title": "Signature rejected", "status_emoji": "❌" },
            })),
        )
            .into_response(),
    }
}

async fn wallet_bill_get(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    match st.hub.get_bill(&id) {
        Some(b) => Json(json!({
            "ok": true,
            "bill": crate::smart::smart_bill_view(&b, &base),
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "err": "no bill yet",
                "next": {
                    "id": "propose_bill",
                    "method": "POST",
                    "path": format!("/v1/wallet/bill/{id}"),
                    "label": "Propose balances",
                }
            })),
        )
            .into_response(),
    }
}

async fn wallet_bill_propose(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ProposeBillRequest>,
) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    match st.hub.propose_bill(&id, req) {
        Ok(b) => Json(json!({
            "ok": true,
            "bill": crate::smart::smart_bill_view(&b, &base),
            "copy_for_user": { "title": "Confirm channel balance", "body": "Both sides must sign." },
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn wallet_bill_sign(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SignBillRequest>,
) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    match st.hub.sign_bill(&id, req) {
        Ok(b) => Json(json!({
            "ok": true,
            "bill": crate::smart::smart_bill_view(&b, &base),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

// --- channels ---

async fn list_channels(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({ "ok": true, "channels": st.hub.list_channels() }))
}

async fn register_channel(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterChannelRequest>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    match st.hub.register_channel(req) {
        Ok(ch) => (StatusCode::OK, Json(json!({ "ok": true, "channel": ch }))).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn get_channel(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.hub.get_channel(&id) {
        Some(ch) => Json(json!({ "ok": true, "channel": ch })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not registered on this hub" })),
        )
            .into_response(),
    }
}

async fn refresh_channel_from_l1(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    if st.hub.get_channel(&id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not registered on this hub" })),
        )
            .into_response();
    }
    match st.fullnode.query_channel_observation(&id).await {
        Ok(observation) => match st
            .hub
            .apply_l1_channel_observation(&id, observation.clone())
        {
            Ok(channel) => Json(json!({
                "ok": true,
                "l1_observation": observation,
                "channel": channel,
                "provenance": "fullnode_state_query",
                "l1_inclusion_proof_verified": false
            }))
            .into_response(),
            Err(error) => (
                StatusCode::CONFLICT,
                Json(json!({ "ok": false, "err": error })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn query_l1_channel(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.fullnode.query_channel(&id).await {
        Ok(v) => Json(json!({ "ok": true, "channel": v })).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}
async fn get_l1_exit_readiness(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some(channel) = st.hub.get_channel(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "channel not registered on this hub" })),
        )
            .into_response();
    };
    let activation = match st.hub.channel_activation_v1(&id) {
        Ok(record) => record,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "err": error })),
            )
                .into_response();
        }
    };
    let capabilities = match st.fullnode.query_exit_capabilities().await {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "ok": false,
                    "err": "fullnode_exit_capabilities_unavailable",
                    "detail": error,
                    "unilateral_l1_enforceable": false,
                    "safe_default": "do_not_construct_or_broadcast_an_exit_transaction"
                })),
            )
                .into_response();
        }
    };
    match crate::l1_exit::build_l1_exit_readiness(&channel, activation.as_ref(), capabilities) {
        Ok(readiness) => Json(json!({
            "ok": true,
            "readiness": readiness,
            "trustless": readiness.unilateral_l1_enforceable,
            "wallet_must_verify_and_sign": true,
            "agent_auto_sign_or_broadcast_allowed": false
        }))
        .into_response(),
        Err(error) => (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "ok": false,
                "err": error,
                "unilateral_l1_enforceable": false
            })),
        )
            .into_response(),
    }
}

// --- V3 channel-state shadow verification ---

async fn get_channel_state_shadow_v2(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.hub.channel_state_shadow_v2(&id) {
        Ok(draft) => Json(json!({
            "ok": true,
            "draft": draft,
            "mode": "unsigned_shadow_migration",
            "requires_fresh_party_signatures": true,
            "l1_anchor_observed": true,
            "l1_inclusion_proof_verified": false,
            "settlement_changed": false
        }))
        .into_response(),
        Err(error) => (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}
async fn get_channel_activation_draft_v1(
    State(st): State<AppState>,
    Path((id, state_hash)): Path<(String, String)>,
) -> impl IntoResponse {
    match st.hub.channel_activation_draft_v1(&id, &state_hash) {
        Ok(draft) => Json(json!({
            "ok": true,
            "draft": draft,
            "mode": "strict_chain_verification_only",
            "requires_both_party_signatures": true,
            "wallet_policy_review_required": true,
            "agent_auto_sign_allowed": false,
            "settlement_authority": false,
            "l1_enforceable": false
        }))
        .into_response(),
        Err(error) => (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

async fn activate_channel_v2(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(certificate): Json<SignedChannelActivationV1>,
) -> impl IntoResponse {
    if let Err(response) = require_api_token(&headers, &st.args.api_token) {
        return response;
    }
    if st.args.state_path_opt().is_none() {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            Json(json!({
                "ok": false,
                "err": "state_path_required",
                "detail": "V2 activation is accepted only with durable persistence enabled"
            })),
        )
            .into_response();
    }
    match st.hub.activate_channel_v2(&id, certificate) {
        Ok(record) => Json(json!({
            "ok": true,
            "activation": record,
            "mode": "strict_chain_verification_only",
            "permanent_for_funding_incarnation": true,
            "settlement_authority": false,
            "l1_enforceable": false
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

async fn get_channel_activation_v1(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.hub.channel_activation_v1(&id) {
        Ok(record) => Json(json!({
            "ok": true,
            "channel_id": id,
            "activated": record.is_some(),
            "activation": record,
            "mode": "strict_chain_verification_only",
            "settlement_authority": false,
            "l1_enforceable": false
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

async fn observe_channel_state_v2(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(state): Json<SignedChannelStateV2>,
) -> impl IntoResponse {
    if st.args.state_path_opt().is_none() {
        return (
            StatusCode::PRECONDITION_REQUIRED,
            Json(json!({
                "ok": false,
                "err": "state_path_required",
                "detail": "V2 observations are accepted only with durable persistence enabled"
            })),
        )
            .into_response();
    }
    match st.hub.observe_channel_state_v2(&id, state) {
        Ok(result) => Json(json!({
            "ok": true,
            "result": result,
            "mode": "shadow_evidence_only",
            "l1_anchor_observed": st.hub.get_channel(&id).and_then(|channel| channel.l1_anchor).is_some(),
            "l1_inclusion_proof_verified": false,
            "settlement_changed": false
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

async fn list_channel_state_observations_v2(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.hub.channel_state_observations_v2(&id) {
        Ok(observations) => Json(json!({
            "ok": true,
            "channel_id": id,
            "count": observations.len(),
            "observations": observations,
            "l1_anchor_observed": st.hub.get_channel(&id).and_then(|channel| channel.l1_anchor).is_some(),
            "l1_inclusion_proof_verified": false,
            "mode": "shadow_evidence_only"
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

async fn list_channel_state_proofs_v2(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match st.hub.channel_state_proofs_v2(&id) {
        Ok(proofs) => {
            let proofs: Vec<_> = proofs
                .into_iter()
                .map(|(proof_id, proof)| json!({ "proof_id": proof_id, "proof": proof }))
                .collect();
            Json(json!({
                "ok": true,
                "channel_id": id,
                "count": proofs.len(),
                "proofs": proofs,
                "l1_enforceable": false,
                "mode": "shadow_evidence_only"
            }))
            .into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

async fn get_channel_state_proof_v2(
    State(st): State<AppState>,
    Path((id, proof_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match st.hub.get_channel_state_proof_v2(&id, &proof_id) {
        Ok(Some(proof)) => Json(json!({
            "ok": true,
            "proof_id": proof_id,
            "proof": proof,
            "l1_enforceable": false,
            "mode": "shadow_evidence_only"
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "equivocation proof not found" })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}
// --- Phase C bills ---

async fn list_bills(State(st): State<AppState>) -> impl IntoResponse {
    let bills = st.hub.list_bills();
    Json(json!({
        "ok": true,
        "count": bills.len(),
        "model": "last_bill_only",
        "bills": bills,
        "note": "Hub stores only the latest bill per channel (whitepaper). Balances are client-submitted.",
    }))
}

async fn get_bill(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.hub.get_bill(&id) {
        Some(b) => Json(json!({ "ok": true, "bill": b })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "err": "no bill for channel — POST a proposal first",
            })),
        )
            .into_response(),
    }
}

async fn propose_bill(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ProposeBillRequest>,
) -> impl IntoResponse {
    // Public: channel parties propose balances; hub does not invent them.
    match st.hub.propose_bill(&id, req) {
        Ok(b) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "bill": b,
                "note": "Both left and right must sign (POST .../bill/sign) before status=active. Previous active bill is replaced (last only).",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn bill_message(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.hub.get_bill(&id) {
        Some(b) => Json(json!({
            "ok": true,
            "channel_id": b.channel_id,
            "sequence": b.sequence,
            "status": b.status,
            "domain": BILL_MSG_DOMAIN,
            "message": b.message,
            "message_hash_hex": b.message_hash_hex,
            "required_signers": b.required_signers,
            "hash_algo": "sha3-256",
            "curve": "secp256k1",
            "sign_wire": "97-byte Sign hex (pubkey||sig) same as payments",
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "no bill for channel" })),
        )
            .into_response(),
    }
}

async fn sign_bill(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SignBillRequest>,
) -> impl IntoResponse {
    match st.hub.sign_bill(&id, req) {
        Ok(b) => {
            let note = if b.status == crate::types::BillStatus::Active {
                "Bill is active — sole last reconciliation credential for this channel on the hub"
            } else {
                "Waiting for remaining party signature"
            };
            Json(json!({ "ok": true, "bill": b, "note": note })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn export_dispute(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.hub.export_dispute(&id, &st.args.fullnode) {
        Ok(pkg) => Json(json!({ "ok": true, "export": pkg })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

// --- payments ---

#[derive(Deserialize)]
struct ListLimit {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    50
}

async fn list_payments(
    State(st): State<AppState>,
    Query(q): Query<ListLimit>,
) -> impl IntoResponse {
    Json(json!({ "ok": true, "payments": st.hub.list_payments(q.limit) }))
}

async fn create_payment(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePaymentRequest>,
) -> impl IntoResponse {
    let idempotency_key = match request_idempotency_key(&headers) {
        Ok(key) => key,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "err": error })),
            )
                .into_response();
        }
    };
    let namespace = req.payer.clone();
    let created = if let Some(key) = idempotency_key.as_deref() {
        st.hub
            .create_distributed_payment_idempotent(req, key, &namespace)
    } else {
        st.hub
            .create_distributed_payment(req)
            .map(|payment| (payment, false))
    };
    match created {
        Ok((candidate, replayed)) => {
            if !candidate.remote_hops.is_empty() && idempotency_key.is_none() {
                let _ = st.hub.fail_payment(
                    candidate.id,
                    "cross-hub create rejected without an idempotency key",
                );
                return (
                    StatusCode::PRECONDITION_REQUIRED,
                    Json(json!({
                        "ok": false,
                        "err": "Idempotency-Key is required for cross-hub payments",
                        "retryable": true,
                    })),
                )
                    .into_response();
            }
            match prepare_created_payment(&st, candidate).await {
        Ok(p) => {
            (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": replayed,
                    "payment": p,
                    "note": "When status becomes settled, that means hub-coordinated ordered signatures only — not L1 ChannelClose. See payment.finality.",
                    "distributed": "cross-hub routes are durably prepared before this response",
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "err": e, "retryable": true })),
        ).into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

fn request_idempotency_key(headers: &HeaderMap) -> Result<Option<String>, String> {
    fn read(headers: &HeaderMap, name: &str) -> Result<Option<String>, String> {
        let Some(value) = headers.get(name) else {
            return Ok(None);
        };
        let value = value
            .to_str()
            .map_err(|_| format!("{name} must be valid ASCII"))?
            .trim();
        Ok((!value.is_empty()).then(|| value.to_string()))
    }

    let standard = read(headers, "idempotency-key")?;
    let legacy = read(headers, "x-idempotency-key")?;
    match (standard, legacy) {
        (Some(left), Some(right)) if left != right => {
            Err("conflicting Idempotency-Key and X-Idempotency-Key headers".into())
        }
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

async fn get_payment(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid payment id" })),
        )
            .into_response();
    };
    match st.hub.get_payment(uuid) {
        Some(p) => Json(json!({ "ok": true, "payment": p })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "payment not found" })),
        )
            .into_response(),
    }
}

/// Phase B: what to sign (canonical message + hash).
async fn payment_message(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid payment id" })),
        )
            .into_response();
    };
    match st.hub.get_payment(uuid) {
        Some(p) => {
            // Recompute from fields so agents always get a consistent V1 message.
            let commit = crate::state::HubState::payment_commit(&p, &st.args.provider_id);
            let message = crate::crypto::canonical_message(&commit);
            let message_hash_hex = crate::crypto::message_hash_hex(&commit);
            Json(json!({
                "ok": true,
                "payment_id": p.id,
                "domain": PAYMENT_MSG_DOMAIN,
                "message": message,
                "message_hash_hex": message_hash_hex,
                "stored_message_hash_hex": p.message_hash_hex,
                "hash_algo": "sha3-256",
                "curve": "secp256k1",
                "required_signers": p.required_signers,
                "signature_order": "payee first → intermediates → payer last",
                "sign_wire": "signature_hex = 97-byte hex (compressed_pubkey[33] || ecdsa_sig[64]) matching Hacash Sign; or 64-byte sig + public_key_hex",
                "how_to": [
                    "1. GET this endpoint (or use payment.message_hash_hex from create)",
                    "2. Sign the 32-byte hash with your Hacash private key (secp256k1, same as L1 txs)",
                    "3. POST /v1/payments/:id/sign with address + signature_hex",
                ],
                "sig_verify_enabled": st.args.sig_verify,
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "payment not found" })),
        )
            .into_response(),
    }
}

async fn sign_payment(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SignPaymentRequest>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid payment id" })),
        )
            .into_response();
    };
    let signed = st.hub.add_signature(uuid, req);
    match signed {
        Ok(candidate) => match commit_signed_payment(&st, candidate).await {
        Ok(p) => {
            Json(json!({
                "ok": true,
                "payment": p,
                "note": "For cross-hub routes, committing means the durable decision is retrying; settled means every participant acknowledged commit.",
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
        },
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct FailBody {
    #[serde(default)]
    reason: String,
}

async fn fail_payment(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<FailBody>>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid payment id" })),
        )
            .into_response();
    };
    let reason = body
        .map(|b| b.0.reason)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "cancelled".into());
    let result = if st.distributed.transaction(uuid).is_some() {
        st.distributed
            .abort_origin(&st.hub, &st.net, uuid, &reason)
            .await
    } else {
        st.hub.fail_payment(uuid, &reason)
    };
    match result {
        Ok(p) => Json(json!({ "ok": true, "payment": p })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

// --- hub network (global mesh) ---

pub(crate) async fn prepare_created_payment(
    state: &AppState,
    payment: crate::types::PaymentSession,
) -> Result<crate::types::PaymentSession, String> {
    if payment.remote_hops.is_empty() {
        return Ok(payment);
    }
    match state
        .distributed
        .prepare_origin(&state.hub, &state.net, &payment)
        .await
    {
        Ok(prepared) => {
            crate::net::spawn_notify_remote_hops(state.net.clone(), prepared.clone());
            Ok(prepared)
        }
        Err(error) => {
            let _ = state
                .hub
                .fail_payment(payment.id, "distributed prepare was not completed");
            Err(error)
        }
    }
}

pub(crate) async fn commit_signed_payment(
    state: &AppState,
    payment: crate::types::PaymentSession,
) -> Result<crate::types::PaymentSession, String> {
    if payment.remote_hops.is_empty() || payment.status != crate::types::PaymentStatus::Committing {
        return Ok(payment);
    }
    let result = state
        .distributed
        .commit_origin_if_ready(&state.hub, &state.net, &payment)
        .await?;
    crate::net::spawn_notify_remote_hops(state.net.clone(), result.clone());
    Ok(result)
}

async fn net_tx_prepare(
    State(state): State<AppState>,
    Json(request): Json<crate::distributed_tx::TxWireRequest>,
) -> impl IntoResponse {
    net_tx_phase(state, crate::distributed_tx::TxPhase::Prepare, request).await
}

async fn net_tx_commit(
    State(state): State<AppState>,
    Json(request): Json<crate::distributed_tx::TxWireRequest>,
) -> impl IntoResponse {
    net_tx_phase(state, crate::distributed_tx::TxPhase::Commit, request).await
}

async fn net_tx_abort(
    State(state): State<AppState>,
    Json(request): Json<crate::distributed_tx::TxWireRequest>,
) -> impl IntoResponse {
    net_tx_phase(state, crate::distributed_tx::TxPhase::Abort, request).await
}

async fn net_tx_phase(
    state: AppState,
    expected_phase: crate::distributed_tx::TxPhase,
    request: crate::distributed_tx::TxWireRequest,
) -> Response {
    if request.phase != expected_phase {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "2pc phase does not match endpoint" })),
        )
            .into_response();
    }
    match state
        .distributed
        .handle_participant_request(&state.hub, &state.net, request)
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(error) => (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "err": error,
                "fail_closed": true,
            })),
        )
            .into_response(),
    }
}

async fn net_distributed_transactions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if state.args.api_token.trim().is_empty() {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "ok": false, "err": "operator api token must be configured" })),
        )
            .into_response();
    }
    if let Err(response) = require_api_token(&headers, &state.args.api_token) {
        return response;
    }
    Json(json!({
        "ok": true,
        "enabled": state.distributed.enabled(),
        "transactions": state.distributed.transactions(),
    }))
    .into_response()
}

async fn net_hello(State(st): State<AppState>, Json(hello): Json<PeerHello>) -> impl IntoResponse {
    if let Err(e) = st.net.validate_inbound_hello(&hello) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e, "hint": "signed hello invalid or too old" })),
        )
            .into_response();
    }
    if let Err(e) = st.hub.upsert_peer_from_hello(&hello, true) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response();
    }
    st.hub.ingest_known_peers(&hello.known_peers);
    let mut meta = st.args.hub_meta();
    meta = st.hub.enrich_meta_capacity(meta);
    let reply =
        st.net
            .hello_payload_with_meta(st.hub.advertise_channels(), st.hub.peer_seeds(), meta);
    Json(json!({
        "ok": true,
        "peer": reply,
        "signed": !reply.signature_hex.is_empty(),
    }))
    .into_response()
}

async fn net_peers(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "provider_id": st.args.provider_id,
        "public_url": st.args.resolved_public_url(),
        "peers": st.hub.list_peers(),
        "capacity": st.hub.capacity_summary(),
        "fees": st.args.fee_schedule(),
    }))
}

async fn net_bootstrap(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BootstrapPeerRequest>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    match bootstrap_peer(&st.net, st.hub.as_ref(), &req.url).await {
        Ok(peer) => Json(json!({ "ok": true, "peer": peer })).into_response(),
        Err(e) => {
            let code = if e.contains("not allowed") || e.contains("only http") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::BAD_GATEWAY
            };
            (code, Json(json!({ "ok": false, "err": e }))).into_response()
        }
    }
}

async fn net_bootstrap_seeds(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BootstrapSeedsRequest>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    let seeds = if !req.url.trim().is_empty() {
        match st.net.fetch_seeds_json(req.url.trim()).await {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "ok": false, "err": e })),
                )
                    .into_response();
            }
        }
    } else if !st.args.seeds_url.trim().is_empty() {
        match st.net.fetch_seeds_json(st.args.seeds_url.trim()).await {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({ "ok": false, "err": e })),
                )
                    .into_response();
            }
        }
    } else {
        let path = if st.args.seeds_path.trim().is_empty() {
            "seeds.example.json".to_string()
        } else {
            st.args.seeds_path.clone()
        };
        match crate::net::load_seeds_file(&path) {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "ok": false, "err": e, "path": path })),
                )
                    .into_response();
            }
        }
    };
    let n = crate::net::bootstrap_seed_list(&st.net, st.hub.as_ref(), &seeds).await;
    Json(json!({
        "ok": true,
        "seeds_loaded": seeds.len(),
        "bootstrapped_ok": n,
        "seeds": seeds,
    }))
    .into_response()
}

async fn net_announce(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AnnounceRequest>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    match crate::net::announce_to(&st.net, st.hub.as_ref(), &req.url).await {
        Ok(peer) => Json(json!({
            "ok": true,
            "announced_to": peer.provider_id,
            "peer": peer,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn net_fees(State(st): State<AppState>) -> impl IntoResponse {
    let schedule = st.args.fee_schedule();
    Json(json!({
        "ok": true,
        "provider_id": st.args.provider_id,
        "schedule": schedule,
        "examples": {
            "1_mei": schedule.estimate_mei(1),
            "100_mei": schedule.estimate_mei(100),
            "1000_mei": schedule.estimate_mei(1000),
        },
        "note": "Fee market is CSP-local; multi-hop may accumulate per-hop hints",
    }))
}

async fn net_capacity(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "provider_id": st.args.provider_id,
        "capacity": st.hub.capacity_summary(),
    }))
}

async fn net_self_hello(State(st): State<AppState>) -> impl IntoResponse {
    let mut meta = st.args.hub_meta();
    meta = st.hub.enrich_meta_capacity(meta);
    let hello =
        st.net
            .hello_payload_with_meta(st.hub.advertise_channels(), st.hub.peer_seeds(), meta);
    Json(json!({
        "ok": true,
        "hello": hello,
        "signed": !hello.signature_hex.is_empty(),
        "identity": {
            "address": hello.identity_address,
            "pubkey_hex": hello.identity_pubkey_hex,
        },
    }))
}

/// Inbound multi-hop payment notify from an origin hub (CSP mesh).
async fn net_payment_notify(
    State(st): State<AppState>,
    Json(n): Json<RemotePaymentNotify>,
) -> impl IntoResponse {
    match st.hub.ingest_remote_payment_notify(n) {
        Ok(fp) => Json(json!({
            "ok": true,
            "foreign": fp,
            "note": "Mirrored for inbox only — sign on origin sign_endpoint, not here",
        }))
        .into_response(),
        Err(e) => {
            let code = if e.contains("not relevant") {
                StatusCode::NOT_ACCEPTABLE
            } else {
                StatusCode::BAD_REQUEST
            };
            (code, Json(json!({ "ok": false, "err": e }))).into_response()
        }
    }
}

async fn net_foreign_payments(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "provider_id": st.args.provider_id,
        "foreign_payments": st.hub.list_foreign_payments(100),
        "note": "Payments owned by other hubs that touch local channels (notify mirrors)",
    }))
}

async fn net_graph(State(st): State<AppState>) -> impl IntoResponse {
    let local = st.hub.list_channels();
    let peers = st.hub.list_peers();
    let edges = crate::route::merge_network_edges(&local, &peers, &st.args.provider_id);
    let edges_json: Vec<_> = edges
        .into_iter()
        .map(|e| {
            json!({
                "channel_id": e.channel_id,
                "a": e.a,
                "b": e.b,
                "via_provider": e.via_provider,
            })
        })
        .collect();
    Json(json!({
        "ok": true,
        "provider_id": st.args.provider_id,
        "edge_count": edges_json.len(),
        "edges": edges_json,
        "fees": st.args.fee_schedule(),
        "capacity": st.hub.capacity_summary(),
    }))
}

// --- rebalance ---

async fn propose_rebalance(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProposeRebalanceRequest>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    match st.hub.propose_rebalance(req) {
        Ok(p) => Json(json!({
            "ok": true,
            "rebalance": p,
            "next": [
                "Parties propose new last bills on both channels reflecting capacity shift",
                "Left+right sign both bills",
                "POST /v1/rebalance/:id/complete when both bills are active",
            ],
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn list_rebalances(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({ "ok": true, "rebalances": st.hub.list_rebalances() }))
}

async fn get_rebalance(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match st.hub.get_rebalance(id) {
        Some(r) => Json(json!({ "ok": true, "rebalance": r })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not found" })),
        )
            .into_response(),
    }
}

async fn complete_rebalance(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    match st.hub.complete_rebalance(id) {
        Ok(r) => Json(json!({ "ok": true, "rebalance": r })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn cancel_rebalance(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if let Err(r) = require_api_token(&headers, &st.args.api_token) {
        return r;
    }
    match st.hub.mark_rebalance_status(id, RebalanceStatus::Cancelled) {
        Ok(r) => Json(json!({ "ok": true, "rebalance": r })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

// --- deferred payments ---

async fn create_deferred(
    State(st): State<AppState>,
    Json(req): Json<CreateDeferredRequest>,
) -> impl IntoResponse {
    match st.hub.create_deferred(req) {
        Ok(d) => Json(json!({ "ok": true, "deferred": d })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn list_deferred(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({ "ok": true, "deferred": st.hub.list_deferred() }))
}

async fn get_deferred(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match st.hub.get_deferred(id) {
        Some(d) => Json(json!({ "ok": true, "deferred": d })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not found" })),
        )
            .into_response(),
    }
}

async fn promote_deferred(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match st.hub.promote_deferred(id) {
        Ok((d, payment)) => Json(json!({
            "ok": true,
            "deferred": d,
            "payment": payment,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

async fn cancel_deferred(State(st): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match st.hub.cancel_deferred(id) {
        Ok(d) => Json(json!({ "ok": true, "deferred": d })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

// --- agent ---

async fn agent_capabilities(State(st): State<AppState>) -> impl IntoResponse {
    Json(AgentCapabilities {
        service: "hacash-l2-hub",
        version: env!("CARGO_PKG_VERSION"),
        phase: "global-mesh",
        provider_id: st.args.provider_id.clone(),
        public_url: st.args.resolved_public_url(),
        capabilities: vec![
            "channel.register",
            "channel.list",
            "channel.l1_incarnation_anchor",
            "channel.state_v2_shadow_unsigned",
            "channel.state_v2_evidence",
            "channel.l1_exit_readiness_fail_closed",
            "channel.state_v2_negotiated_activation",
            "channel.l1_query",
            "bill.propose",
            "bill.sign",
            "bill.last_only",
            "bill.dispute_export",
            "bill.close_package",
            "payment.create_multihop",
            "payment.message",
            "payment.sign_ordered_secp256k1",
            "payment.status",
            "payment.deferred",
            "payment.distributed_2pc",
            "payment.durable_recovery",
            "rebalance.propose",
            "net.hello_signed",
            "net.bootstrap",
            "net.bootstrap_seeds",
            "net.announce",
            "net.peers",
            "net.graph",
            "net.fees",
            "net.capacity",
            "net.payment_notify",
            "net.foreign_payments",
            "discover.hubs",
            "discover.recommend",
            "agent.connect",
            "hub.status",
            "global.vps_mesh",
        ],
        endpoints: vec![
            AgentEndpoint {
                method: "GET",
                path: "/v1/agent/connect",
                purpose: "Which hub URL to attach to + next steps",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/discover",
                purpose: "Wallet Find hubs — scored public directory",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/discover/recommend?role=agent",
                purpose: "Single best hub for agent or wallet",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/net/bootstrap",
                purpose: "Join network: {\"url\":\"http://peer:9090\"}",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/payments",
                purpose: "Multi-hop fast pay; empty route = auto BFS",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/payments/:id/message",
                purpose: "Canonical message + SHA3-256 hash to sign (Phase B)",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/payments/:id/sign",
                purpose: "Ordered multi-sig payee→…→payer; secp256k1 over message_hash",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/channels/:id/bill",
                purpose: "Propose last reconciliation bill (client balances; hub never invents)",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/channels/:id/bill/sign",
                purpose: "Left+right sign bill; becomes active last bill",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/channels/:id/bill/export",
                purpose: "Dispute package for L1 ChannelClose (wallet submits)",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/channels/:id/refresh",
                purpose: "Operator-authorized exact fullnode observation; not an L1 inclusion proof",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/channels/:id/state-v2/shadow",
                purpose: "Unsigned V2 candidate for wallet/policy review; never auto-sign",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/channels/:id/state-v2/observe",
                purpose: "Durably verify party-signed V2 evidence; does not change settlement",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/channels/:id/state-v2/activation-draft/:state_hash",
                purpose: "Canonical opt-in for wallet/policy review; both parties sign, agents never auto-sign",
            },
            AgentEndpoint {
                method: "POST",
                path: "/v1/channels/:id/state-v2/activate",
                purpose: "Operator submits both-party certificate; enables strict verification only",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/channels/:id/state-v2/activation",
                purpose: "Read permanent activation certificate and current mutually signed verification head",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/channels/:id/l1-exit/readiness",
                purpose: "Query actual L1 action codecs and fail closed before wallet signing or broadcast",
            },
            AgentEndpoint {
                method: "GET",
                path: "/v1/agent/capabilities",
                purpose: "This document",
            },
        ],
        payment_rules: PaymentRules {
            signature_order: "payee first, then intermediates along the path, payer last",
            settle_when: "all required_signers posted verified signatures in order → status=settled (hub-coordinated only)",
            finality: "hub settled ≠ L1 final; L1 finality only via ChannelClose/arbitration on fullnode",
            multi_hop: true,
            hub_network: true,
            custody: "none — wallets hold keys; hub only coordinates",
            crypto: PaymentCryptoRules {
                domain: PAYMENT_MSG_DOMAIN,
                hash: "sha3-256 over canonical UTF-8 message (see GET /v1/payments/:id/message)",
                curve: "secp256k1 (same as Hacash L1 Account)",
                sign_wire: "97-byte hex Sign = compressed_pubkey[33] || ecdsa_sig[64]; or 64-byte sig + public_key_hex",
                how_to_sign: "Sign payment.message_hash_hex (32 raw bytes) with Account::do_sign / wallet; POST address + signature_hex",
            },
        },
        bill_rules: BillRules {
            model: "channel-chain last reconciliation bill only (whitepaper)",
            storage: "one bill per channel_id; higher sequence replaces previous",
            activate_when: "both left and right secp256k1-signed bill.message_hash",
            hub_role: "backup + coordinate — never invent balances, never custody keys",
            dispute: "GET /v1/channels/:id/bill/export → wallet builds L1 close/arbitration",
            domain: BILL_MSG_DOMAIN,
        },
    })
}

async fn address_format_help(State(st): State<AppState>) -> impl IntoResponse {
    let pid = &st.args.provider_id;
    Json(json!({
        "provider_id": pid,
        "public_url": st.args.resolved_public_url(),
        "full_form": format!("1YourAddress_CHANNELID64HEX_{pid}"),
        "short_form": format!("1YourAddress_{pid}"),
        "example": format!("1PytoNB53MX2bi1Nw2S6Fyharzv4zGTDDD_4d295889c6e0e1fc64237e01cd480fd6_{pid}"),
        "note": "Anyone can run a hub with a unique provider_id and join via /v1/net/bootstrap",
        "l1_query": "/query/channel?id=<hex>",
    }))
}

#[cfg(test)]
mod durable_checkpoint_tests {
    use super::*;

    #[test]
    fn checkpoints_only_critical_mutating_routes() {
        assert!(requires_durable_checkpoint(
            &Method::POST,
            "/v1/agent/v1/pay"
        ));
        assert!(requires_durable_checkpoint(
            &Method::POST,
            "/v1/payments/00000000-0000-0000-0000-000000000001/sign"
        ));
        assert!(requires_durable_checkpoint(
            &Method::POST,
            "/v1/channels/00112233445566778899aabbccddeeff/state-v2/observe"
        ));
        assert!(requires_durable_checkpoint(
            &Method::POST,
            "/v1/channels/00112233445566778899aabbccddeeff/state-v2/activate"
        ));
        assert!(requires_durable_checkpoint(
            &Method::POST,
            "/v1/channels/00112233445566778899aabbccddeeff/refresh"
        ));
        assert!(!requires_durable_checkpoint(
            &Method::GET,
            "/v1/channels/00112233445566778899aabbccddeeff/state-v2/shadow"
        ));
        assert!(!requires_durable_checkpoint(&Method::GET, "/v1/payments"));
        assert!(!requires_durable_checkpoint(&Method::POST, "/v1/net/hello"));
    }
}
