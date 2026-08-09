//! HTTP handlers for Hacash Agent Pay Protocol (HAP) v1.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::auth::require_api_token;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::agent_pay::{
    self, build_inbox, envelope_err, envelope_from_payment, envelope_from_payment_for,
    AgentPayRequest, AgentSignRequest, HAP_PROTOCOL,
};
use crate::api::AppState;
use crate::state::HubState;
use crate::types::{CreatePaymentRequest, SignPaymentRequest};

#[derive(Deserialize)]
pub struct QuoteBody {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub route: Vec<String>,
}

#[derive(Deserialize)]
pub struct InboxQuery {
    pub address: String,
}

pub async fn agent_manifest(State(st): State<AppState>) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    Json(agent_pay::agent_manifest(
        &base,
        &st.args.provider_id,
        env!("CARGO_PKG_VERSION"),
    ))
}

pub async fn agent_tools(State(st): State<AppState>) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    Json(json!({
        "ok": true,
        "protocol": HAP_PROTOCOL,
        "tools": agent_pay::agent_tools_schema(&base),
        "note": "OpenAI-style function tools with x_http bindings for agent frameworks",
    }))
}

pub async fn agent_quote(
    State(st): State<AppState>,
    Json(body): Json<QuoteBody>,
) -> impl IntoResponse {
    let schedule = st.args.fee_schedule();
    match st.hub.quote_payment_with_fees(
        &body.from,
        &body.to,
        &body.amount_hac,
        body.amount_satoshi,
        body.local_only,
        &body.route,
        &schedule,
    ) {
        Ok(q) => Json(json!({
            "ok": true,
            "protocol": HAP_PROTOCOL,
            "quote": q,
            "machine": {
                "state": if q.can_pay { "quoted" } else { "no_route" },
                "done": true,
                "success": q.can_pay,
                "retryable": !q.can_pay,
                "next_poll_ms": 0
            },
            "next": if q.can_pay {
                json!({
                    "tool": "hacash_agent_pay",
                    "hint": "Call pay with same from/to/amount and a unique idempotency_key; omit fee_hac to use quote.fee_hac_estimate"
                })
            } else {
                json!({
                    "tool": "register_channel_or_find_hubs",
                    "hint": "No route — open/register channels or try another hub"
                })
            }
        }))
        .into_response(),
        Err(e) => {
            let env = envelope_err("no_route", &e, true);
            (StatusCode::BAD_REQUEST, Json(env)).into_response()
        }
    }
}

pub async fn agent_pay(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AgentPayRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    let base = st.args.resolved_public_url();
    let request_id = Uuid::new_v4().to_string();

    // Verified identity: require proof of registration + bind HTTP rate limit to v:address
    let claimed_agent = body.meta.agent_id.trim();
    if let Some(identity) = st.hub.get_identity(claimed_agent) {
        if identity.revoked {
            let env = envelope_err("agent_identity_revoked", "agent identity revoked", false);
            return (StatusCode::UNAUTHORIZED, Json(env)).into_response();
        }
        if identity.verified && !identity.allows("pay") {
            let env = envelope_err(
                "agent_scope_denied",
                "agent identity lacks the 'pay' scope",
                false,
            );
            return (StatusCode::FORBIDDEN, Json(env)).into_response();
        }
    }
    if st.args.require_verified_agent {
        match st.hub.get_identity(claimed_agent) {
            Some(id) if id.allows("pay") => {
                if let Err(e) = st.rate_limit.check(&format!("v:{}", id.address)) {
                    crate::metrics::HubMetrics::inc(&st.metrics.rate_limited);
                    let env = envelope_err("rate_limited", &e, true);
                    return (StatusCode::TOO_MANY_REQUESTS, Json(env)).into_response();
                }
            }
            _ => {
                let env = envelope_err(
                    "policy_denied",
                    "require_verified_agent: register+verify agent_id first",
                    false,
                );
                return (StatusCode::UNAUTHORIZED, Json(env)).into_response();
            }
        }
    } else if !claimed_agent.is_empty() {
        // Best-effort: if this agent_id is already verified, still bind rate limit to address
        if let Some(id) = st.hub.get_identity(claimed_agent) {
            if id.verified {
                if let Err(e) = st.rate_limit.check(&format!("v:{}", id.address)) {
                    crate::metrics::HubMetrics::inc(&st.metrics.rate_limited);
                    let env = envelope_err("rate_limited", &e, true);
                    return (StatusCode::TOO_MANY_REQUESTS, Json(env)).into_response();
                }
            }
        }
    }

    if body.idempotency_key.trim().is_empty() {
        let env = envelope_err(
            "missing_idempotency_key",
            "idempotency_key is required for agent pay (safe retries)",
            false,
        );
        return (StatusCode::BAD_REQUEST, Json(env)).into_response();
    }
    if body.amount_hac.trim().is_empty() && body.amount_satoshi == 0 {
        let env = envelope_err(
            "invalid_amount",
            "amount_hac or amount_satoshi required",
            false,
        );
        return (StatusCode::BAD_REQUEST, Json(env)).into_response();
    }

    let invoice_id = if body.invoice_id.trim().is_empty() {
        None
    } else {
        match Uuid::parse_str(body.invoice_id.trim()) {
            Ok(u) => Some(u),
            Err(_) => {
                let env = envelope_err("invoice_invalid", "invoice_id must be uuid", false);
                return (StatusCode::BAD_REQUEST, Json(env)).into_response();
            }
        }
    };

    // Empty fee_hac → hub CSP schedule (same as quote.fee_hac_estimate). Explicit "0" stays "0".
    let amount_hac = if body.amount_hac.trim().is_empty() {
        "0".to_string()
    } else {
        match crate::amounts::normalize_hac(&body.amount_hac) {
            Ok(amount) => amount,
            Err(e) => {
                let env = envelope_err("invalid_amount", &e, false);
                return (StatusCode::BAD_REQUEST, Json(env)).into_response();
            }
        }
    };
    let fee_hac = match crate::agent_pay::resolve_fee_hac(
        &body.fee_hac,
        &amount_hac,
        &st.args.fee_schedule(),
    ) {
        Ok(fee) => fee,
        Err(e) => {
            let env = envelope_err("invalid_fee", &e, false);
            return (StatusCode::BAD_REQUEST, Json(env)).into_response();
        }
    };

    let proof_required = st.args.require_verified_agent;
    let proof_supplied = !body.intent.signature_hex.trim().is_empty();
    let intent_claim = if proof_required || proof_supplied {
        let identity = match st.hub.get_identity(claimed_agent) {
            Some(identity) if identity.allows("pay") => identity,
            _ => {
                let env = envelope_err(
                    "agent_intent_identity",
                    "signed intent requires a verified agent identity",
                    false,
                );
                return (StatusCode::UNAUTHORIZED, Json(env)).into_response();
            }
        };
        let message = match crate::agent_pay::agent_intent_message(
            &st.args.provider_id,
            claimed_agent,
            &body.from,
            &body.to,
            &amount_hac,
            body.amount_satoshi,
            &fee_hac,
            &body.route,
            &body.invoice_id,
            &body.idempotency_key,
            &body.intent.nonce,
            body.intent.expires_unix,
        ) {
            Ok(message) => message,
            Err(e) => {
                let env = envelope_err("agent_intent_invalid", &e, false);
                return (StatusCode::BAD_REQUEST, Json(env)).into_response();
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Err(e) =
            crate::agent_pay::verify_agent_intent(&identity.address, &body.intent, &message, now)
        {
            let env = envelope_err("agent_intent_invalid", &e, false);
            return (StatusCode::UNAUTHORIZED, Json(env)).into_response();
        }
        let claimed_new = match st.hub.claim_agent_intent(
            claimed_agent,
            &body.intent.nonce,
            &body.idempotency_key,
            body.intent.expires_unix,
        ) {
            Ok(claimed_new) => claimed_new,
            Err(e) => {
                let env = envelope_err("agent_intent_replay", &e, false);
                return (StatusCode::CONFLICT, Json(env)).into_response();
            }
        };
        Some((
            claimed_agent.to_string(),
            body.intent.nonce.clone(),
            body.idempotency_key.clone(),
            claimed_new,
        ))
    } else {
        None
    };

    let req = CreatePaymentRequest {
        payer: body.from,
        payee: body.to,
        amount_hac,
        amount_satoshi: body.amount_satoshi,
        fee_hac,
        route: body.route,
        local_only: body.local_only,
    };

    let viewer = req.payer.clone();
    let create_result = st.hub.agent_create_distributed_payment_ex(
        req,
        &body.idempotency_key,
        body.meta.clone(),
        invoice_id,
        &body.callback_url,
    );
    if create_result.is_err() {
        if let Some((agent_id, nonce, idempotency_key, true)) = &intent_claim {
            st.hub
                .release_agent_intent(agent_id, nonce, idempotency_key);
        }
    }
    match create_result {
        Ok((candidate, replay)) => {
            let p = if replay {
                candidate
            } else {
                match crate::api::prepare_created_payment(&st, candidate).await {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        if let Some((agent_id, nonce, idempotency_key, true)) = &intent_claim {
                            st.hub
                                .release_agent_intent(agent_id, nonce, idempotency_key);
                        }
                        let env = envelope_err("distributed_prepare_failed", &error, true);
                        return (StatusCode::BAD_GATEWAY, Json(env)).into_response();
                    }
                }
            };
            if !replay {
                crate::metrics::HubMetrics::inc(&st.metrics.payments_created);
            }
            let mut env = envelope_from_payment_for(
                &p,
                &base,
                &request_id,
                Some(&body.meta),
                replay,
                Some(&viewer),
            );
            env.request_id = request_id;
            if replay {
                env.human.detail = format!("{} (idempotent replay)", env.human.detail);
            }
            if !p.remote_hops.is_empty() {
                env.result["remote_hops"] =
                    serde_json::to_value(&p.remote_hops).unwrap_or(json!([]));
                env.result["remote_notify"] = json!({
                    "mode": "origin_authority",
                    "hint": "Remote hubs receive inbox mirrors; always sign on this origin hub",
                });
            }
            Json(env).into_response()
        }
        Err(e) => {
            let code = if e.contains("path") || e.contains("route") || e.contains("not found") {
                "no_route"
            } else if e.contains("idempotency") {
                "idempotency_conflict"
            } else if e.contains("allowlist") || e.contains("exceeds") || e.contains("rate limit") {
                "policy_denied"
            } else if e.contains("invoice amount mismatch") {
                "invoice_amount_mismatch"
            } else if e.contains("invoice") {
                "invoice_invalid"
            } else {
                "pay_failed"
            };
            let env = envelope_err(code, &e, code == "no_route");
            (StatusCode::BAD_REQUEST, Json(env)).into_response()
        }
    }
}

pub async fn agent_sign(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AgentSignRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    let base = st.args.resolved_public_url();
    let request_id = Uuid::new_v4().to_string();
    let Ok(id) = Uuid::parse_str(body.payment_id.trim()) else {
        let env = envelope_err("not_found", "invalid payment_id", false);
        return (StatusCode::BAD_REQUEST, Json(env)).into_response();
    };
    let viewer = body.address.clone();
    match st.hub.add_signature(
        id,
        SignPaymentRequest {
            address: body.address,
            signature_hex: body.signature_hex,
            public_key_hex: body.public_key_hex,
        },
    ) {
        Ok(candidate) => {
            let p = match crate::api::commit_signed_payment(&st, candidate).await {
                Ok(payment) => payment,
                Err(error) => {
                    let env = envelope_err("distributed_commit_pending", &error, true);
                    return (StatusCode::SERVICE_UNAVAILABLE, Json(env)).into_response();
                }
            };
            let meta = st.hub.get_payment_meta(id);
            let mut env = envelope_from_payment_for(
                &p,
                &base,
                &request_id,
                Some(&meta),
                false,
                Some(&viewer),
            );
            if p.status == crate::types::PaymentStatus::Settled {
                crate::metrics::HubMetrics::inc(&st.metrics.payments_settled);
                if let Some(r) = st.hub.get_receipt(id) {
                    env.result["receipt"] = serde_json::to_value(&r).unwrap_or(json!({}));
                    fire_payment_webhook(&st, id, "payment.settled", &r.status).await;
                }
                if st.args.auto_bill {
                    // Idempotent: balances already shifted inside add_signature settle path
                    if let Ok(bills) = st.hub.auto_bill_after_settle(&p) {
                        if !bills.is_empty() {
                            env.result["auto_bills"] = json!(bills
                                .iter()
                                .map(|b| json!({
                                    "channel_id": b.channel_id,
                                    "sequence": b.sequence,
                                    "status": b.status,
                                    "left_hac": b.left_hac,
                                    "right_hac": b.right_hac,
                                }))
                                .collect::<Vec<_>>());
                            env.result["balances_note"] =
                                json!("Hub channel balances updated for routing (balance_source=payment_settle). Active bill still required for L1 close evidence.");
                        }
                    }
                    // Snapshot post-settle channel balances on route
                    let chs: Vec<_> = p
                        .route
                        .iter()
                        .filter_map(|cid| st.hub.get_channel(cid))
                        .map(|c| {
                            json!({
                                "channel_id": c.channel_id,
                                "left_hac": c.left_hac,
                                "right_hac": c.right_hac,
                                "left_satoshi": c.left_satoshi,
                                "right_satoshi": c.right_satoshi,
                                "balance_source": c.balance_source,
                            })
                        })
                        .collect();
                    if !chs.is_empty() {
                        env.result["channel_balances"] = json!(chs);
                    }
                }
            }
            Json(env).into_response()
        }
        Err(e) => {
            let code = if e.contains("order") {
                "wrong_order"
            } else if e.contains("signature") || e.contains("address mismatch") {
                "bad_signature"
            } else if e.contains("timed out") || e.contains("expired") {
                "expired"
            } else if e.contains("not found") {
                "not_found"
            } else {
                "sign_failed"
            };
            let env = envelope_err(code, &e, false);
            (StatusCode::BAD_REQUEST, Json(env)).into_response()
        }
    }
}

pub async fn agent_payment_status(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    let request_id = Uuid::new_v4().to_string();
    let Ok(uuid) = Uuid::parse_str(&id) else {
        let env = envelope_err("not_found", "invalid payment id", false);
        return (StatusCode::BAD_REQUEST, Json(env)).into_response();
    };
    match st.hub.get_payment(uuid) {
        Some(p) => {
            let meta = st.hub.get_payment_meta(uuid);
            let mut env = envelope_from_payment(&p, &base, &request_id, Some(&meta), false);
            if env.machine.done {
                if let Some(r) = st.hub.get_receipt(uuid) {
                    env.result["receipt"] = serde_json::to_value(r).unwrap_or(json!({}));
                }
            }
            Json(env).into_response()
        }
        None => {
            let env = envelope_err("not_found", "payment not found", false);
            (StatusCode::NOT_FOUND, Json(env)).into_response()
        }
    }
}

pub async fn agent_inbox(
    State(st): State<AppState>,
    Query(q): Query<InboxQuery>,
) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    if q.address.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "address required" })),
        )
            .into_response();
    }
    let payments = st.hub.payments_for_address(q.address.trim(), 100);
    let metas = st.hub.all_payment_metas();
    let items = build_inbox(q.address.trim(), &payments, &base, &metas);
    let local_count = items.len();
    // Foreign notifications are not authenticated or canonically bound yet.
    // Never turn their caller-supplied hash/endpoint into an automatic signing task.
    let foreign_count = 0usize;
    Json(json!({
        "ok": true,
        "protocol": HAP_PROTOCOL,
        "address": q.address.trim(),
        "count": items.len(),
        "local_count": local_count,
        "foreign_count": foreign_count,
        "foreign_signing_disabled": true,
        "inbox": items,
        "machine": {
            "state": if items.is_empty() { "idle" } else { "work_available" },
            "done": false,
            "success": true,
            "retryable": true,
            "next_poll_ms": if items.is_empty() { 3000 } else { 500 }
        },
        "agent_hint": if items.is_empty() {
            "No signatures required from this address. You may quote/pay or wait."
        } else {
            "Review local items before signing. Outbound and intermediary payments require explicit application approval."
        }
    }))
    .into_response()
}

/// Agent-friendly L1 ChannelClose plan (evidence only — no custody / no unsigned wire encode).
pub async fn agent_close_plan(
    State(st): State<AppState>,
    Path(channel_id): Path<String>,
) -> impl IntoResponse {
    match st.hub.export_dispute(&channel_id, &st.args.fullnode) {
        Ok(exp) => {
            let plan = crate::close_plan::build_agent_close_plan(&exp);
            let evidence_ready = plan
                .get("evidence_complete")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Json(json!({
                "ok": true,
                "protocol": HAP_PROTOCOL,
                "close_plan": plan,
                "export": exp,
                "machine": {
                    "state": if evidence_ready { "evidence_ready_l1_capability_check_required" } else { "need_active_bill" },
                    "done": false,
                    "success": false,
                    "retryable": true,
                    "next_poll_ms": if evidence_ready { 0 } else { 3000 }
                },
                "agent_hint": if evidence_ready {
                    "Fetch /v1/channels/:id/l1-exit/readiness. Never auto-sign or broadcast; current action 3 returns original L1 funding, not the negotiated distribution."
                } else {
                    "Propose+sign last bill until bill_active; re-fetch close-plan"
                }
            }))
            .into_response()
        }
        Err(e) => {
            let env = envelope_err("close_plan_failed", &e, false);
            (StatusCode::BAD_REQUEST, Json(env)).into_response()
        }
    }
}

pub async fn agent_receipt(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    match st.hub.get_receipt(uuid) {
        Some(r) => Json(json!({
            "ok": true,
            "protocol": HAP_PROTOCOL,
            "receipt": r,
            "machine": {
                "state": "receipt",
                "done": true,
                "success": r.status == "settled",
                "retryable": false,
                "next_poll_ms": 0
            },
            "store": "Persist receipt_hash_hex for audit; not L1 finality"
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "err": "no receipt yet — payment not terminal (settled/failed/timeout)",
                "protocol": HAP_PROTOCOL
            })),
        )
            .into_response(),
    }
}

/// SSE stream of machine envelopes until payment is done (or ~2 min).
pub async fn agent_watch(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Sse<std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>>> {
    let hub = st.hub.clone();
    let base = st.args.resolved_public_url();
    let stream: std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> =
        match Uuid::parse_str(&id) {
            Ok(uuid) => Box::pin(watch_stream(hub, base, uuid)),
            Err(_) => Box::pin(stream::iter(vec![Ok(Event::default()
                .event("error")
                .data("invalid payment id"))])),
        };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

async fn fire_payment_webhook(st: &AppState, payment_id: Uuid, event: &str, status: &str) {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let meta = st.hub.get_payment_meta(payment_id);
    let invoice_id = if meta.invoice_id.is_empty() {
        None
    } else {
        Some(meta.invoice_id.clone())
    };
    let mut urls: Vec<String> = Vec::new();
    if let Some(u) = st.hub.get_payment_callback(payment_id) {
        if !u.is_empty() {
            urls.push(u);
        }
    }
    if let Some(ref iid) = invoice_id {
        if let Ok(uid) = Uuid::parse_str(iid) {
            if let Some(inv) = st.hub.get_invoice(uid) {
                if !inv.callback_url.is_empty() && !urls.contains(&inv.callback_url) {
                    urls.push(inv.callback_url);
                }
            }
        }
    }
    if urls.is_empty() {
        return;
    }
    let ev = crate::webhook::WebhookEvent {
        protocol: HAP_PROTOCOL,
        event: event.into(),
        payment_id: Some(payment_id.to_string()),
        invoice_id,
        status: status.into(),
        ts_unix: ts,
        detail: json!({ "agent_id": meta.agent_id }),
    };
    for url in urls {
        let ok = st.webhooks.post_json(&url, &ev).await;
        if ok {
            crate::metrics::HubMetrics::inc(&st.metrics.webhooks_sent);
        } else {
            crate::metrics::HubMetrics::inc(&st.metrics.webhooks_failed);
        }
    }
}

/// Rate limit + optional agent API key + metrics for agent mutators.
///
/// Always rate-limits by connect key (`ip_hint`). If `X-Hacash-Agent-Id` names a
/// **verified** identity, also rate-limits by `v:{address}` (cannot rotate agent_id).
pub fn agent_gate(st: &AppState, headers: &HeaderMap, ip_hint: &str) -> Result<(), Response> {
    crate::metrics::HubMetrics::inc(&st.metrics.agent_requests);
    if let Err(e) = st.rate_limit.check(&format!("ip:{ip_hint}")) {
        crate::metrics::HubMetrics::inc(&st.metrics.rate_limited);
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(json!({ "ok": false, "err": e, "code": "rate_limited" })),
        )
            .into_response());
    }
    // Optional header bind (spoofable if unverified — only enforced when verified)
    if let Some(aid) = headers
        .get("x-hacash-agent-id")
        .or_else(|| headers.get("x-agent-id"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(id) = st.hub.get_identity(aid) {
            if id.revoked {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({
                        "ok": false,
                        "err": "agent identity revoked",
                        "code": "agent_identity_revoked"
                    })),
                )
                    .into_response());
            }
            if id.verified {
                if let Err(e) = st.rate_limit.check(&format!("v:{}", id.address)) {
                    crate::metrics::HubMetrics::inc(&st.metrics.rate_limited);
                    return Err((
                        StatusCode::TOO_MANY_REQUESTS,
                        axum::Json(json!({
                            "ok": false,
                            "err": e,
                            "code": "rate_limited",
                            "principal": format!("v:{}", id.address),
                        })),
                    )
                        .into_response());
                }
            }
        }
    }
    if !st.args.agent_api_key.trim().is_empty() {
        if let Err(r) = require_api_token(headers, &st.args.agent_api_key) {
            return Err(r);
        }
    }
    Ok(())
}

/// Rate-limit key. X-Forwarded-For only trusted when `trust_proxy` is set (behind reverse proxy).
fn client_ip(st: &AppState, headers: &HeaderMap) -> String {
    if st.args.trust_proxy {
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return format!("xff:{xff}");
        }
        if let Some(real) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            return format!("xri:{real}");
        }
    }
    // Untrusted: do not allow client to pick rate-limit bucket via spoofed XFF
    "direct".into()
}

// --- Invoices / policy / openapi ---

pub async fn agent_create_invoice(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::invoice::CreateInvoiceRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    match st.hub.create_invoice(body) {
        Ok(inv) => {
            crate::metrics::HubMetrics::inc(&st.metrics.invoices_created);
            Json(json!({
            "ok": true,
            "protocol": HAP_PROTOCOL,
            "invoice": inv,
            "pay_hint": {
                "method": "POST",
                "path": "/v1/agent/v1/pay-invoice",
                "body": {
                    "invoice_id": inv.id,
                    "from": if inv.payer_hint.is_empty() { "<payer_address>".into() } else { inv.payer_hint.clone() },
                    "idempotency_key": "<unique>"
                }
            },
            "machine": { "state": "invoice_open", "done": false, "success": true }
        }))
        .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e, "protocol": HAP_PROTOCOL })),
        )
            .into_response(),
    }
}

pub async fn agent_get_invoice(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    match st.hub.get_invoice(uuid) {
        Some(inv) => Json(json!({ "ok": true, "invoice": inv })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not found" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ListInvoicesQuery {
    pub address: String,
    #[serde(default = "default_inv_limit")]
    pub limit: usize,
}
fn default_inv_limit() -> usize {
    50
}

pub async fn agent_list_invoices(
    State(st): State<AppState>,
    Query(q): Query<ListInvoicesQuery>,
) -> impl IntoResponse {
    if q.address.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "address required" })),
        )
            .into_response();
    }
    let list = st.hub.list_invoices_for(q.address.trim(), q.limit);
    Json(json!({ "ok": true, "count": list.len(), "invoices": list })).into_response()
}

#[derive(Deserialize)]
pub struct CancelInvoiceBody {
    pub by_address: String,
}

pub async fn agent_cancel_invoice(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CancelInvoiceBody>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    match st.hub.cancel_invoice(uuid, &body.by_address) {
        Ok(inv) => {
            if !inv.callback_url.is_empty() {
                let ev = crate::webhook::WebhookEvent {
                    protocol: HAP_PROTOCOL,
                    event: "invoice.cancelled".into(),
                    payment_id: inv.payment_id.map(|p| p.to_string()),
                    invoice_id: Some(inv.id.to_string()),
                    status: "cancelled".into(),
                    ts_unix: inv.updated_unix,
                    detail: json!({}),
                };
                let ok = st.webhooks.post_json(&inv.callback_url, &ev).await;
                if ok {
                    crate::metrics::HubMetrics::inc(&st.metrics.webhooks_sent);
                } else {
                    crate::metrics::HubMetrics::inc(&st.metrics.webhooks_failed);
                }
            }
            Json(json!({ "ok": true, "invoice": inv })).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

pub async fn agent_pay_invoice(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::invoice::PayInvoiceRequest>,
) -> impl IntoResponse {
    let Ok(iid) = Uuid::parse_str(body.invoice_id.trim()) else {
        let env = envelope_err("invoice_invalid", "invoice_id must be uuid", false);
        return (StatusCode::BAD_REQUEST, Json(env)).into_response();
    };
    let Some(inv) = st.hub.get_invoice(iid) else {
        let env = envelope_err("not_found", "invoice not found", false);
        return (StatusCode::NOT_FOUND, Json(env)).into_response();
    };
    let pay_req = AgentPayRequest {
        from: body.from,
        to: inv.payee,
        amount_hac: inv.amount_hac,
        amount_satoshi: inv.amount_satoshi,
        fee_hac: "0".into(),
        idempotency_key: body.idempotency_key,
        local_only: body.local_only,
        route: vec![],
        meta: {
            let mut m = body.meta;
            if m.invoice_id.is_empty() {
                m.invoice_id = inv.id.to_string();
            }
            if m.purpose.is_empty() {
                m.purpose = inv.description.clone();
            }
            m
        },
        invoice_id: inv.id.to_string(),
        callback_url: inv.callback_url,
        intent: body.intent,
    };
    agent_pay(State(st), headers, Json(pay_req))
        .await
        .into_response()
}

pub async fn micro_settle_summary(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    match st.hub.micro_settle_summary(uuid) {
        Ok(v) => Json(json!({ "ok": true, "summary": v })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct CancelPaymentBody {
    pub by_address: String,
}

pub async fn agent_cancel_payment(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CancelPaymentBody>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    let Some(existing) = st.hub.get_payment(uuid) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "payment not found" })),
        )
            .into_response();
    };
    let by = body.by_address.trim();
    if existing.payer != by
        && existing.payee != by
        && !existing.required_signers.iter().any(|signer| signer == by)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "ok": false, "err": "only a payment party may cancel" })),
        )
            .into_response();
    }
    let result = if st.distributed.transaction(uuid).is_some() {
        st.distributed
            .abort_origin(&st.hub, &st.net, uuid, &format!("cancelled by {by}"))
            .await
    } else {
        st.hub.cancel_payment(uuid, by)
    };
    match result {
        Ok(p) => {
            fire_payment_webhook(&st, uuid, "payment.cancelled", "failed").await;
            let base = st.args.resolved_public_url();
            let meta = st.hub.get_payment_meta(uuid);
            let env =
                envelope_from_payment(&p, &base, &Uuid::new_v4().to_string(), Some(&meta), false);
            Json(env).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

pub async fn agent_ledger(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "protocol": HAP_PROTOCOL,
        "ledger": st.hub.ledger_snapshot(),
        "note": "Soft accounting by policy principal (v:address / u:agent_id / a:payer) — not custody balances",
        "principal_scheme": {
            "v": "verified identity address — rotation of agent_id does not reset limits",
            "u": "unverified agent_id string",
            "a": "anonymous bound to payer address",
            "anon": "fallback"
        }
    }))
}

pub async fn agent_policy(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "ok": true,
        "protocol": HAP_PROTOCOL,
        "policy": st.hub.policy(),
        "provider_id": st.args.provider_id,
        "require_verified_agent": st.args.require_verified_agent,
        "identity_binding": {
            "ledger_and_open_caps": "policy principal v:{address} when agent_id is verified",
            "http_rate_limit": "ip:* plus v:{address} when verified (body meta.agent_id or X-Hacash-Agent-Id)",
            "allowlist": "still matches claimed agent_id string",
            "production_hint": "set HACASH_L2_REQUIRE_VERIFIED_AGENT=true so limits bind to keys, not free-form ids"
        }
    }))
}

pub async fn agent_openapi(State(st): State<AppState>) -> impl IntoResponse {
    let base = st.args.resolved_public_url();
    Json(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Hacash Agent Pay",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Machine payments over Hacash L2 Channel Chain (no custody)"
        },
        "servers": [{ "url": base }],
        "paths": {
            "/v1/agent/v1/manifest": { "get": { "summary": "Bootstrap" } },
            "/v1/agent/v1/quote": { "post": { "summary": "Dry-run route" } },
            "/v1/agent/v1/pay": { "post": { "summary": "Idempotent pay" } },
            "/v1/agent/v1/invoice": { "post": { "summary": "Create request-to-pay invoice" } },
            "/v1/agent/v1/pay-invoice": { "post": { "summary": "Pay an invoice" } },
            "/v1/agent/v1/sign": { "post": { "summary": "Submit signature" } },
            "/v1/agent/v1/inbox": { "get": { "summary": "Signature work queue" } },
            "/v1/agent/v1/receipt/{id}": { "get": { "summary": "Settlement receipt" } },
            "/v1/agent/v1/watch/{id}": { "get": { "summary": "SSE payment stream" } },
            "/v1/agent/v1/ledger": { "get": { "summary": "Agent spend ledger" } },
            "/v1/agent/v1/policy": { "get": { "summary": "Hub agent policy" } },
            "/v1/agent/v1/identity/register": { "post": { "summary": "Register agent pubkey" } },
            "/v1/agent/v1/identity/verify": { "post": { "summary": "Verify agent identity" } },
            "/v1/agent/v1/identity/{id}/scopes": { "post": { "summary": "Set operator-granted scopes", "security": [{"operatorToken": []}] } },
            "/v1/agent/v1/identity/{id}/revoke": { "post": { "summary": "Revoke agent identity", "security": [{"operatorToken": []}] } },
            "/v1/agent/v1/micro/open": { "post": { "summary": "Open micropayment stream" } },
            "/v1/agent/v1/micro/push": { "post": { "summary": "Push micro payment" } },
            "/v1/agent/v1/amounts/normalize": { "post": { "summary": "Normalize HAC/sat amounts" } }
        },
        "components": {
            "securitySchemes": {
                "operatorToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Api-Token"
                }
            }
        },
        "x_protocol": HAP_PROTOCOL,
        "x_tools": agent_pay::agent_tools_schema(&st.args.resolved_public_url())
    }))
}

// --- Identity ---

pub async fn identity_register(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::agent_id::RegisterIdentityRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    match st.hub.register_identity(body) {
        Ok(id) => Json(json!({
            "ok": true,
            "identity": id,
            "next": "GET /v1/agent/v1/identity/challenge?agent_id=… then sign and verify"
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub agent_id: String,
}

pub async fn identity_challenge(
    State(st): State<AppState>,
    Query(q): Query<ChallengeQuery>,
) -> impl IntoResponse {
    match st.hub.issue_identity_challenge(q.agent_id.trim()) {
        Ok(ch) => Json(json!({
            "ok": true,
            "challenge": ch,
            "how": "Sign challenge.message_hash_hex with agent key; POST /identity/verify"
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

pub async fn identity_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::agent_id::VerifyIdentityRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    match st.hub.verify_identity(body) {
        Ok(id) => Json(json!({ "ok": true, "identity": id, "verified": true })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

pub async fn identity_get(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.hub.get_identity(&id) {
        Some(i) => Json(json!({ "ok": true, "identity": i })).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not found" })),
        )
            .into_response(),
    }
}

pub async fn identity_list(State(st): State<AppState>) -> impl IntoResponse {
    Json(json!({ "ok": true, "identities": st.hub.list_identities() }))
}

fn operator_identity_gate(st: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    if st.args.api_token.trim().is_empty() {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "ok": false,
                "err": "operator API token must be configured for identity administration"
            })),
        )
            .into_response());
    }
    require_api_token(headers, &st.args.api_token)
}

pub async fn identity_set_scopes(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<crate::agent_id::SetIdentityScopesRequest>,
) -> impl IntoResponse {
    if let Err(response) = operator_identity_gate(&st, &headers) {
        return response;
    }
    match st.hub.set_identity_scopes(&agent_id, &body.scopes) {
        Ok(identity) => Json(json!({
            "ok": true,
            "identity": identity,
            "note": "Scopes are operator-granted and persisted synchronously."
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

pub async fn identity_revoke(
    State(st): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(response) = operator_identity_gate(&st, &headers) {
        return response;
    }
    match st.hub.revoke_identity(&agent_id) {
        Ok(identity) => Json(json!({
            "ok": true,
            "identity": identity,
            "warning": "Revocation is immediate on this hub; already-settled payments are unchanged."
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": error })),
        )
            .into_response(),
    }
}

// --- Micropayments ---

pub async fn micro_open(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::micro::OpenMicroRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    match st.hub.open_micro_stream(body) {
        Ok(s) => {
            let (rem_z, rem_s) = crate::micro::remaining(&s);

            Json(json!({
                "ok": true,
                "stream": s,
                "remaining": { "hac_zhu": rem_z, "hac_mei": rem_z / crate::amounts::ZHU_PER_MEI, "satoshi": rem_s },
                "push_commit_hint": "POST /v1/agent/v1/micro/push with payer signature over push commit when sig_verify on"
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

pub async fn micro_push(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::micro::PushMicroRequest>,
) -> impl IntoResponse {
    if let Err(r) = agent_gate(&st, &headers, &client_ip(&st, &headers)) {
        return r;
    }
    // If client needs hash to sign first, they can open stream and compute client-side;
    // when signature missing and sig_verify, return commit to sign.
    if st.args.sig_verify && body.signature_hex.trim().is_empty() {
        if let Ok(sid) = Uuid::parse_str(body.stream_id.trim()) {
            if let Some(s) = st.hub.get_micro_stream(sid) {
                let amount = crate::amounts::AmountInput {
                    amount_hac: body.amount_hac.clone(),
                    amount_satoshi: body.amount_satoshi,
                    amount_mei: body.amount_mei,
                    satoshi: body.satoshi,
                    mei: 0,
                }
                .resolve();
                let amount = match amount {
                    Ok(amount) => amount,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({ "ok": false, "err": e })),
                        )
                            .into_response();
                    }
                };
                let seq = s.sequence + 1;
                let msg = crate::micro::push_commit_message(
                    sid, seq, &s.payer, &s.payee, &amount, &body.note,
                );
                let hash = hex::encode(crate::hacash_keys::sha3(msg.as_bytes()));
                return Json(json!({
                    "ok": false,
                    "err": "signature_required",
                    "action_required": {
                        "kind": "sign_micro_push",
                        "stream_id": sid,
                        "sequence": seq,
                        "message": msg,
                        "sign_this_hash_hex": hash,
                        "address": s.payer,
                    }
                }))
                .into_response();
            }
        }
    }
    match st.hub.push_micro(body) {
        Ok((stream, payment)) => {
            crate::metrics::HubMetrics::inc(&st.metrics.micro_pushes);
            let (rem_z, rem_s) = crate::micro::remaining(&stream);
            Json(json!({
                "ok": true,
                "stream": stream,
                "payment": payment,
                "remaining": { "hac_zhu": rem_z, "hac_mei": rem_z / crate::amounts::ZHU_PER_MEI, "satoshi": rem_s },
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

pub async fn micro_get(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    match st.hub.get_micro_stream(uuid) {
        Some(s) => {
            let (rem_z, rem_s) = crate::micro::remaining(&s);
            Json(json!({
                "ok": true,
                "stream": s,
                "remaining": { "hac_zhu": rem_z, "hac_mei": rem_z / crate::amounts::ZHU_PER_MEI, "satoshi": rem_s },
            }))
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "err": "not found" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct MicroCloseBody {
    pub by_address: String,
}

pub async fn micro_close(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<MicroCloseBody>,
) -> impl IntoResponse {
    let Ok(uuid) = Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": "invalid id" })),
        )
            .into_response();
    };
    match st.hub.close_micro_stream(uuid, &body.by_address) {
        Ok(s) => Json(json!({ "ok": true, "stream": s })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct MicroListQuery {
    pub address: String,
}

pub async fn micro_list(
    State(st): State<AppState>,
    Query(q): Query<MicroListQuery>,
) -> impl IntoResponse {
    let list = st.hub.list_micro_streams(q.address.trim());
    Json(json!({ "ok": true, "count": list.len(), "streams": list }))
}

pub async fn amounts_normalize(Json(body): Json<crate::amounts::AmountInput>) -> impl IntoResponse {
    match body.resolve() {
        Ok(d) => Json(json!({
            "ok": true,
            "amount": d,
            "display": d.display(),
            "for_payment": {
                "amount_hac": d.for_payment().0,
                "amount_satoshi": d.for_payment().1,
            },
            "satoshi_first": d.amount_satoshi > 0 && d.hac_zhu == 0,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "err": e })),
        )
            .into_response(),
    }
}

fn watch_stream(
    hub: Arc<HubState>,
    base: String,
    uuid: Uuid,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(0u32, move |tick| {
        let hub = hub.clone();
        let base = base.clone();
        async move {
            if tick >= 80 {
                return None;
            }
            if tick > 0 {
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            let request_id = Uuid::new_v4().to_string();
            match hub.get_payment(uuid) {
                Some(p) => {
                    let meta = hub.get_payment_meta(uuid);
                    let mut env = envelope_from_payment(&p, &base, &request_id, Some(&meta), false);
                    if env.machine.done {
                        if let Some(r) = hub.get_receipt(uuid) {
                            env.result["receipt"] = serde_json::to_value(r).unwrap_or(json!({}));
                        }
                    }
                    let data = serde_json::to_string(&env).unwrap_or_else(|_| "{}".into());
                    let next_tick = if env.machine.done { 80 } else { tick + 1 };
                    Some((Ok(Event::default().event("payment").data(data)), next_tick))
                }
                None => Some((Ok(Event::default().event("error").data("not_found")), 80)),
            }
        }
    })
}
