//! HTTP 402 Payment Required helpers for agent-facing paywalls.
//!
//! Compatible spirit with x402-style flows: server returns 402 + payment instructions;
//! client pays via HAP then retries with payment receipt hash.

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::agent_pay::HAP_PROTOCOL;

/// Build a 402 response that tells agents how to pay.
pub fn payment_required(
    hub_base: &str,
    payee: &str,
    amount_hac: &str,
    amount_satoshi: u64,
    resource: &str,
    invoice_id: Option<&str>,
) -> Response {
    let base = hub_base.trim_end_matches('/');
    let body = json!({
        "ok": false,
        "error": "payment_required",
        "protocol": HAP_PROTOCOL,
        "x402": {
            "version": 1,
            "resource": resource,
            "accepts": [{
                "scheme": "hacash-l2-hap",
                "network": "hacash-channel-chain",
                "pay_to": payee,
                "amount_hac": amount_hac,
                "amount_satoshi": amount_satoshi,
                "invoice_id": invoice_id,
                "pay_endpoint": format!("{base}/v1/agent/v1/pay"),
                "pay_invoice_endpoint": format!("{base}/v1/agent/v1/pay-invoice"),
                "invoice_endpoint": format!("{base}/v1/agent/v1/invoice"),
                "receipt_header": "X-Hacash-Payment-Receipt",
                "instructions": [
                    "1. Create invoice or POST pay with idempotency_key",
                    "2. Complete multi-party signatures via inbox/sign",
                    "3. Retry original request with header X-Hacash-Payment-Receipt: <receipt_hash_hex>"
                ]
            }]
        }
    });
    let mut res = (StatusCode::PAYMENT_REQUIRED, axum::Json(body)).into_response();
    if let Ok(v) = HeaderValue::from_str(HAP_PROTOCOL) {
        res.headers_mut().insert("x-payment-protocol", v);
    }
    res
}

/// Extract optional payment proof from request headers.
pub fn receipt_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-hacash-payment-receipt")
        .or_else(|| headers.get("X-Hacash-Payment-Receipt"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
