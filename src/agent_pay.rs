//! Hacash Agent Pay Protocol (HAP) — first-class AI agent payments.
//!
//! Design goals (best-in-class for agents, not humans reading docs):
//! 1. **Idempotent** — same key never double-spends a session
//! 2. **Machine envelope** — every response has state / done / action_required
//! 3. **Inbox** — agent polls work items (sign this hash) without full graph search
//! 4. **Receipts** — verifiable hub coordination proof after settle
//! 5. **Quote** — dry-run route before committing
//! 6. **Manifest** — single bootstrap document for tool-calling LLMs
//!
//! Keys never leave the agent. Hub coordinates only.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JV};
use uuid::Uuid;

use crate::hacash_keys;
use crate::smart::{self, SmartPaymentView};
use crate::types::{PaymentSession, PaymentStatus};
pub const AGENT_INTENT_DOMAIN: &str = "HACASH_AGENT_PAY_INTENT_V1";

pub const HAP_PROTOCOL: &str = "hacash-agent-pay/1";
pub const RECEIPT_DOMAIN: &str = "HACASH_AGENT_RECEIPT_V1";

/// Optional metadata agents attach to payments (invoice, purpose, skill id).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentPaymentMeta {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub invoice_id: String,
    #[serde(default)]
    pub skill: String,
    #[serde(default)]
    pub conversation_id: String,
    /// Free-form JSON string (bounded by hub).
    #[serde(default)]
    pub extra: String,
    /// Hub-filled: stable policy bucket (`v:addr` / `u:id` / `a:payer`). Clients cannot trust-set this.
    #[serde(default)]
    pub policy_principal: String,
    /// Hub-filled when agent_id is verified: Hacash address of identity key.
    #[serde(default)]
    pub identity_address: String,
}

/// Per-request authorization by a registered agent identity key.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AgentIntentProof {
    /// Unique per agent. Reuse is allowed only for the same idempotent request.
    #[serde(default)]
    pub nonce: String,
    /// Short deadline chosen by the agent.
    #[serde(default)]
    pub expires_unix: u64,
    /// Hacash packed signature over `agent_intent_hash_hex`.
    #[serde(default)]
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}

/// Idempotent pay request (agent primary path).
#[derive(Debug, Deserialize)]
pub struct AgentPayRequest {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub fee_hac: String,
    /// Required for safe agent retries (max 128 chars).
    pub idempotency_key: String,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub route: Vec<String>,
    #[serde(default)]
    pub meta: AgentPaymentMeta,
    /// Optional invoice to fulfill (request-to-pay).
    #[serde(default)]
    pub invoice_id: String,
    /// Optional webhook URL (SSRF-checked) on settle/fail.
    #[serde(default)]
    pub callback_url: String,
    /// Required when the hub enforces verified agents.
    #[serde(default)]
    pub intent: AgentIntentProof,
}

#[derive(Debug, Deserialize)]
pub struct AgentSignRequest {
    pub payment_id: String,
    pub address: String,
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub agent_id: String,
}

/// Machine-first envelope every HAP response wraps.
#[derive(Debug, Clone, Serialize)]
pub struct MachineEnvelope {
    pub ok: bool,
    pub protocol: &'static str,
    pub request_id: String,
    pub machine: MachineStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_required: Option<ActionRequired>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<MachineError>,
    pub result: JV,
    pub human: HumanHint,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineStatus {
    pub state: String,
    pub done: bool,
    pub success: bool,
    pub retryable: bool,
    pub next_poll_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionRequired {
    /// `sign_payment` | `wait_counterparty` | `none`
    pub kind: String,
    pub payment_id: Uuid,
    pub address: String,
    pub sign_this_hash_hex: String,
    pub deadline_unix: u64,
    pub sign_endpoint: String,
    pub sign_body_template: JV,
    pub instructions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HumanHint {
    pub title: String,
    pub detail: String,
}

/// Inbox work item for an agent holding keys for `address`.
#[derive(Debug, Clone, Serialize)]
pub struct InboxItem {
    pub kind: String,
    pub payment_id: Uuid,
    pub role: String,
    pub amount_hac: String,
    pub counterparty: String,
    pub sign_this_hash_hex: String,
    pub expires_unix: u64,
    pub priority: i32,
    pub meta: AgentPaymentMeta,
    pub action: ActionRequired,
}

/// Hub coordination receipt (not L1 final).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    pub protocol: String,
    pub receipt_version: u32,
    pub payment_id: Uuid,
    pub status: String,
    pub finality: String,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub fee_hac: String,
    pub route: Vec<String>,
    pub required_signers: Vec<String>,
    pub signed_by: Vec<String>,
    pub message_hash_hex: String,
    pub settled_unix: u64,
    pub provider_id: String,
    pub meta: AgentPaymentMeta,
    /// SHA3-256 of canonical receipt body (for agents to store/verify integrity).
    pub receipt_hash_hex: String,
    pub disclaimer: String,
    /// Hub operator address that signed this receipt (empty if unsigned).
    #[serde(default)]
    pub hub_identity_address: String,
    /// 97-byte Sign hex over receipt_hash (hub identity); empty if unsigned.
    #[serde(default)]
    pub hub_signature_hex: String,
}
fn intent_field(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str("_len=");
    out.push_str(&value.len().to_string());
    out.push('\n');
    out.push_str(name);
    out.push('=');
    out.push_str(value);
    out.push('\n');
}

pub fn agent_intent_message(
    provider_id: &str,
    agent_id: &str,
    from: &str,
    to: &str,
    amount_hac: &str,
    amount_satoshi: u64,
    fee_hac: &str,
    route: &[String],
    invoice_id: &str,
    idempotency_key: &str,
    nonce: &str,
    expires_unix: u64,
) -> Result<String, String> {
    for (name, value) in [
        ("provider_id", provider_id),
        ("agent_id", agent_id),
        ("from", from),
        ("to", to),
        ("amount_hac", amount_hac),
        ("fee_hac", fee_hac),
        ("invoice_id", invoice_id),
        ("idempotency_key", idempotency_key),
        ("nonce", nonce),
    ] {
        if value.chars().any(char::is_control) {
            return Err(format!("{name} contains control characters"));
        }
    }
    if nonce.len() < 16 || nonce.len() > 128 {
        return Err("intent nonce must be 16..=128 characters".into());
    }
    let mut out = format!("{AGENT_INTENT_DOMAIN}\n");
    intent_field(&mut out, "provider_id", provider_id);
    intent_field(&mut out, "agent_id", agent_id);
    intent_field(&mut out, "from", from);
    intent_field(&mut out, "to", to);
    intent_field(&mut out, "amount_hac", amount_hac);
    out.push_str(&format!("amount_satoshi={amount_satoshi}\n"));
    intent_field(&mut out, "fee_hac", fee_hac);
    out.push_str(&format!("route_count={}\n", route.len()));
    for (index, channel_id) in route.iter().enumerate() {
        intent_field(&mut out, &format!("route_{index}"), channel_id);
    }
    intent_field(&mut out, "invoice_id", invoice_id);
    intent_field(&mut out, "idempotency_key", idempotency_key);
    intent_field(&mut out, "nonce", nonce);
    out.push_str(&format!("expires_unix={expires_unix}\n"));
    Ok(out)
}

pub fn verify_agent_intent(
    identity_address: &str,
    proof: &AgentIntentProof,
    message: &str,
    now_unix: u64,
) -> Result<String, String> {
    if proof.expires_unix <= now_unix {
        return Err("agent intent expired".into());
    }
    if proof.expires_unix > now_unix.saturating_add(600) {
        return Err("agent intent expiry may be at most 10 minutes ahead".into());
    }
    if proof.signature_hex.trim().is_empty() {
        return Err("agent intent signature is required".into());
    }
    let hash = hacash_keys::sha3(message.as_bytes());
    let public_key = proof.public_key_hex.trim();
    crate::crypto::verify_payment_signature(
        &hash,
        identity_address,
        proof.signature_hex.trim(),
        (!public_key.is_empty()).then_some(public_key),
    )?;
    Ok(hex::encode(hash))
}

pub fn receipt_canonical(r: &PaymentReceipt) -> String {
    // Hash without receipt_hash_hex field (computed after).
    format!(
        "\
{domain}\n\
payment_id={pid}\n\
status={status}\n\
finality={finality}\n\
payer={payer}\n\
payee={payee}\n\
amount_hac={amount_hac}\n\
amount_satoshi={amount_satoshi}\n\
fee_hac={fee_hac}\n\
route={route}\n\
signers={signers}\n\
signed_by={signed}\n\
message_hash={msg}\n\
settled_unix={settled}\n\
provider_id={provider}\n\
agent_id={agent}\n\
invoice_id={invoice}\n\
purpose={purpose}\n",
        domain = RECEIPT_DOMAIN,
        pid = r.payment_id,
        status = r.status,
        finality = r.finality,
        payer = r.payer,
        payee = r.payee,
        amount_hac = r.amount_hac,
        amount_satoshi = r.amount_satoshi,
        fee_hac = r.fee_hac,
        route = r.route.join(","),
        signers = r.required_signers.join(","),
        signed = r.signed_by.join(","),
        msg = r.message_hash_hex,
        settled = r.settled_unix,
        provider = r.provider_id,
        agent = r.meta.agent_id,
        invoice = r.meta.invoice_id,
        purpose = r.meta.purpose,
    )
}

pub fn build_receipt(
    p: &PaymentSession,
    provider_id: &str,
    meta: AgentPaymentMeta,
) -> PaymentReceipt {
    let signed_by: Vec<String> = p.signatures.iter().map(|s| s.address.clone()).collect();
    let status = match p.status {
        PaymentStatus::Settled => "settled",
        PaymentStatus::Failed => "failed",
        PaymentStatus::Committing => "committing",
        PaymentStatus::TimedOut => "timed_out",
        PaymentStatus::CollectingSignatures => "collecting",
        PaymentStatus::Pending => "pending",
    };
    let mut r = PaymentReceipt {
        protocol: HAP_PROTOCOL.into(),
        receipt_version: 1,
        payment_id: p.id,
        status: status.into(),
        finality: p.finality.clone(),
        payer: p.payer.clone(),
        payee: p.payee.clone(),
        amount_hac: p.amount_hac.clone(),
        amount_satoshi: p.amount_satoshi,
        fee_hac: p.fee_hac.clone(),
        route: p.route.clone(),
        required_signers: p.required_signers.clone(),
        signed_by,
        message_hash_hex: p.message_hash_hex.clone(),
        settled_unix: p.updated_unix,
        provider_id: provider_id.into(),
        meta,
        receipt_hash_hex: String::new(),
        disclaimer:
            "Hub coordination receipt only — not L1 ChannelClose finality. Keys never held by hub."
                .into(),
        hub_identity_address: String::new(),
        hub_signature_hex: String::new(),
    };
    let canon = receipt_canonical(&r);
    r.receipt_hash_hex = hex::encode(hacash_keys::sha3(canon.as_bytes()));
    r
}

/// Sign receipt_hash with hub operator key (optional authenticity for agents).
pub fn sign_receipt_with_hub(r: &mut PaymentReceipt, account: &crate::hacash_keys::Account) {
    let hash_hex = r.receipt_hash_hex.trim();
    if hash_hex.len() != 64 {
        return;
    }
    let Ok(bytes) = hex::decode(hash_hex) else {
        return;
    };
    if bytes.len() != 32 {
        return;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    r.hub_identity_address = account.readable().to_string();
    r.hub_signature_hex = crate::crypto::sign_payment_hash(account, &hash);
}

pub fn action_from_payment(p: &PaymentSession, hub_base: &str) -> Option<ActionRequired> {
    let next = smart::next_signer(p)?;
    let base = hub_base.trim_end_matches('/');
    Some(ActionRequired {
        kind: "sign_payment".into(),
        payment_id: p.id,
        address: next.clone(),
        sign_this_hash_hex: p.message_hash_hex.clone(),
        deadline_unix: p.expires_unix,
        sign_endpoint: format!("{base}/v1/agent/v1/sign"),
        sign_body_template: json!({
            "payment_id": p.id,
            "address": next,
            "signature_hex": "<97-byte-hex-pubkey||sig>",
            "public_key_hex": ""
        }),
        instructions: vec![
            format!("You must sign as {next}"),
            format!("Hash (SHA3-256 hex): {}", p.message_hash_hex),
            "Sign 32 raw bytes with Hacash secp256k1 key (same as L1)".into(),
            "POST signature to sign_endpoint — never send private key".into(),
            "If you are not next signer, poll status or wait for counterparty".into(),
        ],
    })
}

pub fn envelope_from_payment(
    p: &PaymentSession,
    hub_base: &str,
    request_id: &str,
    meta: Option<&AgentPaymentMeta>,
    idempotent_replay: bool,
) -> MachineEnvelope {
    envelope_from_payment_for(p, hub_base, request_id, meta, idempotent_replay, None)
}

/// Build envelope; when `viewer_address` is set, distinguish sign-me vs wait_counterparty.
pub fn envelope_from_payment_for(
    p: &PaymentSession,
    hub_base: &str,
    request_id: &str,
    meta: Option<&AgentPaymentMeta>,
    idempotent_replay: bool,
    viewer_address: Option<&str>,
) -> MachineEnvelope {
    let view = smart::smart_payment_view(p, hub_base);
    let mut action = action_from_payment(p, hub_base);
    let viewer = viewer_address.map(str::trim).filter(|s| !s.is_empty());

    let (done, success, state, retryable, poll) = match p.status {
        PaymentStatus::Settled => (true, true, "settled_hub", false, 0u64),
        PaymentStatus::Failed => (true, false, "failed", false, 0),
        PaymentStatus::TimedOut => (true, false, "timed_out", true, 0),
        PaymentStatus::Committing => {
            action = None;
            (false, false, "commit_pending", true, 1000)
        }
        PaymentStatus::CollectingSignatures | PaymentStatus::Pending => {
            let next_addr = action.as_ref().map(|a| a.address.clone());
            let my_turn = match (viewer, next_addr.as_deref()) {
                (Some(v), Some(n)) => v == n,
                (None, Some(_)) => true, // unknown viewer: expose next signer action
                _ => false,
            };
            if let Some(ref mut a) = action {
                if let Some(v) = viewer {
                    if a.address != v {
                        a.kind = "wait_counterparty".into();
                        a.instructions = vec![
                            format!("Waiting for {} to sign next", a.address),
                            "Poll status or GET /v1/agent/v1/watch/{payment_id}".into(),
                            "Drain their inbox is not your key — do not sign as them".into(),
                        ];
                    } else {
                        a.kind = "sign_payment".into();
                    }
                }
            }
            (
                false,
                false,
                if my_turn {
                    "action_required"
                } else if next_addr.is_some() {
                    "wait_peer"
                } else {
                    "collecting"
                },
                true,
                if my_turn { 500 } else { 1500 },
            )
        }
    };

    let mut result = json!({
        "payment": view,
        "payment_id": p.id,
        "status": p.status,
        "finality": p.finality,
        "idempotent_replay": idempotent_replay,
        "finality_note": "hub settled ≠ L1 ChannelClose — store receipt; bill/close for on-chain",
    });
    if let Some(m) = meta {
        result["meta"] = serde_json::to_value(m).unwrap_or(json!({}));
    }
    if let Some(v) = viewer {
        result["viewer_address"] = json!(v);
    }

    // Only return action_required for sign_payment (not wait) when viewer is known
    let action_out = match (&action, viewer) {
        (Some(a), Some(_)) if a.kind == "wait_counterparty" => {
            // Still include wait action so agents know who is next
            action
        }
        (Some(_), _) => action,
        (None, _) => None,
    };

    MachineEnvelope {
        ok: true,
        protocol: HAP_PROTOCOL,
        request_id: request_id.into(),
        machine: MachineStatus {
            state: state.into(),
            done,
            success,
            retryable,
            next_poll_ms: poll,
        },
        action_required: action_out,
        error: None,
        result,
        human: HumanHint {
            title: view.ui.title.clone(),
            detail: view.ui.subtitle.clone(),
        },
    }
}

pub fn envelope_err(code: &str, message: &str, retryable: bool) -> MachineEnvelope {
    MachineEnvelope {
        ok: false,
        protocol: HAP_PROTOCOL,
        request_id: Uuid::new_v4().to_string(),
        machine: MachineStatus {
            state: "error".into(),
            done: true,
            success: false,
            retryable,
            next_poll_ms: 0,
        },
        action_required: None,
        error: Some(MachineError {
            code: code.into(),
            message: message.into(),
        }),
        result: json!({}),
        human: HumanHint {
            title: "Payment error".into(),
            detail: message.into(),
        },
    }
}

/// Inbox items for multi-hop payments mirrored from other hubs.
/// Sign always goes to **origin** `sign_endpoint` (never local settle authority).
pub fn build_foreign_inbox(
    address: &str,
    foreign: &[crate::types::ForeignPayment],
) -> Vec<InboxItem> {
    let addr = address.trim();
    let mut items = Vec::new();
    for f in foreign {
        if f.status != "collecting" {
            continue;
        }
        if f.next_signer.trim() != addr {
            continue;
        }
        if f.message_hash_hex.len() != 64 {
            continue;
        }
        let counterparty = if f.payee == addr {
            f.payer.clone()
        } else {
            f.payee.clone()
        };
        items.push(InboxItem {
            kind: "sign_on_origin_hub".into(),
            payment_id: f.payment_id,
            role: if f.payee == addr {
                "payee".into()
            } else if f.payer == addr {
                "payer".into()
            } else {
                "intermediate".into()
            },
            amount_hac: f.amount_hac.clone(),
            counterparty,
            sign_this_hash_hex: f.message_hash_hex.clone(),
            expires_unix: f.expires_unix,
            priority: 8,
            meta: AgentPaymentMeta {
                agent_id: String::new(),
                purpose: format!("foreign_via_{}", f.origin_provider_id),
                invoice_id: String::new(),
                skill: "multi-hop".into(),
                conversation_id: f.payment_id.to_string(),
                extra: f.origin_public_url.clone(),
                ..Default::default()
            },
            action: ActionRequired {
                kind: "sign_payment".into(),
                payment_id: f.payment_id,
                address: addr.to_string(),
                sign_this_hash_hex: f.message_hash_hex.clone(),
                deadline_unix: f.expires_unix,
                sign_endpoint: f.sign_endpoint.clone(),
                sign_body_template: json!({
                    "payment_id": f.payment_id,
                    "address": addr,
                    "signature_hex": "<97-byte-hex-pubkey||sig>",
                    "public_key_hex": ""
                }),
                instructions: vec![
                    format!("Multi-hop: origin hub is {}", f.origin_provider_id),
                    format!("POST signature to {}", f.sign_endpoint),
                    "Do NOT sign on this local hub — session lives on origin".into(),
                    format!("Hash: {}", f.message_hash_hex),
                ],
            },
        });
    }
    items
}

pub fn build_inbox(
    address: &str,
    payments: &[PaymentSession],
    hub_base: &str,
    metas: &std::collections::HashMap<Uuid, AgentPaymentMeta>,
) -> Vec<InboxItem> {
    let addr = address.trim();
    let mut items = Vec::new();
    for p in payments {
        if !matches!(
            p.status,
            PaymentStatus::Pending | PaymentStatus::CollectingSignatures
        ) {
            continue;
        }
        let Some(next) = smart::next_signer(p) else {
            continue;
        };
        if next != addr {
            continue;
        }
        let role = if p.payee == addr {
            "payee"
        } else if p.payer == addr {
            "payer"
        } else {
            "intermediate"
        };
        let counterparty = if p.payer == addr {
            p.payee.clone()
        } else {
            p.payer.clone()
        };
        let Some(action) = action_from_payment(p, hub_base) else {
            continue;
        };
        let meta = metas.get(&p.id).cloned().unwrap_or_default();
        items.push(InboxItem {
            kind: "sign_payment".into(),
            payment_id: p.id,
            role: role.into(),
            amount_hac: p.amount_hac.clone(),
            counterparty,
            sign_this_hash_hex: p.message_hash_hex.clone(),
            expires_unix: p.expires_unix,
            priority: if role == "payee" { 10 } else { 5 },
            meta,
            action,
        });
    }
    items.sort_by(|a, b| b.priority.cmp(&a.priority));
    items
}

/// Full agent bootstrap manifest (one GET = everything an LLM needs).
pub fn agent_manifest(hub_base: &str, provider_id: &str, version: &str) -> JV {
    let base = hub_base.trim_end_matches('/');
    json!({
        "protocol": HAP_PROTOCOL,
        "name": "Hacash Agent Pay",
        "version": version,
        "provider_id": provider_id,
        "base_url": base,
        "philosophy": {
            "custody": "none — agent holds keys",
            "finality": "hub settled ≠ L1 ChannelClose",
            "best_for": "AI agents paying/receiving HAC/satoshi over Channel Chain L2",
            "why_agents": [
                "Idempotent pay (safe retries)",
                "Inbox work queue (no graph traversal)",
                "Machine envelope on every response",
                "Receipts with integrity hash",
                "Quote before pay",
                "SSE watch for async multi-party sign"
            ]
        },
        "bootstrap": {
            "step_1": format!("GET {base}/v1/agent/v1/manifest"),
            "step_2": format!("POST {base}/v1/agent/v1/quote  then  POST {base}/v1/agent/v1/pay"),
            "step_3": format!("GET {base}/v1/agent/v1/inbox?address=YOUR_ADDR"),
            "step_4": "Sign hash locally → POST /v1/agent/v1/sign",
            "step_5": format!("GET {base}/v1/agent/v1/receipt/{{payment_id}} when machine.done")
        },
        "endpoints": {
            "manifest": { "method": "GET", "path": "/v1/agent/v1/manifest" },
            "quote": { "method": "POST", "path": "/v1/agent/v1/quote" },
            "pay": { "method": "POST", "path": "/v1/agent/v1/pay", "requires": ["idempotency_key"], "verified_agent_mode": "also requires a signed, expiring intent nonce" },
            "invoice_create": { "method": "POST", "path": "/v1/agent/v1/invoice" },
            "invoice_get": { "method": "GET", "path": "/v1/agent/v1/invoice/{id}" },
            "pay_invoice": { "method": "POST", "path": "/v1/agent/v1/pay-invoice" },
            "sign": { "method": "POST", "path": "/v1/agent/v1/sign" },
            "status": { "method": "GET", "path": "/v1/agent/v1/payment/{id}" },
            "cancel_payment": { "method": "POST", "path": "/v1/agent/v1/payment/{id}/cancel" },
            "inbox": { "method": "GET", "path": "/v1/agent/v1/inbox?address={addr}" },
            "receipt": { "method": "GET", "path": "/v1/agent/v1/receipt/{id}" },
            "watch": { "method": "GET", "path": "/v1/agent/v1/watch/{id}", "stream": "text/event-stream" },
            "ledger": { "method": "GET", "path": "/v1/agent/v1/ledger" },
            "policy": { "method": "GET", "path": "/v1/agent/v1/policy" },
            "openapi": { "method": "GET", "path": "/v1/agent/v1/openapi.json" },
            "tools": { "method": "GET", "path": "/v1/agent/v1/tools" },
            "identity_register": { "method": "POST", "path": "/v1/agent/v1/identity/register" },
            "identity_verify": { "method": "POST", "path": "/v1/agent/v1/identity/verify" },
            "identity_set_scopes": { "method": "POST", "path": "/v1/agent/v1/identity/{id}/scopes", "auth": "operator API token" },
            "identity_revoke": { "method": "POST", "path": "/v1/agent/v1/identity/{id}/revoke", "auth": "operator API token" },
            "micro_open": { "method": "POST", "path": "/v1/agent/v1/micro/open" },
            "micro_push": { "method": "POST", "path": "/v1/agent/v1/micro/push" },
            "amounts_normalize": { "method": "POST", "path": "/v1/agent/v1/amounts/normalize" },
            "close_plan": { "method": "GET", "path": "/v1/agent/v1/close-plan/{channel_id}", "purpose": "L1 ChannelClose evidence plan (wallet builds/signs tx)" },
            "channel_state_v2_shadow": { "method": "GET", "path": "/v1/channels/{channel_id}/state-v2/shadow", "purpose": "Unsigned migration candidate for deterministic wallet/policy review; never auto-sign" },
            "channel_state_v2_observe": { "method": "POST", "path": "/v1/channels/{channel_id}/state-v2/observe", "purpose": "Verify and durably store party-signed evidence; no settlement authority" },
            "channel_state_v2_activation_draft": { "method": "GET", "path": "/v1/channels/{channel_id}/state-v2/activation-draft/{state_hash}", "purpose": "Canonical strict-verification opt-in; wallet/policy review and both party signatures required; agent must never auto-sign" },
            "channel_state_v2_activate": { "method": "POST", "path": "/v1/channels/{channel_id}/state-v2/activate", "purpose": "Submit a both-party certificate; operator auth and durable state required; no settlement authority" },
            "channel_state_v2_activation_status": { "method": "GET", "path": "/v1/channels/{channel_id}/state-v2/activation", "purpose": "Read activation certificate and current mutually signed verification head" }
            , "l1_exit_readiness": { "method": "GET", "path": "/v1/channels/{channel_id}/l1-exit/readiness", "purpose": "Fail-closed check of actual fullnode action codecs; agent must never auto-sign or broadcast an exit" }
        },
        "tools": agent_tools_schema(base),
        "commerce": {
            "request_to_pay": "Payee creates invoice → payer calls pay-invoice → multi-party sign → receipt",
            "webhooks": "callback_url on pay/invoice (SSRF-safe http/https only)",
            "micropayments": "open stream with caps → push (optional real payments) → close",
            "identity": "register pubkey → challenge → verify → operator scopes/revocation"
        },
        "error_codes": [
            "no_route", "invalid_amount", "bad_signature", "wrong_order",
            "not_found", "expired", "idempotency_conflict", "missing_idempotency_key",
            "policy_denied", "rate_limited", "invoice_invalid", "invoice_amount_mismatch"
        ],
        "signing": {
            "hash": "sha3-256",
            "curve": "secp256k1",
            "wire": "97-byte hex Sign = compressed_pubkey[33] || ecdsa_sig[64]",
            "order": "payee first, then path intermediates, payer last"
        },
        "agent_intent": {
            "domain": AGENT_INTENT_DOMAIN,
            "purpose": "per-request authorization by the verified agent identity key",
            "expiry_max_seconds": 600,
            "nonce": "unique 16..128 character value; reusable only for the same idempotency_key",
            "sdk_helpers": ["signAgentIntent (TypeScript)", "sign_agent_intent (Python)"]
        },        "agent_loop": [
            "loop:",
            "  inbox = GET inbox?address=me  (local items only)",
            "  auto-sign only reviewed incoming payments; never generic outbound/intermediary work",
            "  if user/skill approved a payment: quote → pay(idempotency_key) → sign that payment only",
            "  if payment pending and not my turn: GET watch or poll status",
            "  if machine.done && success: store receipt_hash"
        ],
        "multi_hop": {
            "mode": "experimental_discovery_only",
            "notify": "POST /v1/net/payment-notify (hub-to-hub)",
            "foreign_signing": "disabled",
            "warning": "remote notifications do not provide atomic settlement or remote balance commit",
            "required_before_production": "authenticated canonical relay plus durable prepare/commit/abort reservations"
        }
    })
}

pub fn agent_tools_schema(base: &str) -> Vec<JV> {
    let base = base.trim_end_matches('/');
    vec![
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_quote",
                "description": "Dry-run a payment route without creating a session. Call before pay.",
                "parameters": {
                    "type": "object",
                    "required": ["from", "to"],
                    "properties": {
                        "from": { "type": "string", "description": "Payer Hacash address" },
                        "to": { "type": "string", "description": "Payee Hacash address" },
                        "amount_hac": { "type": "string", "description": "Amount e.g. 1:247" },
                        "local_only": { "type": "boolean", "default": false }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/quote") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_pay",
                "description": "Create idempotent L2 payment. Always pass a unique idempotency_key per logical payment.",
                "parameters": {
                    "type": "object",
                    "required": ["from", "to", "amount_hac", "idempotency_key"],
                    "properties": {
                        "from": { "type": "string" },
                        "to": { "type": "string" },
                        "amount_hac": { "type": "string" },
                        "amount_satoshi": { "type": "integer" },
                        "idempotency_key": { "type": "string", "maxLength": 128 },
                        "meta": {
                            "type": "object",
                            "properties": {
                                "agent_id": { "type": "string" },
                                "purpose": { "type": "string" },
                                "invoice_id": { "type": "string" },
                                "skill": { "type": "string" },
                                "conversation_id": { "type": "string" }
                            }
                        },
                        "intent": {
                            "type": "object",
                            "description": "Required when HACASH_L2_REQUIRE_VERIFIED_AGENT=true",
                            "properties": {
                                "nonce": { "type": "string", "minLength": 16, "maxLength": 128 },
                                "expires_unix": { "type": "integer" },
                                "signature_hex": { "type": "string" },
                                "public_key_hex": { "type": "string" }
                            }
                        }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/pay") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_inbox",
                "description": "List payments waiting for THIS address to sign (work queue).",
                "parameters": {
                    "type": "object",
                    "required": ["address"],
                    "properties": { "address": { "type": "string" } }
                },
                "x_http": { "method": "GET", "url": format!("{base}/v1/agent/v1/inbox?address={{address}}") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_sign",
                "description": "Submit secp256k1 signature for a payment hash. Never send private keys.",
                "parameters": {
                    "type": "object",
                    "required": ["payment_id", "address", "signature_hex"],
                    "properties": {
                        "payment_id": { "type": "string", "format": "uuid" },
                        "address": { "type": "string" },
                        "signature_hex": { "type": "string", "description": "97-byte Sign hex" }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/sign") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_status",
                "description": "Poll payment machine state / action_required.",
                "parameters": {
                    "type": "object",
                    "required": ["payment_id"],
                    "properties": { "payment_id": { "type": "string" } }
                },
                "x_http": { "method": "GET", "url": format!("{base}/v1/agent/v1/payment/{{payment_id}}") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_receipt",
                "description": "Fetch hub coordination receipt after settle (store receipt_hash_hex).",
                "parameters": {
                    "type": "object",
                    "required": ["payment_id"],
                    "properties": { "payment_id": { "type": "string" } }
                },
                "x_http": { "method": "GET", "url": format!("{base}/v1/agent/v1/receipt/{{payment_id}}") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_create_invoice",
                "description": "Request-to-pay: create invoice as payee. Other agent pays with pay_invoice.",
                "parameters": {
                    "type": "object",
                    "required": ["payee", "amount_hac"],
                    "properties": {
                        "payee": { "type": "string" },
                        "amount_hac": { "type": "string" },
                        "payer_hint": { "type": "string" },
                        "description": { "type": "string" },
                        "ttl_secs": { "type": "integer" },
                        "callback_url": { "type": "string" }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/invoice") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_pay_invoice",
                "description": "Pay an open invoice (request-to-pay fulfillment).",
                "parameters": {
                    "type": "object",
                    "required": ["invoice_id", "from", "idempotency_key"],
                    "properties": {
                        "invoice_id": { "type": "string" },
                        "from": { "type": "string" },
                        "idempotency_key": { "type": "string" }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/pay-invoice") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_micro_open",
                "description": "Open a streaming micropayment session with max caps (HAC mei and/or satoshi).",
                "parameters": {
                    "type": "object",
                    "required": ["payer", "payee"],
                    "properties": {
                        "payer": { "type": "string" },
                        "payee": { "type": "string" },
                        "max_hac_mei": { "type": "integer" },
                        "max_satoshi": { "type": "integer" },
                        "create_payments": { "type": "boolean", "description": "true = each push creates real HAP payment" }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/micro/open") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_micro_push",
                "description": "Push a micropayment on a stream. Prefer amount_satoshi for satoshi-first. Payer must sign commit when required.",
                "parameters": {
                    "type": "object",
                    "required": ["stream_id"],
                    "properties": {
                        "stream_id": { "type": "string" },
                        "amount_satoshi": { "type": "integer" },
                        "amount_mei": { "type": "integer" },
                        "amount_hac": { "type": "string" },
                        "signature_hex": { "type": "string" },
                        "note": { "type": "string" }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/micro/push") }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "hacash_agent_register_identity",
                "description": "Bind agent_id to secp256k1 public key. Then challenge+verify.",
                "parameters": {
                    "type": "object",
                    "required": ["agent_id", "public_key_hex"],
                    "properties": {
                        "agent_id": { "type": "string" },
                        "public_key_hex": { "type": "string" },
                        "label": { "type": "string" }
                    }
                },
                "x_http": { "method": "POST", "url": format!("{base}/v1/agent/v1/identity/register") }
            }
        }),
    ]
}

/// Quote result without creating a payment.
#[derive(Debug, Clone, Serialize)]
pub struct QuoteResult {
    pub ok: bool,
    pub from: String,
    pub to: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub route: Vec<String>,
    pub hops: usize,
    pub required_signers: Vec<String>,
    pub remote_hubs: usize,
    pub estimated_sign_rounds: usize,
    pub can_pay: bool,
    /// high = local path only; medium = mixed; low = authenticated remote hubs
    pub confidence: String,
    pub local_only_used: bool,
    /// CSP fee that pay will use if `fee_hac` is left empty (from hub schedule).
    pub fee_hac_estimate: String,
    pub fee_base_mei: u64,
    pub fee_ppm: u64,
    pub note: String,
    pub agent_hint: String,
}

/// Format fee mei as HAC string for payment commit (`N:247` when N>0).
/// If client left `fee_hac` empty and hub schedule is non-zero, return scheduled fee string.
/// Explicit client `"0"` or any non-empty value is respected (not overridden).
pub fn resolve_fee_hac(
    client_fee_hac: &str,
    amount_hac: &str,
    schedule: &crate::types::FeeSchedule,
) -> Result<String, String> {
    let client = client_fee_hac.trim();
    if !client.is_empty() {
        return crate::amounts::normalize_hac(client);
    }
    if schedule.fee_base_mei == 0 && schedule.fee_ppm == 0 {
        return Ok("0".into());
    }
    let amount_zhu = crate::amounts::parse_zhu(amount_hac)?;
    let fee_zhu = schedule.estimate_zhu(amount_zhu)?;
    Ok(crate::amounts::format_zhu(fee_zhu))
}

pub fn quote_from_session_preview(
    from: &str,
    to: &str,
    amount_hac: &str,
    amount_satoshi: u64,
    route: Vec<String>,
    required_signers: Vec<String>,
    remote_hubs: usize,
    local_only: bool,
) -> QuoteResult {
    quote_from_session_preview_with_fee(
        from,
        to,
        amount_hac,
        amount_satoshi,
        route,
        required_signers,
        remote_hubs,
        local_only,
        &crate::types::FeeSchedule {
            fee_base_mei: 0,
            fee_ppm: 0,
            fee_hint: String::new(),
            currency: "HAC",
            note: "",
        },
    )
    .expect("zero fee schedule must always be valid")
}

pub fn quote_from_session_preview_with_fee(
    from: &str,
    to: &str,
    amount_hac: &str,
    amount_satoshi: u64,
    route: Vec<String>,
    required_signers: Vec<String>,
    remote_hubs: usize,
    local_only: bool,
    schedule: &crate::types::FeeSchedule,
) -> Result<QuoteResult, String> {
    let hops = route.len();
    let confidence = if hops == 0 {
        "none"
    } else if remote_hubs == 0 {
        "high"
    } else if remote_hubs == 1 {
        "medium"
    } else {
        "low"
    };
    let can_pay = hops > 0;
    let agent_hint = if !can_pay {
        "No route — register channels or try another hub / local_only=false with seeds".into()
    } else if remote_hubs > 0 {
        "Path uses remote hub channels; sign on origin hub (foreign inbox → sign_endpoint). Directional liquidity enforced when published.".into()
    } else {
        "Local path — directional liquidity checked when channel balances known.".into()
    };
    let fee_hac_estimate = resolve_fee_hac("", amount_hac, schedule)?;
    Ok(QuoteResult {
        ok: true,
        from: from.into(),
        to: to.into(),
        amount_hac: amount_hac.into(),
        amount_satoshi,
        estimated_sign_rounds: required_signers.len(),
        hops,
        required_signers,
        remote_hubs,
        route,
        can_pay,
        confidence: confidence.into(),
        local_only_used: local_only,
        fee_hac_estimate: fee_hac_estimate.clone(),
        fee_base_mei: schedule.fee_base_mei,
        fee_ppm: schedule.fee_ppm,
        note: "Quote only — no payment created. If fee_hac omitted on pay, hub applies fee_hac_estimate into the signed message.".into(),
        agent_hint,
    })
}

/// Helper used by tests / status mapping.
#[allow(dead_code)]
pub fn smart_view(p: &PaymentSession, base: &str) -> SmartPaymentView {
    smart::smart_payment_view(p, base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FeeSchedule;

    #[test]
    fn resolve_fee_respects_explicit_and_fills_empty() {
        let sched = FeeSchedule {
            fee_base_mei: 1,
            fee_ppm: 0,
            fee_hint: String::new(),
            currency: "HAC",
            note: "",
        };
        assert_eq!(resolve_fee_hac("", "100:247", &sched).unwrap(), "1:248");
        assert_eq!(resolve_fee_hac("0", "100:247", &sched).unwrap(), "0");
        assert_eq!(
            resolve_fee_hac("2:247", "100:247", &sched).unwrap(),
            "2:247"
        );
        let zero = FeeSchedule {
            fee_base_mei: 0,
            fee_ppm: 0,
            fee_hint: String::new(),
            currency: "HAC",
            note: "",
        };
        assert_eq!(resolve_fee_hac("", "100:247", &zero).unwrap(), "0");
    }

    #[test]
    fn fee_ppm_estimate() {
        let sched = FeeSchedule {
            fee_base_mei: 0,
            fee_ppm: 10_000, // 1%
            fee_hint: String::new(),
            currency: "HAC",
            note: "",
        };
        assert_eq!(sched.estimate_mei(100), 1);
        assert_eq!(sched.estimate_zhu(10_000_000_000).unwrap(), 100_000_000);
        assert_eq!(crate::amounts::format_zhu(100_000_000), "1:248");
    }

    #[test]
    fn receipt_hash_stable() {
        let p = PaymentSession {
            id: Uuid::nil(),
            status: crate::types::PaymentStatus::Settled,
            finality: "hub_coordinated_not_l1".into(),
            message: "m".into(),
            message_hash_hex: "ab".repeat(32),
            route: vec!["aa".repeat(16)],
            required_signers: vec!["A".into(), "B".into()],
            payer: "B".into(),
            payee: "A".into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            created_unix: 1,
            updated_unix: 2,
            expires_unix: 0,
            last_error: None,
            signatures: vec![],
            remote_hops: vec![],
        };
        let r1 = build_receipt(&p, "HubA", AgentPaymentMeta::default());
        let r2 = build_receipt(&p, "HubA", AgentPaymentMeta::default());
        assert_eq!(r1.receipt_hash_hex, r2.receipt_hash_hex);
        assert_eq!(r1.receipt_hash_hex.len(), 64);
    }

    #[test]
    fn signed_agent_intent_binds_every_payment_field() {
        let account = crate::hacash_keys::Account::create_by_password("intent-agent").unwrap();
        let message = agent_intent_message(
            "HubA",
            "agent-1",
            account.readable(),
            "payee",
            "1:247",
            0,
            "0",
            &["aa".repeat(16)],
            "",
            "retry-key",
            "nonce-0123456789abcdef",
            1_000,
        )
        .unwrap();
        let hash = crate::hacash_keys::sha3(message.as_bytes());
        let proof = AgentIntentProof {
            nonce: "nonce-0123456789abcdef".into(),
            expires_unix: 1_000,
            signature_hex: crate::crypto::sign_payment_hash(&account, &hash),
            public_key_hex: String::new(),
        };
        assert!(verify_agent_intent(account.readable(), &proof, &message, 900).is_ok());

        let tampered = agent_intent_message(
            "HubA",
            "agent-1",
            account.readable(),
            "attacker",
            "1:247",
            0,
            "0",
            &["aa".repeat(16)],
            "",
            "retry-key",
            "nonce-0123456789abcdef",
            1_000,
        )
        .unwrap();
        assert!(verify_agent_intent(account.readable(), &proof, &tampered, 900).is_err());
        assert!(verify_agent_intent(account.readable(), &proof, &message, 1_000).is_err());
    }
}
