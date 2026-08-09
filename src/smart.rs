//! Smart UX layer for wallets and AI agents.
//!
//! Hides multi-step L2 protocol behind:
//! - clear **next action**
//! - plain-language UI strings
//! - agent tool / step machine
//!
//! Low-level `/v1/payments`, `/v1/channels/...` APIs remain for power users.

use serde::Serialize;
use serde_json::{json, Value as JV};
use uuid::Uuid;

use crate::types::{
    BillStatus, ChannelBill, LocalChannel, PaymentSession, PaymentSignature, PaymentStatus,
};

/// What the client should do next (wallet button or agent tool call).
#[derive(Debug, Clone, Serialize)]
pub struct NextAction {
    /// Machine id: `sign_payment`, `wait_others`, `propose_bill`, `done`, `create_payment`, …
    pub id: String,
    /// HTTP method if applicable
    pub method: String,
    /// Path relative to hub base (may include ids)
    pub path: String,
    /// Short label for UI button
    pub label: String,
    /// Who should act (address or role)
    pub actor: String,
    /// Human explanation
    pub detail: String,
    /// Suggested JSON body (agent can POST as-is after filling signature)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_template: Option<JV>,
}

/// Wallet-friendly panel.
#[derive(Debug, Clone, Serialize)]
pub struct UiHint {
    pub title: String,
    pub subtitle: String,
    pub status_emoji: String,
    pub progress: String,
    pub can_user_act: bool,
}

/// Agent step-machine payload.
#[derive(Debug, Clone, Serialize)]
pub struct AgentStep {
    pub state: String,
    pub done: bool,
    pub success: bool,
    pub next_tool: String,
    pub wait_for: String,
    pub instructions: Vec<String>,
}

/// Full smart payment view (create / get / sign responses share this).
#[derive(Debug, Clone, Serialize)]
pub struct SmartPaymentView {
    pub payment_id: Uuid,
    pub status: PaymentStatus,
    pub finality: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub payer: String,
    pub payee: String,
    pub route_hops: usize,
    pub required_signers: Vec<String>,
    pub signed_by: Vec<String>,
    pub next_signer: Option<String>,
    pub message_hash_hex: String,
    /// Raw 32-byte hash hex already — same as message_hash_hex
    pub sign_this_hash_hex: String,
    pub signatures: Vec<PaymentSignature>,
    pub remote_hubs: usize,
    pub expires_unix: u64,
    pub ui: UiHint,
    pub next: Option<NextAction>,
    pub agent: AgentStep,
    pub tips: Vec<&'static str>,
}

pub fn next_signer(p: &PaymentSession) -> Option<String> {
    if !matches!(
        p.status,
        PaymentStatus::Pending | PaymentStatus::CollectingSignatures
    ) {
        return None;
    }
    for s in &p.required_signers {
        if !p.signatures.iter().any(|sig| &sig.address == s) {
            return Some(s.clone());
        }
    }
    None
}

pub fn signed_addresses(p: &PaymentSession) -> Vec<String> {
    p.signatures.iter().map(|s| s.address.clone()).collect()
}

pub fn payment_progress(p: &PaymentSession) -> String {
    let done = p.signatures.len();
    let total = p.required_signers.len().max(1);
    format!("{done}/{total} signatures")
}

pub fn smart_payment_view(p: &PaymentSession, hub_base: &str) -> SmartPaymentView {
    let base = hub_base.trim_end_matches('/');
    let next_sig = next_signer(p);
    let signed = signed_addresses(p);
    let progress = payment_progress(p);

    let (ui, next, agent) = match p.status {
        PaymentStatus::Settled => (
            UiHint {
                title: "Payment complete (hub)".into(),
                subtitle: "All parties signed. This is hub-coordinated — not L1 ChannelClose."
                    .into(),
                status_emoji: "✅".into(),
                progress: progress.clone(),
                can_user_act: true,
            },
            Some(NextAction {
                id: "optional_bill".into(),
                method: "POST".into(),
                path: if let Some(cid) = p.route.first() {
                    format!("/v1/channels/{cid}/bill")
                } else {
                    "/v1/bills".into()
                },
                label: "Update channel bill (optional)".into(),
                actor: "payer_and_payee".into(),
                detail: "After a successful pay, both channel sides can lock a new last bill."
                    .into(),
                body_template: Some(json!({
                    "left_hac": "…",
                    "right_hac": "…",
                    "payment_id": p.id,
                    "notes": "post-payment reconciliation"
                })),
            }),
            AgentStep {
                state: "settled_hub".into(),
                done: true,
                success: true,
                next_tool: "optional_bill_or_stop".into(),
                wait_for: "none".into(),
                instructions: vec![
                    "Hub payment settled (coordinated signatures only).".into(),
                    "Optionally propose last bill on each route channel.".into(),
                    "Do NOT treat as L1 final until ChannelClose on fullnode.".into(),
                ],
            },
        ),
        PaymentStatus::Committing => (
            UiHint {
                title: "Finalizing across hubs".into(),
                subtitle: "A durable commit decision exists; offline hubs are being retried."
                    .into(),
                status_emoji: "⏳".into(),
                progress: progress.clone(),
                can_user_act: false,
            },
            None,
            AgentStep {
                state: "distributed_commit_pending".into(),
                done: false,
                success: false,
                next_tool: "poll_payment_status".into(),
                wait_for: "hub_commit_acknowledgements".into(),
                instructions: vec![
                    "Do not create a replacement payment.".into(),
                    "The commit decision is durable and will be retried after restart.".into(),
                    "Poll the payment status until settled.".into(),
                ],
            },
        ),
        PaymentStatus::Failed => (
            UiHint {
                title: "Payment failed".into(),
                subtitle: p
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "Cancelled or rejected".into()),
                status_emoji: "❌".into(),
                progress: progress.clone(),
                can_user_act: false,
            },
            None,
            AgentStep {
                state: "failed".into(),
                done: true,
                success: false,
                next_tool: "create_new_payment".into(),
                wait_for: "none".into(),
                instructions: vec!["Create a new payment if still needed.".into()],
            },
        ),
        PaymentStatus::TimedOut => (
            UiHint {
                title: "Payment expired".into(),
                subtitle: "Session TTL elapsed before all signatures.".into(),
                status_emoji: "⏰".into(),
                progress: progress.clone(),
                can_user_act: false,
            },
            Some(NextAction {
                id: "create_payment".into(),
                method: "POST".into(),
                path: "/v1/wallet/pay".into(),
                label: "Start new payment".into(),
                actor: "payer".into(),
                detail: "Previous session timed out.".into(),
                body_template: Some(json!({
                    "from": p.payer,
                    "to": p.payee,
                    "amount_hac": p.amount_hac,
                })),
            }),
            AgentStep {
                state: "timed_out".into(),
                done: true,
                success: false,
                next_tool: "wallet_pay".into(),
                wait_for: "none".into(),
                instructions: vec!["Call wallet_pay again with same from/to/amount.".into()],
            },
        ),
        PaymentStatus::Pending | PaymentStatus::CollectingSignatures => {
            let actor = next_sig.clone().unwrap_or_else(|| "unknown".into());
            let is_first = signed.is_empty();
            (
                UiHint {
                    title: if is_first {
                        "Waiting for first signature".into()
                    } else {
                        "Waiting for next signature".into()
                    },
                    subtitle: format!("Next signer: {actor} ({progress})"),
                    status_emoji: "✍️".into(),
                    progress: progress.clone(),
                    can_user_act: true,
                },
                Some(NextAction {
                    id: "sign_payment".into(),
                    method: "POST".into(),
                    path: format!("/v1/wallet/sign/{}", p.id),
                    label: format!("Sign as {actor}"),
                    actor: actor.clone(),
                    detail: format!(
                        "Sign message_hash_hex with Hacash key for {actor}, then POST signature_hex (97-byte Sign)."
                    ),
                    body_template: Some(json!({
                        "address": actor,
                        "signature_hex": "<97-byte-hex-pubkey||sig>",
                        "public_key_hex": ""
                    })),
                }),
                AgentStep {
                    state: "need_signature".into(),
                    done: false,
                    success: false,
                    next_tool: "sign_payment_hash".into(),
                    wait_for: actor.clone(),
                    instructions: vec![
                        format!("Load message_hash_hex: {}", p.message_hash_hex),
                        format!("Sign 32-byte hash with private key of {actor}"),
                        format!("POST {base}/v1/wallet/sign/{} with address + signature_hex", p.id),
                        "If you are not next_signer, wait or notify that party.".into(),
                    ],
                },
            )
        }
    };

    SmartPaymentView {
        payment_id: p.id,
        status: p.status,
        finality: p.finality.clone(),
        amount_hac: p.amount_hac.clone(),
        amount_satoshi: p.amount_satoshi,
        payer: p.payer.clone(),
        payee: p.payee.clone(),
        route_hops: p.route.len(),
        required_signers: p.required_signers.clone(),
        signed_by: signed,
        next_signer: next_sig,
        message_hash_hex: p.message_hash_hex.clone(),
        sign_this_hash_hex: p.message_hash_hex.clone(),
        signatures: p.signatures.clone(),
        remote_hubs: p.remote_hops.len(),
        expires_unix: p.expires_unix,
        ui,
        next,
        agent,
        tips: vec![
            "User never needs to understand hubs if the wallet calls /v1/wallet/* only.",
            "settled = hub coordinated, not L1 final.",
            "signature_hex = 97-byte Hacash Sign (compressed pubkey || ecdsa).",
        ],
    }
}

pub fn smart_bill_view(b: &ChannelBill, hub_base: &str) -> JV {
    let base = hub_base.trim_end_matches('/');
    let signed: Vec<_> = b.signatures.iter().map(|s| s.address.clone()).collect();
    let next = b
        .required_signers
        .iter()
        .find(|s| !signed.iter().any(|x| x == *s))
        .cloned();
    let (title, emoji, can_act) = match b.status {
        BillStatus::Active => ("Channel bill active (last only)".to_string(), "✅", false),
        BillStatus::CollectingSignatures => (
            format!(
                "Bill needs signature from {}",
                next.clone().unwrap_or_else(|| "?".into())
            ),
            "✍️",
            true,
        ),
    };
    json!({
        "channel_id": b.channel_id,
        "sequence": b.sequence,
        "status": b.status,
        "left_hac": b.left_hac,
        "right_hac": b.right_hac,
        "left_satoshi": b.left_satoshi,
        "right_satoshi": b.right_satoshi,
        "message_hash_hex": b.message_hash_hex,
        "sign_this_hash_hex": b.message_hash_hex,
        "required_signers": b.required_signers,
        "signed_by": signed,
        "next_signer": next,
        "ui": {
            "title": title,
            "status_emoji": emoji,
            "can_user_act": can_act,
            "progress": format!("{}/{} signatures", b.signatures.len(), b.required_signers.len()),
        },
        "next": if b.status == BillStatus::CollectingSignatures {
            json!({
                "id": "sign_bill",
                "method": "POST",
                "path": format!("/v1/wallet/bill/{}/sign", b.channel_id),
                "label": "Sign channel bill",
                "actor": next,
                "body_template": {
                    "address": next,
                    "signature_hex": "<97-byte-hex>"
                }
            })
        } else {
            json!({
                "id": "export_dispute",
                "method": "GET",
                "path": format!("/v1/channels/{}/bill/export", b.channel_id),
                "label": "Export for L1 dispute",
            })
        },
        "agent": {
            "state": match b.status {
                BillStatus::Active => "bill_active",
                BillStatus::CollectingSignatures => "bill_need_signature",
            },
            "done": b.status == BillStatus::Active,
            "next_tool": if b.status == BillStatus::Active { "stop_or_export" } else { "sign_bill_hash" },
            "hub_base": base,
        }
    })
}

/// Address-centric snapshot for wallet home screen / agent "my state".
#[derive(Debug, Clone, Serialize)]
pub struct AddressSnapshot {
    pub address: String,
    pub channels: Vec<LocalChannel>,
    pub bills: Vec<ChannelBill>,
    pub open_payments: Vec<SmartPaymentView>,
    pub recent_settled: Vec<SmartPaymentView>,
    pub ui: UiHint,
    pub next: Option<NextAction>,
    pub agent: AgentStep,
}

pub fn build_address_snapshot(
    address: &str,
    channels: Vec<LocalChannel>,
    bills: Vec<ChannelBill>,
    payments: Vec<PaymentSession>,
    hub_base: &str,
) -> AddressSnapshot {
    let addr = address.trim();
    let mut open = Vec::new();
    let mut settled = Vec::new();
    for p in payments {
        let involves =
            p.payer == addr || p.payee == addr || p.required_signers.iter().any(|s| s == addr);
        if !involves {
            continue;
        }
        let view = smart_payment_view(&p, hub_base);
        match p.status {
            PaymentStatus::Settled => {
                if settled.len() < 10 {
                    settled.push(view);
                }
            }
            PaymentStatus::Failed | PaymentStatus::TimedOut => {}
            _ => open.push(view),
        }
    }

    // Prefer action on a payment where this address is next signer
    let next = open
        .iter()
        .find(|v| v.next_signer.as_deref() == Some(addr))
        .and_then(|v| v.next.clone())
        .or_else(|| {
            open.first().and_then(|v| v.next.clone()).or_else(|| {
                Some(NextAction {
                    id: "pay".into(),
                    method: "POST".into(),
                    path: "/v1/wallet/pay".into(),
                    label: "Send instant pay".into(),
                    actor: addr.into(),
                    detail: "Create a multi-hop L2 payment from this address.".into(),
                    body_template: Some(json!({
                        "from": addr,
                        "to": "<payee_address>",
                        "amount_hac": "1:247"
                    })),
                })
            })
        });

    let can_act = next
        .as_ref()
        .map(|n| n.actor == addr || n.actor == "payer")
        .unwrap_or(false);

    let n_ch = channels.len();
    let n_open = open.len();
    let snap = AddressSnapshot {
        address: addr.into(),
        channels,
        bills,
        open_payments: open,
        recent_settled: settled,
        ui: UiHint {
            title: "Your L2 snapshot".into(),
            subtitle: format!("{n_ch} channel(s), {n_open} open payment(s)"),
            status_emoji: "💼".into(),
            progress: if n_open > 0 {
                format!("{n_open} need attention")
            } else {
                "idle".into()
            },
            can_user_act: can_act,
        },
        next,
        agent: AgentStep {
            state: "address_home".into(),
            done: false,
            success: true,
            next_tool: "follow_next_or_wallet_pay".into(),
            wait_for: "user_or_keys".into(),
            instructions: vec![
                "If open_payments has next_signer == this address, sign it.".into(),
                "Else POST /v1/wallet/pay to start a payment.".into(),
                "Use GET /v1/wallet/me?address=… to refresh.".into(),
            ],
        },
    };
    snap
}

/// OpenAPI-ish tool list for AI agents (legacy; prefer agent_pay::agent_tools_schema).
#[allow(dead_code)]
pub fn agent_tools(hub_base: &str) -> Vec<JV> {
    let base = hub_base.trim_end_matches('/');
    vec![
        json!({
            "name": "agent_start",
            "description": "Call first. Returns which hub to use, tools, and playbook.",
            "method": "GET",
            "url": format!("{base}/v1/agent/start"),
            "parameters": {}
        }),
        json!({
            "name": "wallet_me",
            "description": "Home screen for an address: channels, bills, open payments, next action.",
            "method": "GET",
            "url": format!("{base}/v1/wallet/me?address={{address}}"),
            "parameters": { "address": { "type": "string", "required": true } }
        }),
        json!({
            "name": "wallet_pay",
            "description": "Start instant L2 payment. Returns message hash to sign and next_signer.",
            "method": "POST",
            "url": format!("{base}/v1/wallet/pay"),
            "parameters": {
                "from": { "type": "string", "required": true, "description": "payer address" },
                "to": { "type": "string", "required": true, "description": "payee address" },
                "amount_hac": { "type": "string", "required": true, "example": "1:247" },
                "amount_satoshi": { "type": "integer", "required": false },
                "local_only": { "type": "boolean", "required": false }
            }
        }),
        json!({
            "name": "wallet_sign",
            "description": "Submit secp256k1 signature for a payment. Returns updated next step.",
            "method": "POST",
            "url": format!("{base}/v1/wallet/sign/{{payment_id}}"),
            "parameters": {
                "address": { "type": "string", "required": true },
                "signature_hex": { "type": "string", "required": true, "description": "97-byte Sign hex" }
            }
        }),
        json!({
            "name": "payment_next",
            "description": "Poll payment status + next action without full history.",
            "method": "GET",
            "url": format!("{base}/v1/wallet/payment/{{payment_id}}"),
            "parameters": { "payment_id": { "type": "string", "required": true } }
        }),
        json!({
            "name": "find_hubs",
            "description": "Wallet Find hubs — scored public directory.",
            "method": "GET",
            "url": format!("{base}/v1/wallet/start"),
            "parameters": {}
        }),
        json!({
            "name": "bill_propose",
            "description": "Propose last reconciliation bill for a channel (client balances only).",
            "method": "POST",
            "url": format!("{base}/v1/wallet/bill/{{channel_id}}"),
            "parameters": {
                "left_hac": { "type": "string" },
                "right_hac": { "type": "string" },
                "payment_id": { "type": "string", "required": false }
            }
        }),
        json!({
            "name": "bill_sign",
            "description": "Sign a channel bill as left or right party.",
            "method": "POST",
            "url": format!("{base}/v1/wallet/bill/{{channel_id}}/sign"),
            "parameters": {
                "address": { "type": "string" },
                "signature_hex": { "type": "string" }
            }
        }),
    ]
}

/// Simple playbook steps for agents (ordered). Prefer HAP manifest.
#[allow(dead_code)]
pub fn agent_playbook() -> Vec<&'static str> {
    vec![
        "1. GET /v1/agent/start — attach hub + tools",
        "2. GET /v1/wallet/me?address=YOUR_ADDR — see open work",
        "3. POST /v1/wallet/pay {from,to,amount_hac} — start pay",
        "4. Sign sign_this_hash_hex with local key (never send private key)",
        "5. POST /v1/wallet/sign/{id} until agent.done=true",
        "6. Optional: POST bill balances after settle",
        "7. Never claim L1 finality from hub settled alone",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PaymentStatus;

    fn dummy_pay() -> PaymentSession {
        PaymentSession {
            id: Uuid::nil(),
            status: PaymentStatus::CollectingSignatures,
            finality: "hub_coordinated_not_l1".into(),
            message: "HACASH_L2_PAYMENT_V1\n".into(),
            message_hash_hex: "ab".repeat(32),
            route: vec!["aa".repeat(16)],
            required_signers: vec!["Payee".into(), "Payer".into()],
            payer: "Payer".into(),
            payee: "Payee".into(),
            amount_hac: "1:247".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            created_unix: 1,
            updated_unix: 1,
            expires_unix: 100,
            last_error: None,
            signatures: vec![],
            remote_hops: vec![],
        }
    }

    #[test]
    fn next_signer_is_payee_first() {
        let p = dummy_pay();
        assert_eq!(next_signer(&p).as_deref(), Some("Payee"));
        let v = smart_payment_view(&p, "http://127.0.0.1:9090");
        assert_eq!(v.next.as_ref().unwrap().id, "sign_payment");
        assert!(!v.agent.done);
    }
}
