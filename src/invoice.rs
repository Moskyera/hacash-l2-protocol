//! Agent invoices — request-to-pay (payee creates, payer fulfills).
//!
//! Flow:
//! 1. Payee agent: POST /v1/agent/v1/invoice  → open invoice
//! 2. Payer agent: POST /v1/agent/v1/pay { invoice_id }  → payment linked
//! 3. Both sign as usual; invoice → paid when payment settles

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent_pay::AgentPaymentMeta;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Open,
    /// Payment session created against this invoice
    Paying,
    Paid,
    Cancelled,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: Uuid,
    pub status: InvoiceStatus,
    /// Who should receive funds
    pub payee: String,
    /// Optional fixed payer (empty = anyone may pay)
    #[serde(default)]
    pub payer_hint: String,
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub meta: AgentPaymentMeta,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub updated_unix: u64,
    /// Linked payment when paying/paid
    #[serde(default)]
    pub payment_id: Option<Uuid>,
    /// Webhook URL notified on paid/cancelled (optional)
    #[serde(default)]
    pub callback_url: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateInvoiceRequest {
    pub payee: String,
    #[serde(default)]
    pub payer_hint: String,
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub description: String,
    /// TTL seconds (default 3600, max 7 days)
    #[serde(default)]
    pub ttl_secs: u64,
    #[serde(default)]
    pub meta: AgentPaymentMeta,
    #[serde(default)]
    pub callback_url: String,
}

#[derive(Debug, Deserialize)]
pub struct PayInvoiceRequest {
    pub invoice_id: String,
    pub from: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub meta: AgentPaymentMeta,
    #[serde(default)]
    pub intent: crate::agent_pay::AgentIntentProof,
}
