//! Streaming micropayments between two agents (session + cumulative caps).
//!
//! Each push can optionally create a real HAP payment, or only update the
//! stream ledger (bookkeeping). Payer must sign each push commit when
//! require_sig_verify is on.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::agent_pay::AgentPaymentMeta;
use crate::amounts::DualAmount;
use crate::types::PaymentSignature;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MicroStreamStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroEntry {
    pub sequence: u64,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub note: String,
    pub created_unix: u64,
    /// Real payment id when create_payment was true
    #[serde(default)]
    pub payment_id: Option<Uuid>,
    #[serde(default)]
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroStream {
    pub id: Uuid,
    pub status: MicroStreamStatus,
    pub payer: String,
    pub payee: String,
    /// Compatibility/display cap in whole Mei.
    pub max_hac_mei: u64,
    /// Authoritative exact cap and spend counters.
    #[serde(default)]
    pub max_hac_zhu: u64,
    pub max_satoshi: u64,
    /// Deprecated compatibility counter (whole Mei floor).
    pub spent_hac_mei: u64,
    #[serde(default)]
    pub spent_hac_zhu: u64,
    pub spent_satoshi: u64,
    pub sequence: u64,
    pub create_payments: bool,
    pub local_only: bool,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub meta: AgentPaymentMeta,
    pub created_unix: u64,
    pub updated_unix: u64,
    /// Last N pushes (capped)
    pub entries: Vec<MicroEntry>,
    /// Canonical last state message for optional dual-sign later
    #[serde(default)]
    pub last_state_hash_hex: String,
    #[serde(default)]
    pub last_signatures: Vec<PaymentSignature>,
}

#[derive(Debug, Deserialize)]
pub struct OpenMicroRequest {
    pub payer: String,
    pub payee: String,
    /// Cap HAC integer (mei)
    /// Exact cap in Zhu; preferred for fractional HAC streams.
    #[serde(default)]
    pub max_hac_zhu: u64,
    #[serde(default)]
    pub max_hac_mei: u64,
    #[serde(default)]
    pub max_satoshi: u64,
    /// If true, each push creates a real multi-hop payment session
    #[serde(default)]
    pub create_payments: bool,
    #[serde(default)]
    pub local_only: bool,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub meta: AgentPaymentMeta,
}

#[derive(Debug, Deserialize)]
pub struct PushMicroRequest {
    pub stream_id: String,
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub amount_mei: u64,
    #[serde(default)]
    pub satoshi: u64,
    #[serde(default)]
    pub note: String,
    /// Required when creating real payments
    #[serde(default)]
    pub idempotency_key: String,
    /// Payer signature over push commit (optional if sig_verify off)
    #[serde(default)]
    pub signature_hex: String,
    #[serde(default)]
    pub public_key_hex: String,
}

pub fn stream_state_message(s: &MicroStream) -> String {
    format!(
        "HACASH_MICRO_STREAM_V2\nid={}\nsequence={}\npayer={}\npayee={}\nspent_zhu={}\nspent_sat={}\nmax_zhu={}\nmax_sat={}\nstatus={:?}\n",
        s.id,
        s.sequence,
        s.payer,
        s.payee,
        s.spent_hac_zhu,
        s.spent_satoshi,
        s.max_hac_zhu,
        s.max_satoshi,
        s.status,
    )
}

pub fn push_commit_message(
    stream_id: Uuid,
    sequence: u64,
    payer: &str,
    payee: &str,
    amount: &DualAmount,
    note: &str,
) -> String {
    format!(
        "HACASH_MICRO_PUSH_V1\nstream_id={stream_id}\nsequence={sequence}\npayer={payer}\npayee={payee}\namount_hac={}\namount_satoshi={}\nnote={note}\n",
        amount.amount_hac,
        amount.amount_satoshi,
    )
}

pub fn remaining(s: &MicroStream) -> (u64, u64) {
    (
        s.max_hac_zhu.saturating_sub(s.spent_hac_zhu),
        s.max_satoshi.saturating_sub(s.spent_satoshi),
    )
}
