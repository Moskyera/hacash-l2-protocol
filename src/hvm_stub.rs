//! Phase D HVM stubs — interfaces for future on-chain escrow / ViewCheckSign.
//!
//! Not executed on L1 yet; agents can reserve intent records on the hub.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowIntent {
    pub id: Uuid,
    pub payer: String,
    pub payee: String,
    pub amount_hac: String,
    pub amount_satoshi: u64,
    pub release_condition: String,
    pub status: String,
    pub created_unix: u64,
    pub note: String,
    /// Future: HVM contract address / script hash
    #[serde(default)]
    pub hvm_target: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateEscrowRequest {
    pub payer: String,
    pub payee: String,
    #[serde(default)]
    pub amount_hac: String,
    #[serde(default)]
    pub amount_satoshi: u64,
    #[serde(default)]
    pub release_condition: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub hvm_target: String,
}

pub fn roadmap() -> serde_json::Value {
    serde_json::json!({
        "phase": "D-stub",
        "status": "intent_only",
        "planned": [
            { "feature": "fee_escrow", "building_block": "VM contracts 40/41/44 or P2SH 46" },
            { "feature": "agent_allowance", "building_block": "account abstraction + ViewCheckSign" },
            { "feature": "operator_treasury", "building_block": "type3 multisig" },
            { "feature": "timed_dispute", "building_block": "HeightScope" },
            { "feature": "conditional_refund", "building_block": "P2SH / BalanceFloor" }
        ],
        "hub_role": "record escrow intents; L1 execution requires fullnode HVM tx submission",
        "docs": "https://hacash.com/HVM"
    })
}
