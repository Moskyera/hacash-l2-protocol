//! Agent spend policy + simple ledger (hub-side soft limits).
//!
//! Rate / open-payment limits are keyed by a **policy principal**, not free-form
//! `agent_id` alone:
//! - verified identity → `v:{hacash_address}` (cannot bypass by rotating agent_id)
//! - unverified named agent → `u:{agent_id}`
//! - anonymous → `a:{payer_address}` when known, else `anon`

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    /// Maximum whole Mei (whole HAC) for one payment; enforced against exact Zhu.
    pub max_amount_mei: u64,
    /// Max settled payments per **policy principal** per rolling hour
    pub max_payments_per_hour: u32,
    /// Max concurrent open collecting payments per principal
    pub max_open_payments: u32,
    /// If non-empty, only these payees allowed for this agent
    #[serde(default)]
    pub payee_allowlist: Vec<String>,
    /// If non-empty, only these agent_ids may use pay (checked on claimed agent_id)
    #[serde(default)]
    pub agent_allowlist: Vec<String>,
}

/// Stable bucket for spend limits (ledger + open-payment caps).
///
/// `verified_address` = identity.address when agent_id is registered+verified.
pub fn policy_principal(agent_id: &str, payer: &str, verified_address: Option<&str>) -> String {
    if let Some(addr) = verified_address.map(str::trim).filter(|a| !a.is_empty()) {
        return format!("v:{addr}");
    }
    let aid = agent_id.trim();
    if !aid.is_empty() && aid != "anonymous" {
        return format!("u:{aid}");
    }
    let p = payer.trim();
    if !p.is_empty() {
        return format!("a:{p}");
    }
    "anon".into()
}

/// Whether payment meta belongs to the same policy principal.
pub fn meta_matches_principal(
    meta_agent_id: &str,
    meta_policy_principal: &str,
    meta_identity_address: &str,
    principal: &str,
) -> bool {
    if !meta_policy_principal.is_empty() {
        return meta_policy_principal == principal;
    }
    // Legacy metas (no policy_principal field): best-effort match
    if let Some(addr) = principal.strip_prefix("v:") {
        return meta_identity_address == addr;
    }
    if let Some(aid) = principal.strip_prefix("u:") {
        return meta_agent_id == aid;
    }
    if let Some(payer) = principal.strip_prefix("a:") {
        // legacy anonymous: only agent_id empty/anonymous
        return (meta_agent_id.is_empty() || meta_agent_id == "anonymous")
            && meta_identity_address.is_empty()
            && !payer.is_empty();
    }
    meta_agent_id == principal || principal == "anon"
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            max_amount_mei: 1_000_000, // generous default
            max_payments_per_hour: 500,
            max_open_payments: 50,
            payee_allowlist: vec![],
            agent_allowlist: vec![],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentLedgerEntry {
    /// Policy principal key (`v:addr` / `u:id` / `a:payer` / `anon`).
    pub agent_id: String,
    pub payments_created: u64,
    pub payments_settled: u64,
    pub payments_failed: u64,
    pub last_payment_unix: u64,
    /// Rolling window timestamps of creates (unix)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_creates: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentLedger {
    pub by_agent: HashMap<String, AgentLedgerEntry>,
}

impl AgentLedger {
    pub fn snapshot(&self) -> Vec<AgentLedgerEntry> {
        self.by_agent
            .values()
            .map(|e| AgentLedgerEntry {
                agent_id: e.agent_id.clone(),
                payments_created: e.payments_created,
                payments_settled: e.payments_settled,
                payments_failed: e.payments_failed,
                last_payment_unix: e.last_payment_unix,
                recent_creates: vec![],
            })
            .collect()
    }

    pub fn record_create(&mut self, agent_id: &str, now: u64) {
        let e = self
            .by_agent
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentLedgerEntry {
                agent_id: agent_id.to_string(),
                ..Default::default()
            });
        e.payments_created += 1;
        e.last_payment_unix = now;
        e.recent_creates.push(now);
        // keep last hour only
        e.recent_creates.retain(|t| now.saturating_sub(*t) <= 3600);
    }

    pub fn record_settled(&mut self, agent_id: &str) {
        if let Some(e) = self.by_agent.get_mut(agent_id) {
            e.payments_settled += 1;
        }
    }

    pub fn record_failed(&mut self, agent_id: &str) {
        if let Some(e) = self.by_agent.get_mut(agent_id) {
            e.payments_failed += 1;
        }
    }

    pub fn creates_last_hour(&self, agent_id: &str, now: u64) -> u32 {
        self.by_agent
            .get(agent_id)
            .map(|e| {
                e.recent_creates
                    .iter()
                    .filter(|t| now.saturating_sub(**t) <= 3600)
                    .count() as u32
            })
            .unwrap_or(0)
    }
}

pub fn check_pay_policy(
    policy: &AgentPolicy,
    agent_id: &str,
    payee: &str,
    amount_hac: &str,
    open_for_agent: u32,
    creates_last_hour: u32,
) -> Result<(), String> {
    if !policy.agent_allowlist.is_empty() && !policy.agent_allowlist.iter().any(|a| a == agent_id) {
        return Err(format!("agent_id '{agent_id}' not in hub agent_allowlist"));
    }
    if !policy.payee_allowlist.is_empty() && !policy.payee_allowlist.iter().any(|a| a == payee) {
        return Err(format!("payee '{payee}' not in hub payee_allowlist"));
    }
    let amount_zhu = crate::amounts::parse_zhu(amount_hac)?;
    let max_zhu = policy
        .max_amount_mei
        .checked_mul(crate::amounts::ZHU_PER_MEI)
        .ok_or_else(|| "max_amount_mei exceeds the L2 u64 Zhu range".to_string())?;
    if amount_zhu > max_zhu {
        return Err(format!(
            "amount {amount_zhu} Zhu exceeds max_amount_mei {}",
            policy.max_amount_mei
        ));
    }
    if open_for_agent >= policy.max_open_payments {
        return Err(format!(
            "too many open payments for agent (max {})",
            policy.max_open_payments
        ));
    }
    if creates_last_hour >= policy.max_payments_per_hour {
        return Err(format!(
            "rate limit: max {} payments/hour for agent",
            policy.max_payments_per_hour
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_verified_beats_agent_id_rotation() {
        let a = policy_principal("bot-1", "1Payer", Some("1AbcAddress"));
        let b = policy_principal("bot-2-rotated", "1Payer", Some("1AbcAddress"));
        assert_eq!(a, b);
        assert_eq!(a, "v:1AbcAddress");
    }

    #[test]
    fn principal_unverified_uses_agent_id() {
        assert_eq!(policy_principal("bot-1", "1Payer", None), "u:bot-1");
    }

    #[test]
    fn principal_anonymous_binds_payer() {
        assert_eq!(policy_principal("", "1PayerXX", None), "a:1PayerXX");
        assert_eq!(
            policy_principal("anonymous", "1PayerXX", None),
            "a:1PayerXX"
        );
    }

    #[test]
    fn meta_match_by_stored_principal() {
        assert!(meta_matches_principal(
            "bot-1", "v:1Addr", "1Addr", "v:1Addr"
        ));
        assert!(!meta_matches_principal(
            "bot-1", "v:1Addr", "1Addr", "v:Other"
        ));
    }
}
