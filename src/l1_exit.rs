//! Honest L1 exit capability and readiness checks.
//!
//! The active Hacash node currently registers cooperative ChannelClose action
//! 3. Legacy unilateral actions 23/27 exist in older source trees but are not
//! registered by the active node. V2 signatures are also a separate domain and
//! must never be presented as legacy reconciliation signatures.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::channel_state_store::ChannelActivationRecordV1;
use crate::types::LocalChannel;

pub const FULLNODE_CAPABILITIES_API_V1: u64 = 1;
pub const HACASH_MAINNET_CHAIN_ID: u32 = 0;
pub const ACTION_COOPERATIVE_ORIGINAL_CLOSE: u16 = 3;
pub const ACTION_COOPERATIVE_DISTRIBUTION_CLOSE: u16 = 12;
pub const ACTION_UNILATERAL_RECONCILIATION: u16 = 23;
pub const ACTION_CLAIM_DISTRIBUTION: u16 = 27;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FullnodeExitCapabilitiesV1 {
    pub observed_unix: u64,
    pub api_version: u64,
    pub chain_id: u32,
    pub height: u64,
    pub next_height: u64,
    pub mainnet: bool,
    pub registered_actions: Vec<u16>,
    pub enabled_actions: Vec<u16>,
}

impl FullnodeExitCapabilitiesV1 {
    pub fn parse(value: &Value) -> Result<Self, String> {
        if value.get("ret").and_then(Value::as_u64) != Some(0) {
            return Err(format!(
                "fullnode capabilities query failed: {}",
                value
                    .get("err")
                    .and_then(Value::as_str)
                    .unwrap_or("invalid response")
            ));
        }
        let api_version = required_u64(value, "api_version")?;
        if api_version != FULLNODE_CAPABILITIES_API_V1 {
            return Err(format!(
                "unsupported fullnode capabilities api_version {api_version}"
            ));
        }
        let chain = value
            .get("chain")
            .and_then(Value::as_object)
            .ok_or("fullnode capabilities missing chain object")?;
        let chain_id = u32::try_from(required_object_u64(chain, "id")?)
            .map_err(|_| "fullnode chain id exceeds u32")?;
        let height = required_object_u64(chain, "height")?;
        let next_height = required_object_u64(chain, "next_height")?;
        if next_height != height.saturating_add(1) {
            return Err("fullnode capabilities next_height is inconsistent".into());
        }
        let mainnet = chain
            .get("mainnet")
            .and_then(Value::as_bool)
            .ok_or("fullnode capabilities chain.mainnet must be boolean")?;
        if mainnet != (chain_id == HACASH_MAINNET_CHAIN_ID) {
            return Err("fullnode capabilities chain identity is inconsistent".into());
        }
        let actions = value
            .get("actions")
            .and_then(Value::as_object)
            .ok_or("fullnode capabilities missing actions object")?;
        let registered_actions = parse_action_list(actions.get("registered"), "registered")?;
        let enabled_actions = parse_action_list(actions.get("enabled"), "enabled")?;
        if enabled_actions
            .iter()
            .any(|kind| !registered_actions.contains(kind))
        {
            return Err("fullnode enabled action is not registered".into());
        }
        Ok(Self {
            observed_unix: now_unix(),
            api_version,
            chain_id,
            height,
            next_height,
            mainnet,
            registered_actions,
            enabled_actions,
        })
    }

    pub fn action_enabled(&self, kind: u16) -> bool {
        self.enabled_actions.binary_search(&kind).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct L1ExitReadinessV1 {
    pub schema: &'static str,
    pub channel_id: String,
    pub funding_anchor_hash_hex: Option<String>,
    pub fullnode_capabilities: FullnodeExitCapabilitiesV1,
    pub channel_open_on_observed_l1: bool,
    pub v2_activation_present: bool,
    pub v2_verification_head_sequence: Option<u64>,
    pub cooperative_original_funding_close_available: bool,
    pub cooperative_negotiated_distribution_close_available: bool,
    pub legacy_unilateral_reconciliation_actions_available: bool,
    pub v2_state_codec_registered_on_l1: bool,
    pub unilateral_l1_enforceable: bool,
    pub blockers: Vec<&'static str>,
    pub active_action_3_semantics: &'static str,
    pub required_consensus_work: Vec<&'static str>,
}

pub fn build_l1_exit_readiness(
    channel: &LocalChannel,
    activation: Option<&ChannelActivationRecordV1>,
    capabilities: FullnodeExitCapabilitiesV1,
) -> Result<L1ExitReadinessV1, String> {
    let anchor = channel
        .l1_anchor
        .as_ref()
        .ok_or("channel has no verified fullnode funding anchor")?;
    anchor.validate_against_channel(channel)?;
    let channel_open = channel.l1_status == Some(0);
    let cooperative_original =
        channel_open && capabilities.action_enabled(ACTION_COOPERATIVE_ORIGINAL_CLOSE);
    let cooperative_distribution =
        channel_open && capabilities.action_enabled(ACTION_COOPERATIVE_DISTRIBUTION_CLOSE);
    let legacy_unilateral = channel_open
        && capabilities.action_enabled(ACTION_UNILATERAL_RECONCILIATION)
        && capabilities.action_enabled(ACTION_CLAIM_DISTRIBUTION);

    // The active L1 has no registered codec that verifies
    // HACASH_L2_CHANNEL_STATE_V2 / HACASH_L2_CHANNEL_ACTIVATION_V1.
    let v2_state_codec_registered_on_l1 = false;
    let unilateral_l1_enforceable =
        legacy_unilateral && activation.is_some() && v2_state_codec_registered_on_l1;

    let mut blockers = Vec::new();
    if !capabilities.mainnet {
        blockers.push("configured_fullnode_is_not_hacash_mainnet");
    }
    if !channel_open {
        blockers.push("channel_not_open_on_observed_l1");
    }
    if activation.is_none() {
        blockers.push("v2_negotiated_activation_missing");
    }
    if !capabilities.action_enabled(ACTION_UNILATERAL_RECONCILIATION) {
        blockers.push("l1_action_23_unilateral_reconciliation_not_enabled");
    }
    if !capabilities.action_enabled(ACTION_CLAIM_DISTRIBUTION) {
        blockers.push("l1_action_27_claim_distribution_not_enabled");
    }
    if !v2_state_codec_registered_on_l1 {
        blockers.push("l1_does_not_verify_hacash_l2_channel_state_v2");
    }
    blockers.push("portable_l1_channel_inclusion_proof_unavailable");

    Ok(L1ExitReadinessV1 {
        schema: "hacash-l2-l1-exit-readiness/1",
        channel_id: channel.channel_id.clone(),
        funding_anchor_hash_hex: Some(anchor.funding_incarnation_hash_hex.clone()),
        fullnode_capabilities: capabilities,
        channel_open_on_observed_l1: channel_open,
        v2_activation_present: activation.is_some(),
        v2_verification_head_sequence: activation
            .map(|record| record.verification_head.commitment.sequence),
        cooperative_original_funding_close_available: cooperative_original,
        cooperative_negotiated_distribution_close_available: cooperative_distribution,
        legacy_unilateral_reconciliation_actions_available: legacy_unilateral,
        v2_state_codec_registered_on_l1,
        unilateral_l1_enforceable,
        blockers,
        active_action_3_semantics:
            "requires both channel parties to sign the L1 transaction and returns the original L1 funding distribution",
        required_consensus_work: vec![
            "register and activate an L1 action that verifies the V2 state and activation domains",
            "define challenge replacement by strictly higher V2 sequence",
            "define timeout claim/refund using the channel arbitration lock",
            "publish canonical cross-implementation vectors and activation height",
        ],
    })
}

fn parse_action_list(value: Option<&Value>, field: &str) -> Result<Vec<u16>, String> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("fullnode capabilities actions.{field} must be an array"))?;
    let mut seen = HashSet::new();
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let raw = value.as_u64().ok_or_else(|| {
            format!("fullnode capabilities actions.{field} must contain integers")
        })?;
        let kind = u16::try_from(raw)
            .map_err(|_| format!("fullnode capabilities actions.{field} exceeds u16"))?;
        if !seen.insert(kind) {
            return Err(format!(
                "fullnode capabilities actions.{field} contains duplicates"
            ));
        }
        output.push(kind);
    }
    output.sort_unstable();
    Ok(output)
}

fn required_u64(value: &Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("fullnode capabilities {field} must be an integer"))
}

fn required_object_u64(value: &serde_json::Map<String, Value>, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("fullnode capabilities chain.{field} must be an integer"))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities(actions: Vec<u16>) -> Value {
        serde_json::json!({
            "ret": 0,
            "api_version": 1,
            "chain": {
                "id": 0,
                "height": 100,
                "next_height": 101,
                "mainnet": true
            },
            "actions": {
                "registered": actions,
                "enabled": actions
            }
        })
    }

    #[test]
    fn parses_capabilities_and_never_infers_unregistered_unilateral_exit() {
        let parsed = FullnodeExitCapabilitiesV1::parse(&capabilities(vec![1, 2, 3])).unwrap();
        assert!(parsed.action_enabled(3));
        assert!(!parsed.action_enabled(23));
        assert!(!parsed.action_enabled(27));
    }

    #[test]
    fn rejects_inconsistent_or_ambiguous_capabilities() {
        let mut wrong_chain = capabilities(vec![3]);
        wrong_chain["chain"]["id"] = serde_json::json!(1);
        assert!(FullnodeExitCapabilitiesV1::parse(&wrong_chain)
            .unwrap_err()
            .contains("identity"));

        let duplicate = capabilities(vec![3, 3]);
        assert!(FullnodeExitCapabilitiesV1::parse(&duplicate)
            .unwrap_err()
            .contains("duplicates"));

        let mut impossible = capabilities(vec![3]);
        impossible["actions"]["enabled"] = serde_json::json!([3, 23]);
        assert!(FullnodeExitCapabilitiesV1::parse(&impossible)
            .unwrap_err()
            .contains("not registered"));
    }
    #[test]
    fn legacy_unilateral_actions_still_do_not_make_v2_l1_enforceable() {
        let left = crate::hacash_keys::Account::create_by_password("exit-left").unwrap();
        let right = crate::hacash_keys::Account::create_by_password("exit-right").unwrap();
        let channel_id = "42".repeat(16);
        let observation = crate::l1_anchor::parse_fullnode_channel_observation(
            &channel_id,
            &serde_json::json!({
                "ret": 0,
                "id": channel_id,
                "status": 0,
                "open_height": 100,
                "close_height": 0,
                "reuse_version": 1,
                "arbitration_lock": 5000,
                "interest_attribution": 0,
                "left": {
                    "address": left.readable(),
                    "hacash": "6:245",
                    "satoshi": 30
                },
                "right": {
                    "address": right.readable(),
                    "hacash": "4:245",
                    "satoshi": 70
                }
            }),
            200,
            1_700_000_000,
        )
        .unwrap();
        let channel = LocalChannel {
            channel_id: channel_id.clone(),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac: "6:245".into(),
            right_hac: "4:245".into(),
            left_satoshi: 30,
            right_satoshi: 70,
            l1_status: Some(0),
            open_height: Some(100),
            l1_anchor: Some(observation.anchor),
            hub_side: crate::types::HubSide::Unknown,
            notes: String::new(),
            registered_unix: 1,
            balance_source: "l1_fullnode_observation_v1".into(),
            last_settle_payment_id: None,
        };
        let parsed = FullnodeExitCapabilitiesV1::parse(&capabilities(vec![3, 23, 27])).unwrap();
        let readiness = build_l1_exit_readiness(&channel, None, parsed).unwrap();
        assert!(readiness.legacy_unilateral_reconciliation_actions_available);
        assert!(!readiness.v2_state_codec_registered_on_l1);
        assert!(!readiness.unilateral_l1_enforceable);
        assert!(readiness
            .blockers
            .contains(&"l1_does_not_verify_hacash_l2_channel_state_v2"));
        assert_eq!(
            readiness.active_action_3_semantics,
            "requires both channel parties to sign the L1 transaction and returns the original L1 funding distribution"
        );
    }
}
