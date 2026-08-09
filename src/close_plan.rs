//! Agent / wallet L1 ChannelClose helpers (no custody, no unsigned L1 encoding).
//!
//! Hub exports evidence; wallets/fullnode builders produce wire txs.
//! This module only structures a machine-friendly close plan.

use serde_json::{json, Value as JV};

use crate::types::DisputeExport;

/// Build agent-oriented close plan from dispute export (same fields SDKs use).
pub fn build_agent_close_plan(exp: &DisputeExport) -> JV {
    let pack = exp.close_package.as_ref();
    let mut blockers = Vec::new();
    if exp.channel.is_none() {
        blockers.push("channel_not_registered_on_hub");
    }
    if exp.last_bill.is_none() {
        blockers.push("no_last_bill");
    } else if !exp.bill_active {
        blockers.push("bill_not_active_need_left_and_right_signatures");
    }
    if let Some(p) = pack {
        if !p.both_signed {
            blockers.push("bill_not_both_signed");
        }
    } else {
        blockers.push("missing_close_package");
    }
    let evidence_complete =
        exp.bill_active && blockers.is_empty() && pack.map(|p| p.both_signed).unwrap_or(false);
    blockers.push("l1_capabilities_not_verified_use_l1_exit_readiness");
    blockers.push("bill_signatures_are_not_l1_transaction_or_reconciliation_signatures");
    let ready = false;

    let distribution = pack.map(|p| {
        json!({
            "left_address": p.left_address,
            "right_address": p.right_address,
            "left_hac": p.distribution_left_hac,
            "right_hac": p.distribution_right_hac,
            "left_satoshi": p.distribution_left_satoshi,
            "right_satoshi": p.distribution_right_satoshi,
            "bill_sequence": p.bill_sequence,
            "bill_message_hash_hex": p.bill_message_hash_hex,
        })
    });

    let signatures = pack.map(|p| {
        p.bill_signatures
            .iter()
            .map(|s| {
                json!({
                    "address": s.address,
                    "signature_hex": s.signature_hex,
                    "public_key_hex": s.public_key_hex,
                    "verified": s.verified,
                    "order_index": s.order_index,
                })
            })
            .collect::<Vec<_>>()
    });

    json!({
        "schema": "hacash-l2-close-intent/1",
        "channel_id": exp.channel_id,
        "ready_for_l1_close": ready,
        "evidence_complete": evidence_complete,
        "l1_enforceability_verified": false,
        "unilateral_l1_enforceable": false,
        "blockers": blockers,
        "bill_active": exp.bill_active,
        "distribution": distribution,
        "bill_signatures": signatures,
        "bill_message": pack.map(|p| p.bill_message.clone()),
        "bill_message_hash_hex": pack.map(|p| p.bill_message_hash_hex.clone()),
        "fullnode_l1_query": exp.fullnode_l1_query,
        "close_package_schema": pack.map(|p| p.schema),
        "wallet_actions": [
            "1. Fetch /v1/channels/:id/l1-exit/readiness and require capabilities from the configured fullnode",
            "2. Confirm exact enabled L1 action semantics; action 3 returns original L1 funding only",
            "3. Never reuse bill or V2 signatures as L1 transaction/reconciliation signatures",
            "4. Build only an action explicitly enabled by /query/capabilities",
            "5. Sign the L1 transaction in the wallet (never send keys to hub)",
            "6. Broadcast the already-signed tx and monitor L1 inclusion",
            "7. Refresh the hub channel from L1"
        ],
        "hub_submit": {
            "method": "POST",
            "path": "/v1/l1/submit",
            "body": {
                "tx_hex": "<already-signed-channel-close-hex>",
                "path": ""
            },
            "auth": "X-Api-Token or agent API key when configured",
            "note": "Hub only relays hex to fullnode — does not build or sign ChannelClose"
        },
        "disclaimer": exp.disclaimer,
        "evidence_notes": exp.evidence_notes,
        "next_steps": exp.next_steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BillStatus, ChannelBill, ClosePackage, HubSide, LocalChannel};

    #[test]
    fn close_plan_blocks_without_active_bill() {
        let exp = DisputeExport {
            purpose: "l1_arbitration_evidence_package",
            channel_id: "aa".repeat(16),
            channel: None,
            last_bill: None,
            bill_active: false,
            fullnode_l1_query: "http://x".into(),
            disclaimer: "d",
            next_steps: vec![],
            evidence_notes: vec![],
            close_package: None,
        };
        let plan = build_agent_close_plan(&exp);
        assert_eq!(plan["ready_for_l1_close"], false);
        let blockers = plan["blockers"].as_array().unwrap();
        assert!(blockers.iter().any(|b| b.as_str() == Some("no_last_bill")));
    }

    #[test]
    fn evidence_ready_never_implies_l1_exit_ready() {
        let cid = "bb".repeat(16);
        let exp = DisputeExport {
            purpose: "l1_arbitration_evidence_package",
            channel_id: cid.clone(),
            channel: Some(LocalChannel {
                channel_id: cid.clone(),
                left_address: "L".into(),
                right_address: "R".into(),
                left_hac: "5:247".into(),
                right_hac: "5:247".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                l1_status: Some(1),
                open_height: Some(1),
                l1_anchor: None,
                hub_side: HubSide::Unknown,
                notes: String::new(),
                registered_unix: 1,
                balance_source: "registration".into(),
                last_settle_payment_id: None,
            }),
            last_bill: Some(ChannelBill {
                channel_id: cid.clone(),
                sequence: 1,
                status: BillStatus::Active,
                left_address: "L".into(),
                right_address: "R".into(),
                left_hac: "5:247".into(),
                right_hac: "5:247".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                prev_bill_hash: String::new(),
                message: "m".into(),
                message_hash_hex: "cc".repeat(32),
                required_signers: vec!["L".into(), "R".into()],
                signatures: vec![],
                created_unix: 1,
                updated_unix: 1,
                payment_id: None,
                notes: String::new(),
                source: "test".into(),
            }),
            bill_active: true,
            fullnode_l1_query: "http://fn/query".into(),
            disclaimer: "d",
            next_steps: vec![],
            evidence_notes: vec![],
            close_package: Some(ClosePackage {
                schema: "hacash-l2-close-package/1",
                channel_id: cid,
                left_address: "L".into(),
                right_address: "R".into(),
                distribution_left_hac: "5:247".into(),
                distribution_right_hac: "5:247".into(),
                distribution_left_satoshi: 0,
                distribution_right_satoshi: 0,
                bill_sequence: 1,
                bill_message: "m".into(),
                bill_message_hash_hex: "cc".repeat(32),
                bill_signatures: vec![],
                both_signed: true,
                ready_for_l1_close: false,
                l1_actions: vec![],
            }),
        };
        let plan = build_agent_close_plan(&exp);
        assert_eq!(plan["evidence_complete"], true);
        assert_eq!(plan["ready_for_l1_close"], false);
        assert_eq!(plan["unilateral_l1_enforceable"], false);
        assert!(plan["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "l1_capabilities_not_verified_use_l1_exit_readiness"));
        assert_eq!(plan["schema"], "hacash-l2-close-intent/1");
        assert_eq!(plan["distribution"]["left_hac"], "5:247");
    }
}
