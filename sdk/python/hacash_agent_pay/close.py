"""L1 ChannelClose helpers for agents/wallets (no key custody, no L1 wire encode).

Hub provides last-bill evidence via close-plan / dispute export.
Wallets or fullnode protocol crates build the actual ChannelClose transaction.
"""

from __future__ import annotations

from typing import Any, Optional


CLOSE_INTENT_SCHEMA = "hacash-l2-close-intent/1"


def build_close_intent(export_or_plan: dict) -> dict:
    """
    Normalize hub export / close_plan into a stable close intent for agents.

    Accepts:
      - full GET /v1/agent/v1/close-plan/:id body
      - GET /v1/channels/:id/dispute body ({"ok", "export": ...})
      - raw export / close_plan object
    """
    if not isinstance(export_or_plan, dict):
        return {
            "schema": CLOSE_INTENT_SCHEMA,
            "ready_for_l1_close": False,
            "blockers": ["invalid_input"],
        }

    # Unwrap common envelopes
    if "close_plan" in export_or_plan and isinstance(export_or_plan["close_plan"], dict):
        plan = dict(export_or_plan["close_plan"])
        # Prefer structured plan from hub
        if plan.get("schema") == CLOSE_INTENT_SCHEMA:
            return plan
        export = export_or_plan.get("export") or {}
    elif "export" in export_or_plan and isinstance(export_or_plan["export"], dict):
        export = export_or_plan["export"]
        plan = None
    elif export_or_plan.get("schema") == CLOSE_INTENT_SCHEMA:
        return export_or_plan
    elif "close_package" in export_or_plan or "channel_id" in export_or_plan:
        export = export_or_plan
        plan = None
    else:
        return {
            "schema": CLOSE_INTENT_SCHEMA,
            "ready_for_l1_close": False,
            "blockers": ["unrecognized_payload"],
        }

    if plan is not None and plan.get("schema") == CLOSE_INTENT_SCHEMA:
        return plan

    pack = export.get("close_package") or {}
    blockers: list[str] = []
    if not export.get("channel"):
        blockers.append("channel_not_registered_on_hub")
    if not export.get("last_bill"):
        blockers.append("no_last_bill")
    elif not export.get("bill_active"):
        blockers.append("bill_not_active_need_left_and_right_signatures")
    if not pack:
        blockers.append("missing_close_package")
    else:
        if not pack.get("ready_for_l1_close"):
            blockers.append("close_package_not_ready")
        if not pack.get("both_signed"):
            blockers.append("bill_not_both_signed")

    ready = len(blockers) == 0 and bool(pack.get("ready_for_l1_close"))

    return {
        "schema": CLOSE_INTENT_SCHEMA,
        "channel_id": export.get("channel_id") or pack.get("channel_id") or "",
        "ready_for_l1_close": ready,
        "blockers": blockers,
        "bill_active": bool(export.get("bill_active")),
        "distribution": {
            "left_address": pack.get("left_address"),
            "right_address": pack.get("right_address"),
            "left_hac": pack.get("distribution_left_hac"),
            "right_hac": pack.get("distribution_right_hac"),
            "left_satoshi": pack.get("distribution_left_satoshi", 0),
            "right_satoshi": pack.get("distribution_right_satoshi", 0),
            "bill_sequence": pack.get("bill_sequence"),
            "bill_message_hash_hex": pack.get("bill_message_hash_hex"),
        }
        if pack
        else None,
        "bill_signatures": pack.get("bill_signatures") or [],
        "bill_message": pack.get("bill_message"),
        "bill_message_hash_hex": pack.get("bill_message_hash_hex"),
        "fullnode_l1_query": export.get("fullnode_l1_query") or "",
        "wallet_actions": [
            "1. Confirm ready_for_l1_close == true",
            "2. Query L1 channel via fullnode_l1_query",
            "3. Build ChannelClose with distribution balances (wallet/fullnode protocol)",
            "4. Sign L1 tx with party keys (never send keys to hub)",
            "5. Broadcast signed tx_hex via fullnode or hub POST /v1/l1/submit",
            "6. POST /v1/channels/:id/refresh on hub",
        ],
        "hub_submit": {
            "method": "POST",
            "path": "/v1/l1/submit",
            "body": {"tx_hex": "<already-signed-channel-close-hex>", "path": ""},
            "note": "Hub relays hex only — does not build ChannelClose",
        },
        "disclaimer": export.get("disclaimer")
        or "Hub coordination evidence only — not L1 finality until ChannelClose confirms",
        "evidence_notes": export.get("evidence_notes") or [],
    }


def assert_ready_for_close(intent: dict) -> None:
    """Raise ValueError if not ready for L1 close."""
    if not intent.get("ready_for_l1_close"):
        blockers = intent.get("blockers") or ["not_ready"]
        raise ValueError(f"not ready for L1 close: {', '.join(blockers)}")


def close_checklist(intent: dict) -> list[str]:
    """Human/agent checklist strings."""
    if intent.get("ready_for_l1_close"):
        return list(intent.get("wallet_actions") or [])
    blockers = intent.get("blockers") or []
    return [f"blocker: {b}" for b in blockers] + [
        "Propose last bill on both sides if missing",
        "Left+right sign bill until active",
        "Re-fetch close_plan / export_dispute",
    ]
