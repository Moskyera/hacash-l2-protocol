"""Unit tests for L1 close intent helpers (no network)."""

from hacash_agent_pay.close import (
    assert_ready_for_close,
    build_close_intent,
    close_checklist,
)


def test_build_close_intent_not_ready():
    intent = build_close_intent(
        {
            "export": {
                "channel_id": "aa" * 32,
                "bill_active": False,
                "last_bill": None,
                "channel": None,
                "fullnode_l1_query": "http://fn",
            }
        }
    )
    assert intent["ready_for_l1_close"] is False
    assert "no_last_bill" in intent["blockers"]
    assert any(c.startswith("blocker:") for c in close_checklist(intent))


def test_build_close_intent_ready():
    pack = {
        "schema": "hacash-l2-close-package/1",
        "channel_id": "bb" * 32,
        "left_address": "L",
        "right_address": "R",
        "distribution_left_hac": "5:247",
        "distribution_right_hac": "5:247",
        "distribution_left_satoshi": 0,
        "distribution_right_satoshi": 0,
        "bill_sequence": 1,
        "bill_message": "m",
        "bill_message_hash_hex": "cc" * 32,
        "bill_signatures": [{"address": "L", "signature_hex": "00"}],
        "both_signed": True,
        "ready_for_l1_close": True,
    }
    intent = build_close_intent(
        {
            "export": {
                "channel_id": "bb" * 32,
                "bill_active": True,
                "last_bill": {"sequence": 1},
                "channel": {"channel_id": "bb" * 32},
                "close_package": pack,
                "fullnode_l1_query": "http://fn/q",
            }
        }
    )
    assert intent["ready_for_l1_close"] is True
    assert intent["distribution"]["left_hac"] == "5:247"
    assert_ready_for_close(intent)


def test_unwraps_agent_close_plan_envelope():
    plan = {
        "schema": "hacash-l2-close-intent/1",
        "ready_for_l1_close": True,
        "blockers": [],
        "channel_id": "x",
    }
    out = build_close_intent({"ok": True, "close_plan": plan})
    assert out["ready_for_l1_close"] is True
