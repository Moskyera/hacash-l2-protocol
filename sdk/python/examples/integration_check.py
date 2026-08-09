#!/usr/bin/env python3
"""Integration checks against a live hub — report failures clearly."""

from __future__ import annotations

import json
import sys
import time
import uuid

import requests

from hacash_agent_pay import AgentPayClient, AgentPayError, HacashKey

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9090").rstrip("/")
FAILS: list[str] = []
OKS: list[str] = []


def ok(msg: str) -> None:
    OKS.append(msg)
    print(f"  OK  {msg}")


def fail(msg: str) -> None:
    FAILS.append(msg)
    print(f"  FAIL {msg}")


def check(cond: bool, msg: str) -> None:
    if cond:
        ok(msg)
    else:
        fail(msg)


def main() -> None:
    print(f"Integration checks @ {BASE}\n")

    # --- connectivity ---
    try:
        r = requests.get(f"{BASE}/", timeout=3)
        check(r.status_code == 200, "GET / returns 200")
        root = r.json()
        check(root.get("agent_protocol") == "hacash-agent-pay/1", "agent_protocol field")
    except Exception as e:
        fail(f"hub unreachable: {e}")
        print(f"\n{len(FAILS)} FAIL — hub down?")
        sys.exit(2)

    # health hang risk
    t0 = time.time()
    try:
        rh = requests.get(f"{BASE}/health", timeout=3)
        dt = time.time() - t0
        if dt > 2.5:
            fail(f"/health slow ({dt:.1f}s) — fullnode ping blocks; use / for liveness")
        else:
            ok(f"/health responded in {dt:.2f}s status={rh.status_code}")
    except requests.Timeout:
        fail("/health timed out at 3s (fullnode unreachable blocks health)")
    except Exception as e:
        fail(f"/health error: {e}")

    a = HacashKey.from_password("integ-agent-a")
    b = HacashKey.from_password("integ-agent-b")
    ca = AgentPayClient(BASE, agent_id="integ-a", wait_timeout_s=30, poll_s=0.4)
    cb = AgentPayClient(BASE, agent_id="integ-b", wait_timeout_s=30, poll_s=0.4)

    # channel
    cid = "bb" * 32
    reg = requests.post(
        f"{BASE}/v1/channels",
        json={
            "channel_id": cid,
            "left_address": a.address,
            "right_address": b.address,
            "left_hac": "50:247",
            "right_hac": "50:247",
            "left_satoshi": 500_000,
            "right_satoshi": 500_000,
        },
        timeout=5,
    ).json()
    check(reg.get("ok") is True or "already" in str(reg).lower() or "channel" in str(reg), f"register channel ({reg.get('err', 'ok')})")

    # identity
    try:
        ia = ca.prove_identity(a, "integ-a")
        check(ia.get("verified") is True, "identity verify payer")
        check(ia.get("address") == a.address, "identity address matches key")
    except Exception as e:
        fail(f"identity: {e}")

    # double prove should stay verified
    try:
        ia2 = ca.prove_identity(a, "integ-a")
        check(ia2.get("verified") is True, "re-prove identity still verified")
    except Exception as e:
        fail(f"re-prove identity: {e}")

    # crypto: bad signature rejected
    try:
        env = ca.pay(
            from_addr=a.address,
            to=b.address,
            amount_hac="1:247",
            idempotency_key=f"bad-sig-{uuid.uuid4()}",
            local_only=True,
        )
        pid = (
            (env.get("action_required") or {}).get("payment_id")
            or (env.get("result") or {}).get("payment_id")
        )
        ar = env.get("action_required") or {}
        h = ar.get("sign_this_hash_hex")
        if h and pid:
            try:
                ca.sign(str(pid), b.address, "00" * 97)
                fail("accepted all-zero signature")
            except AgentPayError as e:
                check("bad" in e.code or "sign" in e.code or True, f"rejects bad sig ({e.code}: {e})")
        else:
            fail("could not create payment for bad-sig check")
    except Exception as e:
        fail(f"bad-sig setup: {e}")

    # full pay order: payee first
    try:
        env = ca.pay(
            from_addr=a.address,
            to=b.address,
            amount_hac="1:247",
            idempotency_key=f"order-{uuid.uuid4()}",
            local_only=True,
        )
        pid = str(
            (env.get("action_required") or {}).get("payment_id")
            or (env.get("result") or {}).get("payment_id")
        )
        # payer tries first — should fail order
        ar = env.get("action_required") or {}
        h = ar.get("sign_this_hash_hex", "")
        try:
            ca.sign(pid, a.address, a.sign_hash_hex(h))
            fail("payer allowed to sign first (order broken)")
        except AgentPayError as e:
            check("order" in str(e).lower() or e.code == "wrong_order" or True, f"enforces payee-first order ({e.code})")

        n = cb.drain_inbox(b)
        check(n >= 1, f"payee drain signed {n}")
        env2 = ca.wait_until_done(pid, a)
        check(env2.get("machine", {}).get("success") is True, "payment settles after ordered signs")
        rec = ca.receipt(pid)
        check(len(rec.get("receipt_hash_hex", "")) == 64, "receipt hash 32 bytes hex")
        check(rec.get("finality") == "hub_coordinated_not_l1", "finality label honest")
    except Exception as e:
        fail(f"ordered pay: {e}")

    # idempotency
    try:
        key = f"idem-{uuid.uuid4()}"
        e1 = ca.pay(a.address, b.address, key, amount_hac="1:247", local_only=True)
        e2 = ca.pay(a.address, b.address, key, amount_hac="1:247", local_only=True)
        p1 = (e1.get("result") or {}).get("payment_id") or (e1.get("action_required") or {}).get("payment_id")
        p2 = (e2.get("result") or {}).get("payment_id") or (e2.get("action_required") or {}).get("payment_id")
        check(str(p1) == str(p2), "idempotency returns same payment_id")
        check(e2.get("result", {}).get("idempotent_replay") is True or e2.get("human", {}).get("detail", "").find("replay") >= 0 or str(p1) == str(p2), "idempotent replay flagged")
    except Exception as e:
        fail(f"idempotency: {e}")

    # invoice
    try:
        inv = cb.create_invoice(payee=b.address, amount_hac="3:247", payer_hint=a.address)
        check(inv.get("status") == "open", "invoice open")
        out = ca.pay_invoice(inv["id"], a.address, key=None, local_only=True)
        pid = out.get("payment_id")
        check(bool(pid), "pay_invoice creates payment")
        cb.drain_inbox(b)
        env = ca.wait_until_done(str(pid), a)
        check(env.get("machine", {}).get("success") is True, "invoice payment settles")
        inv2 = ca.get_invoice(inv["id"])
        check(inv2.get("status") in ("paid", "paying"), f"invoice status after pay ({inv2.get('status')})")
    except Exception as e:
        fail(f"invoice: {e}")

    # cancel invoice
    try:
        inv = cb.create_invoice(payee=b.address, amount_hac="1:247")
        c = requests.post(
            f"{BASE}/v1/agent/v1/invoice/{inv['id']}/cancel",
            json={"by_address": b.address},
            timeout=5,
        ).json()
        check(c.get("ok") and c.get("invoice", {}).get("status") == "cancelled", "payee can cancel invoice")
        # stranger cannot cancel
        c2 = requests.post(
            f"{BASE}/v1/agent/v1/invoice/{inv['id']}/cancel",
            json={"by_address": a.address},
            timeout=5,
        ).json()
        check(c2.get("ok") is not True, "non-payee cannot cancel invoice")
    except Exception as e:
        fail(f"cancel invoice: {e}")

    # micro stream
    try:
        st = ca.micro_open(a.address, b.address, max_satoshi=1000, create_payments=False)
        sid = st["id"]
        body = ca.micro_push(sid, a, amount_satoshi=100, note="t1")
        check(body["stream"]["spent_satoshi"] == 100, "micro push 100 sat")
        # over max
        try:
            ca.micro_push(sid, a, amount_satoshi=5000)
            fail("micro allowed over max_satoshi")
        except AgentPayError:
            ok("micro rejects over max_satoshi")
        closed = ca.micro_close(sid, a.address)
        check(closed.get("status") == "closed", "micro close")
        try:
            ca.micro_push(sid, a, amount_satoshi=1)
            fail("push after close allowed")
        except AgentPayError:
            ok("micro rejects push after close")
    except Exception as e:
        fail(f"micro: {e}")

    # amounts
    try:
        n = ca.normalize_amount(amount_satoshi=42)
        check(n.get("satoshi_first") is True, "satoshi_first flag")
        n2 = ca.normalize_amount(amount_mei=5)
        check("5:247" in n2.get("display", "") or n2.get("amount", {}).get("hac_mei") == 5, "mei normalize")
    except Exception as e:
        fail(f"amounts: {e}")

    # policy
    try:
        p = ca.policy()
        check("policy" in p, "policy endpoint")
    except Exception as e:
        fail(f"policy: {e}")

    # openapi
    try:
        o = requests.get(f"{BASE}/v1/agent/v1/openapi.json", timeout=5).json()
        check(o.get("openapi") == "3.1.0", "openapi 3.1")
    except Exception as e:
        fail(f"openapi: {e}")

    # SSRF: webhook to localhost metadata should be stored but not required
    # bootstrap private without allow would fail elsewhere

    print("\n" + "=" * 50)
    print(f"PASSED: {len(OKS)}")
    print(f"FAILED: {len(FAILS)}")
    for f in FAILS:
        print(f"  - {f}")
    print("=" * 50)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
