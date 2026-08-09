#!/usr/bin/env python3
"""
Live demo: two agents on local hub — identity, pay, micro stream, receipt.

  # terminal 1: hub already running on :9090
  python examples/demo_agents.py http://127.0.0.1:9090
"""

from __future__ import annotations

import sys
import time
import uuid

import requests

from hacash_agent_pay import AgentPayClient, HacashKey

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9090").rstrip("/")


def wait_hub(base: str, tries: int = 40) -> None:
    for i in range(tries):
        try:
            # Prefer / over /health — health waits on fullnode and can hang.
            r = requests.get(f"{base}/", timeout=2)
            if r.status_code == 200:
                print(f"[hub] up ({r.status_code})")
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise SystemExit(f"hub not reachable at {base}")


def register_channel(base: str, left: str, right: str) -> str:
    # 32-byte channel id (demo)
    cid = "aa" * 32
    body = {
        "channel_id": cid,
        "left_address": left,
        "right_address": right,
        "left_hac": "100:247",
        "right_hac": "100:247",
        "left_satoshi": 1_000_000,
        "right_satoshi": 1_000_000,
        "hub_side": "right",
        "notes": "demo channel",
    }
    r = requests.post(f"{base}/v1/channels", json=body, timeout=10)
    data = r.json()
    if not data.get("ok"):
        # already registered is fine for re-runs
        if "too many" in str(data.get("err", "")):
            raise SystemExit(data)
        print(f"[channel] register: {data.get('err', data)}")
    else:
        print(f"[channel] registered {cid[:16]}…")
    return cid


def main() -> None:
    print("=" * 60)
    print("Hacash L2 Agent Pay — LIVE DEMO")
    print(f"hub: {BASE}")
    print("=" * 60)

    wait_hub(BASE)

    payer_key = HacashKey.from_password("demo-payer-agent")
    payee_key = HacashKey.from_password("demo-payee-agent")
    print(f"[keys] payer {payer_key.address}")
    print(f"[keys] payee {payee_key.address}")

    register_channel(BASE, payer_key.address, payee_key.address)

    payer = AgentPayClient(BASE, agent_id="demo-payer")
    payee = AgentPayClient(BASE, agent_id="demo-payee")

    # --- Identity ---
    print("\n--- 1) Identity ---")
    id_p = payer.prove_identity(payer_key, "demo-payer")
    id_e = payee.prove_identity(payee_key, "demo-payee")
    print(f"  payer verified={id_p.get('verified')} addr={id_p.get('address')}")
    print(f"  payee verified={id_e.get('verified')} addr={id_e.get('address')}")

    # --- Manifest ---
    man = payer.manifest()
    print(f"\n--- 2) Manifest protocol={man.get('protocol')} ---")

    # --- Quote + Pay ---
    print("\n--- 3) Quote + Pay (1:247 HAC) ---")
    q = payer.quote(
        payer_key.address,
        payee_key.address,
        amount_hac="1:247",
        local_only=True,
    )
    print(f"  can_pay={q.get('can_pay')} hops={q.get('hops')} signers={q.get('required_signers')}")

    idem = f"demo-pay-{uuid.uuid4()}"
    env = payer.pay(
        from_addr=payer_key.address,
        to=payee_key.address,
        amount_hac="1:247",
        idempotency_key=idem,
        local_only=True,
        meta={"purpose": "demo_full_pay", "skill": "demo"},
    )
    pid = (
        (env.get("action_required") or {}).get("payment_id")
        or (env.get("result") or {}).get("payment_id")
        or ((env.get("result") or {}).get("payment") or {}).get("payment_id")
    )
    print(f"  payment_id={pid} state={env.get('machine', {}).get('state')}")

    # payee signs first (ordered multi-sig)
    n = payee.drain_inbox(payee_key)
    print(f"  payee drain_inbox signed={n}")
    env = payer.wait_until_done(str(pid), payer_key)
    print(f"  final machine={env.get('machine')}")

    if env.get("machine", {}).get("success"):
        rec = payer.receipt(str(pid))
        print(f"  RECEIPT hash={rec.get('receipt_hash_hex')}")
        print(f"  status={rec.get('status')} finality={rec.get('finality')}")
    else:
        print("  payment not settled:", env.get("error") or env.get("human"))

    # --- Invoice (request-to-pay) ---
    print("\n--- 4) Invoice (request-to-pay) ---")
    inv = payee.create_invoice(
        payee=payee_key.address,
        amount_hac="2:247",
        payer_hint=payer_key.address,
        description="demo invoice for service",
        ttl_secs=600,
    )
    print(f"  invoice_id={inv['id']} status={inv['status']} amount={inv['amount_hac']}")

    # Create payment from invoice without waiting — payee must sign first.
    out = payer.pay_invoice(
        invoice_id=inv["id"],
        from_addr=payer_key.address,
        key=None,
        local_only=True,
    )
    pid2 = out.get("payment_id")
    print(f"  payment_id={pid2}")
    n = payee.drain_inbox(payee_key)
    print(f"  payee drain_inbox signed={n}")
    if pid2:
        env2 = payer.wait_until_done(str(pid2), payer_key)
        print(f"  invoice pay machine={env2.get('machine')}")
        if env2.get("machine", {}).get("success"):
            r2 = payer.receipt(str(pid2))
            print(f"  invoice RECEIPT={r2.get('receipt_hash_hex')}")

    # --- Micro stream (satoshi-first bookkeeping) ---
    print("\n--- 5) Micro stream (satoshi bookkeeping, no full pays) ---")
    stream = payer.micro_open(
        payer=payer_key.address,
        payee=payee_key.address,
        max_satoshi=10_000,
        max_hac_mei=0,
        create_payments=False,
        local_only=True,
    )
    sid = stream["id"]
    print(f"  stream_id={sid} max_sat={stream['max_satoshi']}")

    for i, sats in enumerate((100, 250, 500), 1):
        body = payer.micro_push(
            stream_id=sid,
            key=payer_key,
            amount_satoshi=sats,
            note=f"tick-{i}",
        )
        st = body["stream"]
        rem = body.get("remaining", {})
        print(
            f"  push #{i}: +{sats} sat  spent={st['spent_satoshi']}  remaining_sat={rem.get('satoshi')}"
        )

    closed = payer.micro_close(sid, payer_key.address)
    print(f"  closed status={closed['status']} total_spent_sat={closed['spent_satoshi']}")

    # --- Normalize amounts ---
    print("\n--- 6) Amount helpers ---")
    n1 = payer.normalize_amount(amount_satoshi=1500)
    n2 = payer.normalize_amount(amount_mei=3)
    print(f"  sat-only: {n1.get('display')}  satoshi_first={n1.get('satoshi_first')}")
    print(f"  mei-only: {n2.get('display')}")

    # --- Policy snapshot ---
    print("\n--- 7) Policy / ledger ---")
    pol = payer.policy()
    print(f"  policy max_amount_mei={pol.get('policy', {}).get('max_amount_mei')}")
    led = payer.ledger()
    print(f"  ledger entries={len(led.get('ledger') or [])}")

    print("\n" + "=" * 60)
    print("DEMO OK")
    print("=" * 60)


if __name__ == "__main__":
    main()
