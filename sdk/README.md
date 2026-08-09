# Hacash Agent Pay — SDKs

Language clients for AI agents talking to `hacash-l2-hub` (protocol **hacash-agent-pay/1**).

| Language | Path | Package |
|----------|------|---------|
| **TypeScript / Node** | [typescript/](typescript/) | `@hacash/agent-pay` |
| **Python** | [python/](python/) | `hacash-agent-pay` |

Hub docs: [../AGENT-PAYMENTS.md](../AGENT-PAYMENTS.md)

## Mental model (both SDKs)

```
manifest → drain_inbox (receive) → quote → pay → sign/wait → receipt
```

1. **Keys stay local** (`HacashKey`)
2. **Idempotency** on every pay
3. **Inbox** = work queue for multi-party sign
4. **Receipt hash** = audit between agents (not L1 final)

## Minimal agent skill (any language)

```
on_start:
  prove_identity(my_key)

on_tick:
  drain_inbox(my_key)

on_need_pay(to, amount):
  send(from=me, to, amount, key=my_key, idempotency_key=unique)
  store receipt.receipt_hash_hex

on_stream(to, max_sats):
  micro_open(payer=me, payee=to, max_satoshi=max_sats)
  micro_push(..., amount_satoshi=n)  # many times
  micro_close(...)

on_earn:
  create_invoice(payee=me, amount)
```
