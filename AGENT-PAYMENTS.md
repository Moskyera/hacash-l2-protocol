# Hacash Agent Pay (HAP) — best path for AI agents

**Protocol:** `hacash-agent-pay/1`
**Primary entry:** `GET /v1/agent/v1/manifest`
**SDKs:** [sdk/typescript](sdk/typescript) (`@hacash/agent-pay`) · [sdk/python](sdk/python) (`hacash-agent-pay`)

This hub is optimized so an **AI agent can pay and get paid** without understanding
hubs, multi-hop graphs, or L1 mechanics. Humans still use `/v1/wallet/*`.

### 30-second SDK (TypeScript)

```ts
import { AgentPayClient, HacashKey } from "@hacash/agent-pay";
const key = HacashKey.fromPassword("secret");
const c = new AgentPayClient({ baseUrl: "http://hub:9090", agentId: "bot" });
await c.drainInbox(key);
await c.send({ from: key.address, to: "1Payee…", amount_hac: "1:247",
  idempotency_key: "inv-1", key, meta: { purpose: "fee" } });
```

---

## Why this is agent-first

| Need | HAP feature |
|------|-------------|
| Safe retries | **Idempotency key** on every pay |
| Clear next step | **Machine envelope** (`state`, `done`, `action_required`) |
| Work queue | **Inbox** — only hashes *this* agent must sign |
| Proof after settle | **Receipt** + `receipt_hash_hex` |
| Dry-run | **Quote** before pay |
| Async multi-party | **SSE watch** |
| Tool calling | **OpenAI-style tools** with JSON Schema + `x_http` |
| No custody | Keys stay in agent runtime |

---

## Agent loop (copy into system prompt)

```
1. GET {hub}/v1/agent/v1/manifest
2. GET {hub}/v1/agent/v1/inbox?address={my_address}
3. If inbox non-empty:
     for item in inbox:
       sig = sign_local(item.sign_this_hash_hex)   # NEVER send private key
       POST {hub}/v1/agent/v1/sign { payment_id, address, signature_hex }
4. To send money:
     POST quote { from, to, amount_hac }
     POST pay { from, to, amount_hac, idempotency_key, meta, callback_url? }
     while not machine.done:
       if action_required.address == me: sign
       else: GET payment/{id} or GET watch/{id}
     GET receipt/{id} → store receipt_hash_hex
5. Request-to-pay (earn money):
     POST invoice { payee: me, amount_hac, description, callback_url? }
     → other agent: POST pay-invoice { invoice_id, from }
6. Treat settled as hub-coordinated only — not L1 ChannelClose
```

### Cross-hub agent behavior

The primary `/v1/agent/v1/pay` flow can select a route across verified hubs.
Use one unique `idempotency_key` per logical payment and reuse it only when
retrying the same fields.

After the last user signature, `machine.state` may temporarily be
`distributed_commit_pending`. This means an irreversible durable commit
decision already exists and one or more hubs are being retried. Do not cancel
the payment and do not create a replacement payment. Poll the same
`payment_id`; the recovery worker continues delivery after restarts.

### Request-to-pay (agent commerce)

| Step | Who | Call |
|------|-----|------|
| 1 | Seller agent | `POST /v1/agent/v1/invoice` |
| 2 | Buyer agent | `POST /v1/agent/v1/pay-invoice` |
| 3 | Both | inbox/sign as usual |
| 4 | Either | `GET receipt` + optional webhook |

### Policy & ledger

- `GET /v1/agent/v1/policy` — max amount, rate limits, allowlists
- `GET /v1/agent/v1/ledger` — soft per-agent counters
- Flags: `--max-amount-mei`, `--max-pay-per-hour`, `--agent-allowlist`, `--payee-allowlist`

### Agent identity

```
POST /v1/agent/v1/identity/register  { agent_id, public_key_hex }
GET  /v1/agent/v1/identity/challenge?agent_id=
POST /v1/agent/v1/identity/verify    { agent_id, challenge_id, signature_hex }
```

SDK: `prove_identity(key)` / `proveIdentity(key)`.

### Micropayment streams

```
POST /v1/agent/v1/micro/open   { payer, payee, max_satoshi, max_hac_mei, create_payments? }
POST /v1/agent/v1/micro/push   { stream_id, amount_satoshi|amount_mei, signature_hex? }
POST /v1/agent/v1/micro/:id/close { by_address }
```

Satoshi-first: pass `amount_satoshi` / `satoshi`.
HAC: `amount_mei` or `amount_hac`.
Normalize: `POST /v1/agent/v1/amounts/normalize`.

### Docker seed

```bash
docker compose up --build   # :9090 seed hub
```

---

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/agent/v1/manifest` | Full bootstrap (tools, loop, rules) |
| GET | `/v1/agent/v1/tools` | Function-calling tool list |
| POST | `/v1/agent/v1/quote` | Dry-run route |
| POST | `/v1/agent/v1/pay` | Idempotent create payment |
| POST | `/v1/agent/v1/sign` | Submit signature |
| GET | `/v1/agent/v1/payment/:id` | Status + envelope |
| GET | `/v1/agent/v1/inbox?address=` | Pending signs for address |
| GET | `/v1/agent/v1/receipt/:id` | Terminal receipt |
| GET | `/v1/agent/v1/watch/:id` | SSE status stream |
| GET | `/v1/channels/:id/l1-exit/readiness` | Fail-closed L1 action compatibility check; never auto-sign or broadcast |

### Pay body

```json
{
  "from": "1PayerAddress…",
  "to": "1PayeeAddress…",
  "amount_hac": "1:247",
  "idempotency_key": "skill-invoice-42-attempt-1",
  "meta": {
    "agent_id": "research-bot-7",
    "purpose": "pay_for_api_result",
    "invoice_id": "inv_99",
    "skill": "web_search",
    "conversation_id": "chat_abc"
  }
}
```

### Machine envelope (every pay/sign/status)

```json
{
  "ok": true,
  "protocol": "hacash-agent-pay/1",
  "machine": {
    "state": "action_required",
    "done": false,
    "success": false,
    "retryable": true,
    "next_poll_ms": 1500
  },
  "action_required": {
    "kind": "sign_payment",
    "address": "1Payee…",
    "sign_this_hash_hex": "…",
    "sign_endpoint": "…/v1/agent/v1/sign",
    "instructions": ["…"]
  },
  "result": { "payment": { "…smart view…" } },
  "human": { "title": "…", "detail": "…" }
}
```

---

## Comparison (agent DX)

| System | Agent-friendly traits |
|--------|------------------------|
| **Hacash Agent Pay** | Idempotent L2, inbox, receipts, quote, SSE, no custody |
| Card / bank APIs | Heavy KYC, slow, human forms |
| Lightning (raw) | Complex async hops, watchtowers |
| Custodial agent wallets | Keys on server — wrong trust model |

---

## Security notes for agents

1. **Never** put private keys in HTTP body or logs.
2. Always use a **new idempotency_key** per logical payment (reuse only for retries).
3. `machine.success && status=settled` = hub coordination complete — **not** L1 final.
4. Store `receipt.receipt_hash_hex` for audit trails between agents.
5. Prefer `sig_verify=true` on production hubs.

---

## Humans

Use `/v1/wallet/*` for UI apps. Same underlying payments; HAP is the machine dialect.
