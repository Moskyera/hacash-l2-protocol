# Wallet + AI agent — easy integration

The hub still has full power APIs (`/v1/payments`, `/v1/channels`, …).
**Wallets and agents should use the smart layer only** so users never think about hubs.

## User never needs to know

| Hidden concept | Who handles it |
|----------------|----------------|
| Hub / CSP / provider_id | Wallet `Find network` → `/v1/wallet/start` |
| Multi-hop route | Hub BFS on `/v1/wallet/pay` |
| Signature order | `payment.next_signer` + `payment.next` |
| Last bill / sequence | `/v1/wallet/bill/…` when needed |
| 50 VPS peers | Gossip + one `attach_to` URL |

---

## Wallet integration (minimal)

### 1. On open / "Find network"

```http
GET {seed}/v1/wallet/start
```

Use `attach_to` (or `recommended.public_url`) as the hub base for this session.

**UI:** title/subtitle/buttons from `ui` + `copy_for_user`.

### 2. Home for user address

```http
GET {hub}/v1/wallet/me?address=1UserAddress…
```

Shows channels, open payments, **next button** (`snapshot.next`).

### 3. Send

```http
POST {hub}/v1/wallet/pay
{
  "from": "1Payer…",
  "to": "1Payee…",
  "amount_hac": "1:247"
}
```

Response `payment`:

| Field | Use |
|-------|-----|
| `sign_this_hash_hex` | Sign with user key (32-byte SHA3) |
| `next_signer` | Who must sign now |
| `ui` | Screen title / progress |
| `next` | Next HTTP call template |
| `agent.done` | false until complete |

### 4. Confirm (sign)

Wallet signs `sign_this_hash_hex` → 97-byte Hacash Sign hex, then:

```http
POST {hub}/v1/wallet/sign/{payment_id}
{
  "address": "1Payer…",
  "signature_hex": "<194 hex chars>"
}
```

Repeat until `payment.agent.done == true` and `status == settled`.

**Show user:** "Sent" — footnote: not L1 channel close.

### 5. Optional bill

After settle, if the wallet manages channel balances:

```http
POST {hub}/v1/wallet/bill/{channel_id}
{ "left_hac": "…", "right_hac": "…", "payment_id": "…" }
POST {hub}/v1/wallet/bill/{channel_id}/sign
```

---

## AI agent integration (minimal)

### Option A — tools list

```http
GET {seed}/v1/agent/start
```

- `attach_to` — base URL
- `tools[]` — name, method, url, parameters
- `playbook[]` — ordered steps

Loop: call tools, never request private keys; sign only if the agent holds keys locally.

### Option B — single intent brain

```http
POST {hub}/v1/agent/intent
{ "action": "pay", "from": "…", "to": "…", "amount_hac": "1:247" }
```

| action | body fields |
|--------|-------------|
| `find_hubs` | — |
| `me` | `address` |
| `pay` | `from`, `to`, `amount_hac` |
| `status` | `payment_id` |
| `sign` | `payment_id`, `address`, `signature_hex` |
| `bill` | `channel_id`, `left_hac`, `right_hac` |

Every response includes `ui` + `agent` (`done`, `next_tool`, `instructions`).

### Agent pseudo-code

```text
base = GET seed/v1/agent/start → attach_to
snap = intent { action: me, address }
if snap has open payment where next_signer == me:
    sign hash locally
    intent { action: sign, payment_id, address, signature_hex }
else if user wants send:
    intent { action: pay, from, to, amount_hac }
    while not payment.agent.done:
        if next_signer == me: sign + intent sign
        else: wait / notify
```

---

## Copy suggestions (Greek UI)

| Key | Text |
|-----|------|
| find_hubs | «Εύρεση δικτύου πληρωμών…» |
| pay | «Άμεση αποστολή» |
| sign | «Επιβεβαίωση πληρωμής» |
| done | «Στάλθηκε» |
| footnote | «Το κλείσιμο καναλιού στο blockchain είναι ξεχωριστό» |

---

## Power API (optional)

Still available for operators: `/v1/payments`, `/v1/channels`, `/v1/net/*`, `/v1/discover`.
Do **not** force normal wallets through those.
