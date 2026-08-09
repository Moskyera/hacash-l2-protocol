# @hacash/agent-pay (TypeScript / Node)

AI agent SDK for **Hacash Agent Pay** — L2 Channel Chain hub protocol `hacash-agent-pay/1`.

## Install

```bash
cd sdk/typescript
npm install
npm run build
```

## Quick start

```ts
import { AgentPayClient, HacashKey } from "@hacash/agent-pay";

const key = HacashKey.fromPassword("my-agent-secret");
const client = new AgentPayClient({
  baseUrl: "http://127.0.0.1:9090",
  agentId: "research-bot",
});

// 1) Receive / intermediate: drain signatures waiting for us
await client.drainInbox(key);

// 2) Send money
const { envelope, receipt, payment_id } = await client.send({
  from: key.address,
  to: "1PayeeAddress…",
  amount_hac: "1:247",
  idempotency_key: `inv-${Date.now()}`,
  key, // auto-sign when action_required.address === us
  meta: { purpose: "pay_for_result", skill: "web_search" },
});

console.log(envelope.machine);
console.log(receipt?.receipt_hash_hex);
```

## Agent loop (recommended)

```ts
async function agentTick(client: AgentPayClient, key: HacashKey) {
  await client.drainInbox(key); // always clear work queue first
  // then optional: client.send(...) when skill needs to pay
}
```

## API surface

| Method | Purpose |
|--------|---------|
| `manifest()` | Bootstrap HAP tools + rules |
| `quote(...)` | Dry-run route |
| `pay(...)` | Idempotent create |
| `sign(...)` | Submit signature hex |
| `inbox(address)` | Work queue |
| `drainInbox(key)` | Sign all pending for key |
| `waitUntilDone(id, key?)` | Poll + auto-sign |
| `send({...key})` | quote → pay → wait |
| `receipt(id)` | Terminal receipt |

Keys **never** leave the process. Hub only gets `signature_hex`.

## Example

```bash
# hub running with channels registered for demo addresses
npx tsx examples/pay-loop.ts http://127.0.0.1:9090
```

## Tests

```bash
npm test
```
