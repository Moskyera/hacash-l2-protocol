/**
 * Minimal two-agent loop (run against a local hub with a registered channel).
 *
 *   npx tsx examples/pay-loop.ts http://127.0.0.1:9090
 */

import { AgentPayClient, HacashKey } from "../src/index.js";

async function main() {
  const baseUrl = process.argv[2] ?? "http://127.0.0.1:9090";
  const payer = HacashKey.fromPassword("demo-payer-key");
  const payee = HacashKey.fromPassword("demo-payee-key");

  console.log("payer", payer.address);
  console.log("payee", payee.address);

  const payerClient = new AgentPayClient({ baseUrl, agentId: "payer-bot" });
  const payeeClient = new AgentPayClient({ baseUrl, agentId: "payee-bot" });

  const man = await payerClient.manifest();
  console.log("protocol", man.protocol);

  // Payee drains first (empty)
  await payeeClient.drainInbox(payee);

  const idem = `demo-${Date.now()}`;
  let env = await payerClient.pay({
    from: payer.address,
    to: payee.address,
    amount_hac: "1:247",
    idempotency_key: idem,
    local_only: true,
    meta: { purpose: "demo", skill: "example" },
  });
  console.log("pay state", env.machine.state, env.human);

  const paymentId = String(
    env.action_required?.payment_id ??
      (env.result as any)?.payment_id ??
      (env.result as any)?.payment?.payment_id,
  );
  console.log("payment_id", paymentId);

  // Payee signs first (ordered multi-sig)
  await payeeClient.drainInbox(payee);
  // Payer finishes
  env = await payerClient.waitUntilDone(paymentId, payer);

  console.log("done", env.machine);
  if (env.machine.success) {
    const receipt = await payerClient.receipt(paymentId);
    console.log("receipt_hash", receipt.receipt_hash_hex);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
