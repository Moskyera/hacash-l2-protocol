/**
 * @hacash/agent-pay — Hacash Agent Pay SDK
 *
 * ```ts
 * import { AgentPayClient, HacashKey } from "@hacash/agent-pay";
 *
 * const key = HacashKey.fromPassword("my-agent-secret");
 * const client = new AgentPayClient({ baseUrl: "http://127.0.0.1:9090", agentId: "bot-1" });
 *
 * // Receive: drain signatures waiting for us
 * await client.drainInbox(key);
 *
 * // Send
 * const { envelope, receipt } = await client.send({
 *   from: key.address,
 *   to: "1Payee…",
 *   amount_hac: "1:247",
 *   idempotency_key: `inv-${Date.now()}`,
 *   key, // auto-sign when our turn
 *   meta: { purpose: "api_fee", skill: "search" },
 * });
 * ```
 */

export { AgentPayClient, AgentPayError } from "./client.js";
export { buildAgentIntentMessage, signAgentIntent, type AgentIntentParams } from "./crypto.js";
export {
  CLOSE_INTENT_SCHEMA,
  assertReadyForClose,
  buildCloseIntent,
  closeChecklist,
} from "./close.js";
export type { CloseIntent } from "./close.js";
export { HacashKey, addressFromPubkey, sha3Hex, hexToBytes, bytesToHex } from "./crypto.js";
export type {
  AgentClientOptions,
  AgentPaymentMeta,
  ActionRequired,
  AgentIntentProof,
  InboxItem,
  MachineEnvelope,
  MachineStatus,
  PayOptions,
  PaymentReceipt,
  QuoteResult,
} from "./types.js";
