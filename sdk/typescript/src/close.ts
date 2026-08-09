/**
 * L1 ChannelClose helpers (evidence plan only — no custody, no L1 wire encode).
 */

export const CLOSE_INTENT_SCHEMA = "hacash-l2-close-intent/1";

export interface CloseIntent {
  schema: string;
  channel_id: string;
  ready_for_l1_close: boolean;
  blockers: string[];
  bill_active?: boolean;
  distribution?: Record<string, unknown> | null;
  bill_signatures?: unknown[];
  bill_message?: string;
  bill_message_hash_hex?: string;
  fullnode_l1_query?: string;
  wallet_actions?: string[];
  hub_submit?: Record<string, unknown>;
  disclaimer?: string;
  evidence_notes?: string[];
  [key: string]: unknown;
}

/** Normalize hub close-plan / dispute export into stable close intent. */
export function buildCloseIntent(exportOrPlan: unknown): CloseIntent {
  if (!exportOrPlan || typeof exportOrPlan !== "object") {
    return {
      schema: CLOSE_INTENT_SCHEMA,
      channel_id: "",
      ready_for_l1_close: false,
      blockers: ["invalid_input"],
    };
  }
  const root = exportOrPlan as Record<string, unknown>;

  if (root.close_plan && typeof root.close_plan === "object") {
    const plan = root.close_plan as CloseIntent;
    if (plan.schema === CLOSE_INTENT_SCHEMA) return plan;
  }
  if (root.schema === CLOSE_INTENT_SCHEMA) {
    return root as CloseIntent;
  }

  const exportBody =
    root.export && typeof root.export === "object"
      ? (root.export as Record<string, unknown>)
      : root;

  const pack =
    exportBody.close_package && typeof exportBody.close_package === "object"
      ? (exportBody.close_package as Record<string, unknown>)
      : null;

  const blockers: string[] = [];
  if (!exportBody.channel) blockers.push("channel_not_registered_on_hub");
  if (!exportBody.last_bill) blockers.push("no_last_bill");
  else if (!exportBody.bill_active)
    blockers.push("bill_not_active_need_left_and_right_signatures");
  if (!pack) blockers.push("missing_close_package");
  else {
    if (!pack.ready_for_l1_close) blockers.push("close_package_not_ready");
    if (!pack.both_signed) blockers.push("bill_not_both_signed");
  }

  const ready = blockers.length === 0 && Boolean(pack?.ready_for_l1_close);

  return {
    schema: CLOSE_INTENT_SCHEMA,
    channel_id: String(exportBody.channel_id || pack?.channel_id || ""),
    ready_for_l1_close: ready,
    blockers,
    bill_active: Boolean(exportBody.bill_active),
    distribution: pack
      ? {
          left_address: pack.left_address,
          right_address: pack.right_address,
          left_hac: pack.distribution_left_hac,
          right_hac: pack.distribution_right_hac,
          left_satoshi: pack.distribution_left_satoshi ?? 0,
          right_satoshi: pack.distribution_right_satoshi ?? 0,
          bill_sequence: pack.bill_sequence,
          bill_message_hash_hex: pack.bill_message_hash_hex,
        }
      : null,
    bill_signatures: (pack?.bill_signatures as unknown[]) || [],
    bill_message: pack?.bill_message as string | undefined,
    bill_message_hash_hex: pack?.bill_message_hash_hex as string | undefined,
    fullnode_l1_query: String(exportBody.fullnode_l1_query || ""),
    wallet_actions: [
      "1. Confirm ready_for_l1_close == true",
      "2. Query L1 channel via fullnode_l1_query",
      "3. Build ChannelClose with distribution balances (wallet/fullnode protocol)",
      "4. Sign L1 tx with party keys (never send keys to hub)",
      "5. Broadcast signed tx_hex via fullnode or hub POST /v1/l1/submit",
      "6. POST /v1/channels/:id/refresh on hub",
    ],
    hub_submit: {
      method: "POST",
      path: "/v1/l1/submit",
      body: { tx_hex: "<already-signed-channel-close-hex>", path: "" },
      note: "Hub relays hex only — does not build ChannelClose",
    },
    disclaimer:
      (exportBody.disclaimer as string) ||
      "Hub coordination evidence only — not L1 finality until ChannelClose confirms",
    evidence_notes: (exportBody.evidence_notes as string[]) || [],
  };
}

export function assertReadyForClose(intent: CloseIntent): void {
  if (!intent.ready_for_l1_close) {
    const b = (intent.blockers || ["not_ready"]).join(", ");
    throw new Error(`not ready for L1 close: ${b}`);
  }
}

export function closeChecklist(intent: CloseIntent): string[] {
  if (intent.ready_for_l1_close) {
    return [...(intent.wallet_actions || [])];
  }
  return [
    ...(intent.blockers || []).map((b) => `blocker: ${b}`),
    "Propose last bill on both sides if missing",
    "Left+right sign bill until active",
    "Re-fetch close_plan / export_dispute",
  ];
}
