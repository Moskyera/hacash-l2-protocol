import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import * as secp from "@noble/secp256k1";
import {
  assertReadyForClose,
  buildCloseIntent,
  closeChecklist,
  type CloseIntent,
} from "./close.js";
import { HacashKey } from "./crypto.js";
import type {
  AgentClientOptions,
  AgentPaymentMeta,
  InboxItem,
  MachineEnvelope,
  PayOptions,
  PaymentReceipt,
  QuoteResult,
} from "./types.js";

// Required for @noble/secp256k1 deterministic signatures
secp.etc.hmacSha256Sync = (key, ...msgs) => {
  const h = hmac.create(sha256, key);
  msgs.forEach((m) => h.update(m));
  return h.digest();
};

export class AgentPayError extends Error {
  readonly code: string;
  readonly envelope?: MachineEnvelope;

  constructor(code: string, message: string, envelope?: MachineEnvelope) {
    super(message);
    this.name = "AgentPayError";
    this.code = code;
    this.envelope = envelope;
  }
}

/**
 * Hacash Agent Pay client — the primary way for AI agents to send/receive L2 payments.
 *
 * Keys stay local. Hub only coordinates.
 */
export class AgentPayClient {
  readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  readonly agentId: string;
  private readonly waitTimeoutMs: number;
  private readonly pollMs: number;
  private readonly apiKey: string;

  constructor(opts: AgentClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.agentId = opts.agentId ?? "agent";
    this.waitTimeoutMs = opts.waitTimeoutMs ?? 120_000;
    this.pollMs = opts.pollMs ?? 1_500;
    this.apiKey = (opts.agentApiKey ?? opts.apiKey ?? "").trim();
  }

  /** Bootstrap document (tools, loop, endpoints). Call once. */
  async manifest(): Promise<Record<string, unknown>> {
    return this.getJson("/v1/agent/v1/manifest");
  }

  async tools(): Promise<unknown> {
    return this.getJson("/v1/agent/v1/tools");
  }

  /** Dry-run route without creating a payment. */
  async quote(opts: {
    from: string;
    to: string;
    amount_hac?: string;
    amount_satoshi?: number;
    local_only?: boolean;
  }): Promise<QuoteResult> {
    const body = await this.postJson("/v1/agent/v1/quote", {
      from: opts.from,
      to: opts.to,
      amount_hac: opts.amount_hac ?? "",
      amount_satoshi: opts.amount_satoshi ?? 0,
      local_only: opts.local_only ?? false,
    });
    if (!body.ok) {
      throw new AgentPayError("quote_failed", JSON.stringify(body));
    }
    return body.quote as QuoteResult;
  }

  /**
   * Create idempotent payment. Always pass a unique idempotency_key per logical payment.
   * Safe to retry with the same key.
   */
  async pay(opts: PayOptions): Promise<MachineEnvelope> {
    const meta: AgentPaymentMeta = {
      agent_id: this.agentId,
      ...opts.meta,
    };
    const env = (await this.postJson("/v1/agent/v1/pay", {
      from: opts.from,
      to: opts.to,
      amount_hac: opts.amount_hac ?? "",
      amount_satoshi: opts.amount_satoshi ?? 0,
      idempotency_key: opts.idempotency_key,
      local_only: opts.local_only ?? false,
      meta,
      intent: opts.intent,
    })) as MachineEnvelope;

    if (!env.ok) {
      throw new AgentPayError(
        env.error?.code ?? "pay_failed",
        env.error?.message ?? "pay failed",
        env,
      );
    }
    return env;
  }

  async status(paymentId: string): Promise<MachineEnvelope> {
    const env = (await this.getJson(
      `/v1/agent/v1/payment/${paymentId}`,
    )) as MachineEnvelope;
    if (!env.ok && env.error) {
      throw new AgentPayError(env.error.code, env.error.message, env);
    }
    return env;
  }

  async sign(opts: {
    payment_id: string;
    address: string;
    signature_hex: string;
    public_key_hex?: string;
  }): Promise<MachineEnvelope> {
    const env = (await this.postJson("/v1/agent/v1/sign", {
      payment_id: opts.payment_id,
      address: opts.address,
      signature_hex: opts.signature_hex,
      public_key_hex: opts.public_key_hex ?? "",
      agent_id: this.agentId,
    })) as MachineEnvelope;
    if (!env.ok) {
      throw new AgentPayError(
        env.error?.code ?? "sign_failed",
        env.error?.message ?? "sign failed",
        env,
      );
    }
    return env;
  }

  /** Work queue: payments waiting for this address to sign. */
  async inbox(address: string): Promise<InboxItem[]> {
    const body = await this.getJson(
      `/v1/agent/v1/inbox?address=${encodeURIComponent(address)}`,
    );
    if (!body.ok) {
      throw new AgentPayError("inbox_failed", JSON.stringify(body));
    }
    return (body.inbox as InboxItem[]) ?? [];
  }

  async receipt(paymentId: string): Promise<PaymentReceipt> {
    const body = await this.getJson(`/v1/agent/v1/receipt/${paymentId}`);
    if (!body.ok) {
      throw new AgentPayError("no_receipt", body.err ?? "no receipt");
    }
    return body.receipt as PaymentReceipt;
  }

  /** Request-to-pay: create invoice as payee. */
  async createInvoice(opts: {
    payee: string;
    amount_hac: string;
    payer_hint?: string;
    description?: string;
    ttl_secs?: number;
    callback_url?: string;
    meta?: AgentPaymentMeta;
  }): Promise<Record<string, unknown>> {
    const body = await this.postJson("/v1/agent/v1/invoice", {
      payee: opts.payee,
      amount_hac: opts.amount_hac,
      payer_hint: opts.payer_hint ?? "",
      description: opts.description ?? "",
      ttl_secs: opts.ttl_secs ?? 3600,
      callback_url: opts.callback_url ?? "",
      meta: { agent_id: this.agentId, ...opts.meta },
    });
    if (!body.ok) throw new AgentPayError("invoice_failed", body.err ?? "invoice failed");
    return body.invoice as Record<string, unknown>;
  }

  async getInvoice(invoiceId: string): Promise<Record<string, unknown>> {
    const body = await this.getJson(`/v1/agent/v1/invoice/${invoiceId}`);
    if (!body.ok) throw new AgentPayError("not_found", body.err ?? "not found");
    return body.invoice as Record<string, unknown>;
  }

  async listInvoices(address: string, limit = 50): Promise<unknown[]> {
    const body = await this.getJson(
      `/v1/agent/v1/invoices?address=${encodeURIComponent(address)}&limit=${limit}`,
    );
    return (body.invoices as unknown[]) ?? [];
  }

  /** Fulfill a request-to-pay invoice. */
  async payInvoice(opts: {
    invoice_id: string;
    from: string;
    idempotency_key?: string;
    key?: HacashKey;
    local_only?: boolean;
  }): Promise<{
    envelope: MachineEnvelope;
    receipt?: PaymentReceipt;
    payment_id: string;
    invoice_id: string;
  }> {
    const idem =
      opts.idempotency_key ?? `invpay-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const env = (await this.postJson("/v1/agent/v1/pay-invoice", {
      invoice_id: opts.invoice_id,
      from: opts.from,
      idempotency_key: idem,
      local_only: opts.local_only ?? false,
      meta: { agent_id: this.agentId },
    })) as MachineEnvelope;
    if (!env.ok) {
      throw new AgentPayError(
        env.error?.code ?? "pay_failed",
        env.error?.message ?? "pay invoice failed",
        env,
      );
    }
    let paymentId = String(env.action_required?.payment_id ?? "");
    const res = env.result as { payment_id?: string; payment?: { payment_id?: string } };
    if (!paymentId) paymentId = String(res.payment_id ?? res.payment?.payment_id ?? "");
    let finalEnv = env;
    if (opts.key && paymentId) {
      finalEnv = await this.signIfNeeded(opts.key, env);
      finalEnv = await this.waitUntilDone(paymentId, opts.key);
    }
    let receipt: PaymentReceipt | undefined;
    if (finalEnv.machine.done && finalEnv.machine.success && paymentId) {
      try {
        receipt = await this.receipt(paymentId);
      } catch {
        /* optional */
      }
    }
    return {
      envelope: finalEnv,
      receipt,
      payment_id: paymentId,
      invoice_id: opts.invoice_id,
    };
  }

  async cancelPayment(paymentId: string, byAddress: string): Promise<MachineEnvelope> {
    return (await this.postJson(`/v1/agent/v1/payment/${paymentId}/cancel`, {
      by_address: byAddress,
    })) as MachineEnvelope;
  }

  async policy(): Promise<Record<string, unknown>> {
    return this.getJson("/v1/agent/v1/policy");
  }

  async ledger(): Promise<Record<string, unknown>> {
    return this.getJson("/v1/agent/v1/ledger");
  }

  async registerIdentity(opts: {
    agent_id: string;
    public_key_hex: string;
    label?: string;
  }): Promise<Record<string, unknown>> {
    const body = await this.postJson("/v1/agent/v1/identity/register", opts);
    if (!body.ok) throw new AgentPayError("identity_failed", body.err ?? "failed");
    return body.identity as Record<string, unknown>;
  }

  async proveIdentity(key: HacashKey, agentId?: string): Promise<Record<string, unknown>> {
    const aid = agentId ?? this.agentId;
    const pk = Array.from(key.publicKey)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    await this.registerIdentity({ agent_id: aid, public_key_hex: pk });
    const chBody = await this.getJson(
      `/v1/agent/v1/identity/challenge?agent_id=${encodeURIComponent(aid)}`,
    );
    if (!chBody.ok) throw new AgentPayError("challenge_failed", chBody.err ?? "failed");
    const ch = chBody.challenge as { challenge_id: string; message_hash_hex: string };
    const sig = key.signHashHex(ch.message_hash_hex);
    const ver = await this.postJson("/v1/agent/v1/identity/verify", {
      agent_id: aid,
      challenge_id: ch.challenge_id,
      signature_hex: sig,
      public_key_hex: pk,
    });
    if (!ver.ok) throw new AgentPayError("verify_failed", ver.err ?? "failed");
    return ver.identity as Record<string, unknown>;
  }

  async microOpen(opts: {
    payer: string;
    payee: string;
    max_satoshi?: number;
    max_hac_mei?: number;
    create_payments?: boolean;
    local_only?: boolean;
  }): Promise<Record<string, unknown>> {
    const body = await this.postJson("/v1/agent/v1/micro/open", {
      ...opts,
      max_satoshi: opts.max_satoshi ?? 0,
      max_hac_mei: opts.max_hac_mei ?? 0,
      create_payments: opts.create_payments ?? false,
      local_only: opts.local_only ?? true,
      agent_id: this.agentId,
    });
    if (!body.ok) throw new AgentPayError("micro_open_failed", body.err ?? "failed");
    return body.stream as Record<string, unknown>;
  }

  async microPush(opts: {
    stream_id: string;
    key: HacashKey;
    amount_satoshi?: number;
    amount_mei?: number;
    amount_hac?: string;
    note?: string;
  }): Promise<Record<string, unknown>> {
    const payload: Record<string, unknown> = {
      stream_id: opts.stream_id,
      amount_satoshi: opts.amount_satoshi ?? 0,
      amount_mei: opts.amount_mei ?? 0,
      amount_hac: opts.amount_hac ?? "",
      note: opts.note ?? "",
      signature_hex: "",
    };
    let body = await this.postJson("/v1/agent/v1/micro/push", payload);
    if (body.err === "signature_required" && body.action_required) {
      const ar = body.action_required as { sign_this_hash_hex: string };
      payload.signature_hex = opts.key.signHashHex(ar.sign_this_hash_hex);
      body = await this.postJson("/v1/agent/v1/micro/push", payload);
    }
    if (!body.ok) throw new AgentPayError("micro_push_failed", body.err ?? "failed", body as any);
    return body;
  }

  async microClose(streamId: string, byAddress: string): Promise<Record<string, unknown>> {
    const body = await this.postJson(`/v1/agent/v1/micro/${streamId}/close`, {
      by_address: byAddress,
    });
    if (!body.ok) throw new AgentPayError("micro_close_failed", body.err ?? "failed");
    return body.stream as Record<string, unknown>;
  }

  async normalizeAmount(opts: {
    amount_hac?: string;
    amount_satoshi?: number;
    amount_mei?: number;
    satoshi?: number;
  }): Promise<Record<string, unknown>> {
    return this.postJson("/v1/agent/v1/amounts/normalize", opts);
  }

  /**
   * Sign trusted, local incoming-payment items for this key.
   * Outbound and intermediary signatures require an explicit application
   * decision; otherwise an unsolicited payment could spend or move funds.
   * Returns number of signatures submitted.
   */
  async drainInbox(key: HacashKey): Promise<{ signed: number; envelopes: MachineEnvelope[] }> {
    const items = await this.inbox(key.address);
    const envelopes: MachineEnvelope[] = [];
    for (const item of items) {
      if (item.action.address !== key.address) continue;
      if (item.role !== "payee") continue;
      const endpoint = (item.action.sign_endpoint || "").trim();
      if (
        item.kind === "sign_on_origin_hub" ||
        !this.isLocalSignEndpoint(endpoint)
      ) continue;
      const signature_hex = key.signHashHex(item.sign_this_hash_hex);
      let env: MachineEnvelope;
      if (
        item.kind === "sign_on_origin_hub" &&
        (endpoint.startsWith("http://") || endpoint.startsWith("https://"))
      ) {
        env = await this.signAtEndpoint(endpoint, {
          payment_id: String(item.payment_id),
          address: key.address,
          signature_hex,
        });
      } else {
        env = await this.sign({
          payment_id: item.payment_id,
          address: key.address,
          signature_hex,
        });
      }
      envelopes.push(env);
    }
    return { signed: envelopes.length, envelopes };
  }

  /**
   * If action_required is for this key, sign it. Otherwise no-op.
   * Foreign multi-hop: POSTs to action.sign_endpoint when absolute origin URL.
   */
  async signIfNeeded(key: HacashKey, env: MachineEnvelope): Promise<MachineEnvelope> {
    const ar = env.action_required;
    if (!ar) return env;
    if (ar.kind !== "sign_payment") return env;
    if (ar.address !== key.address) return env;
    const endpoint = (ar.sign_endpoint || "").trim();
    if (!this.isLocalSignEndpoint(endpoint)) return env;
    const signature_hex = key.signHashHex(ar.sign_this_hash_hex);
    if (
      (endpoint.startsWith("http://") || endpoint.startsWith("https://")) &&
      !endpoint.replace(/\/$/, "").startsWith(this.baseUrl)
    ) {
      return this.signAtEndpoint(endpoint, {
        payment_id: String(ar.payment_id),
        address: key.address,
        signature_hex,
      });
    }
    return this.sign({
      payment_id: String(ar.payment_id),
      address: key.address,
      signature_hex,
    });
  }

  private isLocalSignEndpoint(endpoint: string): boolean {
    try {
      const actual = new URL(endpoint, `${this.baseUrl}/`);
      const expected = new URL(`${this.baseUrl}/v1/agent/v1/sign`);
      return (
        actual.origin === expected.origin &&
        actual.pathname === expected.pathname &&
        actual.search === "" &&
        actual.hash === "" &&
        actual.username === "" &&
        actual.password === ""
      );
    } catch {
      return false;
    }
  }

  /** POST sign to absolute origin hub URL (multi-hop foreign mirror). */
  async signAtEndpoint(
    signEndpoint: string,
    opts: { payment_id: string; address: string; signature_hex: string; public_key_hex?: string },
  ): Promise<MachineEnvelope> {
    if (!this.isLocalSignEndpoint(signEndpoint)) {
      throw new AgentPayError("unsafe_sign_endpoint", "refusing to send a signature or API key to a foreign origin");
    }
    const res = await this.fetchFn(signEndpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        ...this.authHeaders(),
      },
      body: JSON.stringify({
        payment_id: opts.payment_id,
        address: opts.address,
        signature_hex: opts.signature_hex,
        public_key_hex: opts.public_key_hex ?? "",
        agent_id: this.agentId,
      }),
    });
    const body = (await res.json()) as MachineEnvelope;
    if (!body.ok) {
      throw new AgentPayError(
        body.error?.code || "sign_failed",
        body.error?.message || "sign failed",
        body,
      );
    }
    return body;
  }

  /**
   * Poll until machine.done (or timeout).
   * If `key` is provided, auto-signs when it is this agent's turn.
   */
  async waitUntilDone(
    paymentId: string,
    key?: HacashKey,
  ): Promise<MachineEnvelope> {
    const start = Date.now();
    let env = await this.status(paymentId);
    while (!env.machine.done) {
      if (Date.now() - start > this.waitTimeoutMs) {
        throw new AgentPayError("timeout", `payment ${paymentId} not done in time`, env);
      }
      if (key) {
        env = await this.signIfNeeded(key, env);
        if (env.machine.done) break;
      }
      // Also drain any other inbox items for this key
      if (key) {
        await this.drainInbox(key);
        env = await this.status(paymentId);
        if (env.machine.done) break;
      }
      const sleep = env.machine.next_poll_ms || this.pollMs;
      await delay(sleep);
      env = await this.status(paymentId);
    }
    return env;
  }

  /**
   * High-level: quote → pay → auto-sign as payer if key given → wait.
   * Counterparty (payee) must sign via their own agent drainInbox/waitUntilDone.
   */
  async send(opts: PayOptions & { key?: HacashKey }): Promise<{
    envelope: MachineEnvelope;
    receipt?: PaymentReceipt;
    payment_id: string;
  }> {
    const q = await this.quote({
      from: opts.from,
      to: opts.to,
      amount_hac: opts.amount_hac,
      amount_satoshi: opts.amount_satoshi,
      local_only: opts.local_only,
    });
    if (!q.can_pay) {
      throw new AgentPayError("no_route", q.note || "no route between addresses");
    }

    let env = await this.pay(opts);
    const paymentId = String(
      (env.result as { payment_id?: string })?.payment_id ??
        (env.action_required?.payment_id ?? ""),
    );
    if (!paymentId) {
      // try nested payment object
      const pay = (env.result as { payment?: { payment_id?: string } })?.payment;
      if (pay?.payment_id) {
        // use it
      }
    }
    const pid =
      paymentId ||
      String(
        (env.result as { payment?: { payment_id?: string } })?.payment?.payment_id ??
          env.action_required?.payment_id ??
          "",
      );

    if (opts.key) {
      env = await this.signIfNeeded(opts.key, env);
      env = await this.waitUntilDone(pid || String(env.action_required?.payment_id), opts.key);
    }

    const finalId = pid || String(env.action_required?.payment_id ?? "");
    let receipt: PaymentReceipt | undefined;
    if (env.machine.done && env.machine.success && finalId) {
      try {
        receipt = await this.receipt(finalId);
      } catch {
        /* optional */
      }
    }
    return { envelope: env, receipt, payment_id: finalId };
  }

  // --- L1 ChannelClose helpers (evidence + submit relay; no key custody) ---

  /** Agent close-plan: ready flag, distribution, wallet_actions. */
  async closePlan(channelId: string): Promise<Record<string, unknown>> {
    const body = await this.getJson(`/v1/agent/v1/close-plan/${channelId}`);
    if (!body.ok) {
      const err = (body.error as { code?: string; message?: string }) || {};
      throw new AgentPayError(
        err.code || "close_plan_failed",
        err.message || String(body.err || body),
        body as MachineEnvelope,
      );
    }
    return body;
  }

  /** Raw hub dispute export. */
  async exportDispute(channelId: string): Promise<Record<string, unknown>> {
    const body = await this.getJson(`/v1/channels/${channelId}/dispute`);
    if (!body.ok) {
      throw new AgentPayError("dispute_export_failed", String(body.err || body));
    }
    return (body.export as Record<string, unknown>) || body;
  }

  /** Normalized close intent (hacash-l2-close-intent/1). */
  async closeIntent(channelId: string): Promise<CloseIntent> {
    try {
      const body = await this.closePlan(channelId);
      return buildCloseIntent(body);
    } catch {
      const exp = await this.exportDispute(channelId);
      return buildCloseIntent({ export: exp });
    }
  }

  async closeChecklistFor(channelId: string): Promise<string[]> {
    return closeChecklist(await this.closeIntent(channelId));
  }

  async requireReadyForClose(channelId: string): Promise<CloseIntent> {
    const intent = await this.closeIntent(channelId);
    assertReadyForClose(intent);
    return intent;
  }

  /**
   * Relay already-signed L1 tx hex via hub → fullnode.
   * Does not build ChannelClose; requires hub API token when configured.
   */
  async submitSignedL1Tx(txHex: string, path = ""): Promise<Record<string, unknown>> {
    const body = await this.postJson("/v1/l1/submit", { tx_hex: txHex, path });
    if (!body.ok) {
      throw new AgentPayError("l1_submit_failed", String(body.err || body));
    }
    return body;
  }

  // --- HTTP ---

  private authHeaders(): Record<string, string> {
    if (!this.apiKey) return {};
    return {
      "X-Api-Token": this.apiKey,
      Authorization: `Bearer ${this.apiKey}`,
    };
  }

  private async getJson(path: string): Promise<Record<string, any>> {
    const res = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: { accept: "application/json", ...this.authHeaders() },
    });
    return res.json();
  }

  private async postJson(path: string, body: unknown): Promise<Record<string, any>> {
    const res = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        ...this.authHeaders(),
      },
      body: JSON.stringify(body),
    });
    return res.json();
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
