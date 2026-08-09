export interface AgentPaymentMeta {
  agent_id?: string;
  purpose?: string;
  invoice_id?: string;
  skill?: string;
  conversation_id?: string;
  extra?: string;
}

export interface MachineStatus {
  state: string;
  done: boolean;
  success: boolean;
  retryable: boolean;
  next_poll_ms: number;
}

export interface ActionRequired {
  kind: string;
  payment_id: string;
  address: string;
  sign_this_hash_hex: string;
  deadline_unix: number;
  sign_endpoint: string;
  sign_body_template: Record<string, unknown>;
  instructions: string[];
}

export interface MachineEnvelope {
  ok: boolean;
  protocol: string;
  request_id: string;
  machine: MachineStatus;
  action_required?: ActionRequired | null;
  error?: { code: string; message: string } | null;
  result: Record<string, unknown>;
  human: { title: string; detail: string };
}

export interface QuoteResult {
  ok: boolean;
  from: string;
  to: string;
  amount_hac: string;
  amount_satoshi: number;
  route: string[];
  hops: number;
  required_signers: string[];
  remote_hubs: number;
  estimated_sign_rounds: number;
  can_pay: boolean;
  note: string;
}

export interface InboxItem {
  kind: string;
  payment_id: string;
  role: string;
  amount_hac: string;
  counterparty: string;
  sign_this_hash_hex: string;
  expires_unix: number;
  priority: number;
  meta: AgentPaymentMeta;
  action: ActionRequired;
}

export interface PaymentReceipt {
  protocol: string;
  payment_id: string;
  status: string;
  finality: string;
  payer: string;
  payee: string;
  amount_hac: string;
  receipt_hash_hex: string;
  disclaimer: string;
  meta: AgentPaymentMeta;
}
export interface AgentIntentProof {
  nonce: string;
  expires_unix: number;
  signature_hex: string;
  public_key_hex?: string;
}


export interface PayOptions {
  from: string;
  to: string;
  amount_hac?: string;
  amount_satoshi?: number;
  idempotency_key: string;
  local_only?: boolean;
  meta?: AgentPaymentMeta;
  intent?: AgentIntentProof;
}

export interface AgentClientOptions {
  /** Hub base URL, e.g. http://127.0.0.1:9090 */
  baseUrl: string;
  /** Optional fetch implementation (default global fetch) */
  fetch?: typeof fetch;
  /** Default agent_id stamped into meta */
  agentId?: string;
  /** Max wait ms for waitUntilDone (default 120_000) */
  waitTimeoutMs?: number;
  /** Poll interval ms (default 1500) */
  pollMs?: number;
  /** Agent API key (X-Api-Token / Bearer) when hub sets agent_api_key */
  agentApiKey?: string;
  /** Alias for agentApiKey */
  apiKey?: string;
}
