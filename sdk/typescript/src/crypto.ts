/**
 * Hacash L1-compatible keys for agents (never send private keys to the hub).
 *
 * - address = base58check(version=0 || RIPEMD160(SHA256(compressed_pubkey)))
 * - password account = SHA256(password) as private key (same as fullnode Account::create_by_password)
 * - sign wire = 97-byte hex: compressed_pubkey[33] || ecdsa_sig[64]
 */

import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { sha3_256 } from "@noble/hashes/sha3";
import { ripemd160 } from "@noble/hashes/ripemd160";
import * as secp from "@noble/secp256k1";

// Noble keeps synchronous hashing injectable so browser and Node runtimes use
// the same audited primitive instead of an environment-specific implementation.
secp.etc.hmacSha256Sync = (key, ...messages) => hmac(sha256, key, secp.etc.concatBytes(...messages));
// bs58check v4 default export
import bs58check from "bs58check";
// Avoid relying on Node Buffer in edge runtimes
function asUint8(a: Uint8Array): Uint8Array {
  return a;
}

export class HacashKey {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array; // 33-byte compressed
  readonly address: string;

  private constructor(privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error("private key must be 32 bytes");
    }
    if (privateKey[0] === 255 && privateKey[1] === 255 && privateKey[2] === 255 && privateKey[3] === 255) {
      throw new Error("secret_key not supported; try a different one");
    }
    this.privateKey = privateKey;
    this.publicKey = secp.getPublicKey(privateKey, true);
    this.address = addressFromPubkey(this.publicKey);
  }

  /** Same as Hacash Account::create_by_password */
  static fromPassword(password: string): HacashKey {
    const key = sha256(new TextEncoder().encode(password));
    return new HacashKey(key);
  }

  /** 32-byte hex private key */
  static fromPrivateKeyHex(hex: string): HacashKey {
    const clean = hex.replace(/^0x/i, "");
    if (clean.length !== 64) throw new Error("private key hex must be 64 chars");
    return new HacashKey(hexToBytes(clean));
  }

  /**
   * Sign a 32-byte payment/bill hash (already SHA3-256 from hub).
   * Returns 97-byte Sign hex (pubkey || sig) for HAP /v1/agent/v1/sign.
   */
  signHashHex(hashHex: string): string {
    const hash = hexToBytes(hashHex.replace(/^0x/i, ""));
    if (hash.length !== 32) throw new Error("hash must be 32 bytes");
    // noble secp256k1: sign returns compact 64-byte r||s (low-S)
    const sig = secp.sign(hash, this.privateKey);
    const compact = sig.toCompactRawBytes();
    const out = new Uint8Array(97);
    out.set(this.publicKey, 0);
    out.set(compact, 33);
    return bytesToHex(out);
  }

  /** Verify a 97-byte Sign hex against this key's address (optional helper). */
  static verifySignHex(hashHex: string, signHex: string, expectedAddress: string): boolean {
    try {
      const hash = hexToBytes(hashHex.replace(/^0x/i, ""));
      const raw = hexToBytes(signHex.replace(/^0x/i, ""));
      if (raw.length !== 97 || hash.length !== 32) return false;
      const pk = raw.slice(0, 33);
      const sig = raw.slice(33);
      if (addressFromPubkey(pk) !== expectedAddress) return false;
      return secp.verify(sig, hash, pk);
    } catch {
      return false;
    }
  }
}

export function addressFromPubkey(pubkey: Uint8Array): string {
  const h = ripemd160(sha256(pubkey));
  const payload = new Uint8Array(21);
  payload[0] = 0; // version
  payload.set(h, 1);
  // bs58check: first byte is version, rest is hash (21 bytes total).
  return bs58check.encode(asUint8(payload));
}

export function sha3Hex(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha3_256(bytes));
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("hex must contain an even number of hexadecimal characters");
  }
  const h = hex;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

export interface AgentIntentParams {
  providerId: string;
  agentId: string;
  from: string;
  to: string;
  amountHac: string;
  amountSatoshi?: number;
  feeHac?: string;
  route?: string[];
  invoiceId?: string;
  idempotencyKey: string;
  nonce: string;
  expiresUnix: number;
}

function intentField(name: string, value: string): string {
  const byteLength = new TextEncoder().encode(value).length;
  return `${name}_len=${byteLength}\n${name}=${value}\n`;
}

/** Exact domain-separated message expected by hubs enforcing verified agents. */
export function buildAgentIntentMessage(p: AgentIntentParams): string {
  const route = p.route ?? [];
  const values: Array<[string, string]> = [
    ["provider_id", p.providerId],
    ["agent_id", p.agentId],
    ["from", p.from],
    ["to", p.to],
    ["amount_hac", p.amountHac],
    ["fee_hac", p.feeHac ?? "0"],
    ["invoice_id", p.invoiceId ?? ""],
    ["idempotency_key", p.idempotencyKey],
    ["nonce", p.nonce],
  ];
  for (const [name, value] of values) {
    if (/[\u0000-\u001f\u007f]/.test(value)) {
      throw new Error(`${name} contains control characters`);
    }
  }
  if (p.nonce.length < 16 || p.nonce.length > 128) {
    throw new Error("intent nonce must be 16..=128 characters");
  }
  let out = "HACASH_AGENT_PAY_INTENT_V1\n";
  out += intentField("provider_id", p.providerId);
  out += intentField("agent_id", p.agentId);
  out += intentField("from", p.from);
  out += intentField("to", p.to);
  out += intentField("amount_hac", p.amountHac);
  out += `amount_satoshi=${p.amountSatoshi ?? 0}\n`;
  out += intentField("fee_hac", p.feeHac ?? "0");
  out += `route_count=${route.length}\n`;
  route.forEach((channelId, index) => {
    out += intentField(`route_${index}`, channelId);
  });
  out += intentField("invoice_id", p.invoiceId ?? "");
  out += intentField("idempotency_key", p.idempotencyKey);
  out += intentField("nonce", p.nonce);
  out += `expires_unix=${p.expiresUnix}\n`;
  return out;
}

export function signAgentIntent(key: HacashKey, params: AgentIntentParams) {
  const message = buildAgentIntentMessage(params);
  return {
    nonce: params.nonce,
    expires_unix: params.expiresUnix,
    signature_hex: key.signHashHex(sha3Hex(message)),
  };
}
