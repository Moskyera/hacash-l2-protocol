# Security & trust model — hacash-l2-hub

This hub is a **Channel Service Provider (CSP)** coordinator for Hacash L2
[Channel Chain](https://hacash.org/layer-2). It is **not** a bank and **must not**
hold user private keys.

Official CSP model: [layer-2-node](https://hacash.org/layer-2-node) — like email/broadband
providers: they route; they do not own your funds.

## What "settled" means (read this)

| Term | Meaning on this hub |
|------|---------------------|
| `status: settled` | All **ordered multi-sig** signatures for the session were collected here |
| `finality: hub_coordinated_not_l1` | Explicit: **not** L1 `ChannelClose` / arbitration |
| Real L1 finality | Only on fullnode via channel close / dispute evidence |

Wallets and AI agents **must not** treat hub `settled` as irreversible on-chain money
movement until L1 confirms close (or your protocol's reconciling bill is safe per whitepaper).

## Trust boundaries

| Component | Trust |
|-----------|--------|
| User wallet / AI agent | Holds keys; signs payments |
| This hub | Coordinates route, sessions, peer gossip; **no custody** |
| Peer hubs | Same role; may lie about advertised channels — verify with L1 when critical |
| L1 fullnode | Source of truth for open channels and arbitration |

## Built-in protections (reliability phase)

1. **Optional API token** (`--api-token` / `HACASH_L2_API_TOKEN`)
   Protects operator mutators: register channel, refresh, bootstrap, fail payment.
   Headers: `X-Api-Token: …` or `Authorization: Bearer …`.
   Wallet `POST /v1/payments` and `POST …/sign` stay open so public CSPs work.

2. **SSRF-safe outbound peers**
   Bootstrap/gossip only to `http://` / `https://`.
   By default **blocks** loopback, private RFC1918, link-local, metadata hostnames.
   Local multi-hub tests: `--allow-private-peers`.
   No HTTP redirects followed on peer client.

3. **Request body limit** (`--max-body-bytes`, default 256 KiB).

4. **DoS caps** — max channels, peers, payment sessions, hops, hello ads.

5. **Payment TTL** (`--payment-ttl-secs`, default 3600) → `timed_out` if still collecting.

6. **Optional persistence** (`--state-path`) for channels + peer seeds + bills + **agent recovery**
   (open payments, invoices, identities, content-bound idempotency keys).

7. **Honest API labels** — `finality`, status notes, agent `payment_rules.finality`.

8. **Agent pay hardening** — invoice amounts forced; idempotency content-bound (same key ≠ different body);
   optional hub-signed receipts; rate-limit ignores spoofed `X-Forwarded-For` unless `--trust-proxy`.

9. **Policy principal binding** — spend caps / open payments keyed by:
   - `v:{address}` when `agent_id` is **verified** (rotating agent_id does not reset limits)
   - `u:{agent_id}` when unverified
   - `a:{payer}` for anonymous
   HTTP also rate-limits `v:{address}` when verified (body or `X-Hacash-Agent-Id`).
   Production: `HACASH_L2_REQUIRE_VERIFIED_AGENT=true`.

## Cross-hub durable transaction model

Cross-hub payments require `--state-path`, a hub identity key, and strict signed
hello verification. Peer identities are pinned after a verified hello;
an unsigned hello cannot replace a pin and identity rotation requires explicit
operator action.

The coordinator and every participant use a hash-chained, append-only JSONL
journal at `<state_path>.txlog`. Each acknowledged transition is written and
synced before the acknowledgement is returned. Complete-record corruption,
sequence gaps, invalid state transitions, and hash-chain mismatches stop startup;
only a non-newline-terminated torn tail is truncated.

Protocol safety rules:

- prepare, commit, abort, and acknowledgements are signed by pinned hub
  identities and bound to the full transaction descriptor;
- the participant checks exact ownership coverage and direction of its route
  hops;
- commit carries the complete ordered user signature set, which every
  participant verifies cryptographically;
- commit decision is durable before balance application and can never become
  abort;
- balance application and all phase messages are idempotent;
- prepared participants do not time out unilaterally;
- unresolved commit and abort acknowledgements are retried after restart.

The journal hash chain detects accidental corruption; it is not a substitute
for filesystem permissions, encrypted backups, host integrity, or an HSM.
2PC is blocking during coordinator failure and still does not provide L1
finality.

## Phase B crypto (payment signatures)

| Item | Spec |
|------|------|
| Domain | `HACASH_L2_PAYMENT_V1` |
| Hash | SHA3-256 of canonical UTF-8 message |
| Curve | secp256k1 (Hacash `sys::Account` / L1) |
| Wire | 97-byte Sign hex = compressed pubkey \|\| ECDSA sig; or 64-byte sig + `public_key_hex` |
| Address | Must equal address derived from the public key |
| Disable | `--sig-verify=false` only for local demos (not production) |

See `GET /v1/payments/:id/message` and `crypto` in agent capabilities.

## Phase C bills (reconciliation)

| Item | Spec |
|------|------|
| Domain | `HACASH_L2_BILL_V1` |
| Storage | **One last bill** per channel (higher sequence replaces) |
| Activate | left + right verified secp256k1 over bill hash |
| Hub role | Backup only — **never invents balances** |
| Dispute | `GET /v1/channels/:id/bill/export` → wallet builds L1 close |
| Not L1 | Export is evidence package; hub does **not** broadcast ChannelClose |
| Capability gate | `/v1/channels/:id/l1-exit/readiness` verifies registered and height-enabled fullnode actions; failure means no signing or broadcast |
| Action 3 | Cooperative original-funding return only; it cannot settle the negotiated off-chain distribution |

## What is **not** finished (honest limits)

- **No automatic L1 ChannelClose submission** from the hub (by design / Phase D+ wallet).
- **Peer channel ads** are gossip, not L1-proven balances.
- **TLS** is operator responsibility (reverse proxy / public HTTPS URL).
- Hub can be DoS'd if left open on the internet without rate limits at the edge.
- Payment `settled` still means hub coordination; **active bill** is the off-chain credential; L1 close is separate.

## Operator checklist

1. Set a strong `--api-token` on any internet-facing hub.
2. Use HTTPS `public-url` behind a reverse proxy.
3. Point `--fullnode` at a fullnode you trust; use fullnode `api_token` if required.
4. Keep `--allow-private-peers` **off** in production.
5. Persist with `--state-path ./data/hub-state.json` on VPS.
6. Never put user private keys in hub config or env.

## Dependency status

The `hub-v0.2.0` release passes `cargo audit` with no known vulnerable
dependencies as of 2026-08-09. The audit does report that
`libsecp256k1 0.7.2` is unmaintained (`RUSTSEC-2025-0161`). Replacing a
signature library is a compatibility-sensitive cryptographic migration, so
it must be completed with Hacash signature and address test vectors before a
production mainnet claim. Until then, this release is a technical preview and
the HPAY wallet must keep its documented mainnet readiness gates fail-closed.


## Related

- [HVM-EVOLUTION.md](HVM-EVOLUTION.md) — how Istanbul/HVM can harden the hub later
- [NETWORK.md](NETWORK.md) — multi-hub / wallet / agent model
- Official: [layer-2-intro](https://hacash.org/layer-2-intro) · [HVM](https://hacash.com/HVM)
