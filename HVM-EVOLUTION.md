# How HVM / Istanbul can evolve this hub

Research notes aligned with [hacash.org L2](https://hacash.org/layer-2) and
[Hacash Virtual Machine](https://hacash.com/HVM), plus this repo's Istanbul gates.

## Official L2 (Channel Chain) — what the hub must respect

From [layer-2-intro](https://hacash.org/layer-2-intro):

- **State channel** core: lock funds → many off-chain payments → on-chain settle or arbitrate.
- **Synchronous payments** preferred over Lightning-style async hops (all-or-nothing security).
- **Only last reconciliation bill** needed (not full payment history).
- **CSP (Channel Service Provider)** = email/broadband: routes value, **does not custody keys**.
- Address form: `1Addr_channelId_ProviderId` ([layer-2-node](https://hacash.org/layer-2-node)).

This hub today implements **coordination + multi-hub routing discovery**.
It does **not** yet implement full whitepaper channel bills or L1 close automation.

## HVM / Istanbul toolkit (mainnet height 765432)

In this codebase (`protocol` / `app` capabilities):

| Feature | Kind / note | Hub evolution use |
|---------|-------------|-------------------|
| **type3 multisig** | ≤200 signers | Hub operator treasury, multi-admin CSP keys |
| **VM contracts** | actions 40/41/44 | Escrow, fee split, PayFi agents |
| **P2SH** | action 46 | Scripted lockboxes, conditional claim |
| **ViewCheckSign** | VM native | On-chain verification of payment proofs |
| **HeightScope / BalanceFloor** | guards | Time/balance constrained channel logic |
| **Account abstraction** | HVM design | Agent wallets without exposing raw keys to hub |

HVM marketing ([hacash.com/HVM](https://hacash.com/HVM)): security-first, multi-language contracts,
state-efficient storage — aimed at DeFi / BTCFi / **PayFi**.

## Evolution roadmap (hub ↔ L1/HVM)

### Phase A — Honesty & ops (done in reliability pass)

- Label hub settle as **not L1 final**
- API token, SSRF bootstrap, TTL, persistence, caps
- L1 channel watch via fullnode `/query/channel`

### Phase B — Real signatures ✅ (implemented in l2-hub)

1. **Canonical payment message** `HACASH_L2_PAYMENT_V1` (session_id, provider, payer/payee, amounts, route, signers, created_unix).
2. **SHA3-256** → 32-byte `message_hash_hex` (same family as `sys::sha3` / Hacash).
3. **secp256k1 verify** via `sys::Account` (same as L1 wallets); address must match derived pubkey.
4. Wire: **97-byte Sign** hex (`pubkey[33]||sig[64]`) or 64-byte sig + `public_key_hex`.
5. Ordered multi-sig still enforced; fake hex signatures rejected when `--sig-verify` (default).
6. API: `GET /v1/payments/:id/message` for wallets/agents.

### Phase C — Reconciliation bills ✅ (implemented in l2-hub)

1. **Last bill only** per `channel_id` (`HACASH_L2_BILL_V1`, sequence monotonic).
2. Hub **backs up** client-submitted balances — never invents empty bills.
3. Both **left + right** secp256k1-sign → `status=active`; channel balances mirrored.
4. **Dispute export** `GET /v1/channels/:id/bill/export` for wallet L1 ChannelClose (hub does not submit txs).
5. Persistence v2 stores last bills with channels/peers.

### Phase D — HVM-backed CSP services

| Idea | HVM building block |
|------|--------------------|
| Fee escrow for multi-hop | Contract or P2SH lockbox |
| Agent payment allowance | Account abstraction + ViewCheckSign |
| Operator multi-sig treasury | type3 multisig |
| Timed dispute windows | HeightScope |
| Conditional refunds | P2SH / BalanceFloor |

### Phase E — Do **not** centralize

Even with HVM:

- Users choose any CSP (`_ProviderId`); revoke anytime (official model).
- Super-hubs are **seed / discovery**, not monopolies.
- Hub never becomes a custodial exchange.

## Practical implication for this binary

`hacash-l2-hub` stays a **Rust API coordinator**.
Heavy crypto and contract logic belong in:

1. Wallet / agent (signing)
2. Fullnode + HVM (verification, open/close, contracts)
3. Future optional "bill verifier" module that calls L1/HVM views

Phase B signatures + Phase C last bills are **real off-chain credentials**.
**L1 money finality** still requires wallet/fullnode `ChannelClose` / arbitration (export package only from hub).

## References

- https://hacash.org/layer-2
- https://hacash.org/layer-2-intro
- https://hacash.org/layer-2-node
- https://hacash.org/whitepaper.pdf
- https://hacash.com/HVM
- Repo: `protocol/src/upgrade.rs` (`ONLINE_OPEN_HEIGHT`), `docs/COMMUNITY-POOL-DESIGN.md` (Istanbul summary)
