# Hacash L2 Protocol V3 — Safety Foundation

Status: implementation draft. This defines required guarantees; it does not claim that the current hub already provides all of them.

## Current implementation status

Implemented in shadow and negotiated-activation modes: standalone V2 canonical validation and signatures; bounded latest-observation storage per channel party; automatic deterministic equivocation proofs; snapshot format v9 persistence with backward loading; fail-closed semantic restore; exact fullnode channel-incarnation provenance; read-only proof/draft APIs, and mutually signed strict-verification activation. `POST /v1/channels/:id/state-v2/observe` requires `--state-path` and is durably checkpointed before success is acknowledged. `GET /v1/channels/:id/state-v2/shadow` deterministically derives an unsigned V2 candidate from a cryptographically valid active V1 bill.

Shadow mode does not alter balances, V1 bills, routing, payment settlement, or peer negotiation. A refresh binds the registration to Hacash mainnet genesis and the fullnode-returned channel id, `reuse_version`, open height, arbitration parameters, parties, and exact funding amounts. The resulting hash identifies one funding incarnation and cannot silently change. This is still a trusted fullnode observation, not an L1 inclusion proof; APIs therefore report `l1_inclusion_proof_verified: false`, `l1_enforceable: false`, and `settlement_changed: false`.
Snapshot v9 durably stores negotiated activation certificates and their latest mutually signed verification heads, while v8 snapshots still load with no activation.

Negotiated activation uses the portable `HACASH_L2_CHANNEL_ACTIVATION_V1` domain and requires exactly both channel-party signatures. The commitment binds network genesis, funding incarnation, initial mutually signed V2 state, and parties; its safety flags must remain `settlement_authority: false` and `l1_enforceable: false`.


## Goal and trust boundaries

V3 targets a global, non-custodial payment network for humans and autonomous agents. Hubs coordinate and route but never receive authority to spend user funds. A failure may delay funds; it must not create, redirect, duplicate, or steal value. Hub acknowledgement is never described as L1 finality.

- Wallets and isolated agent-wallet processes own keys and spending policy.
- Hubs are Byzantine: they may lie, equivocate, censor, replay, stop, collude, reorder messages, or lose data.
- Seeds, peer gossip, liquidity ads, and watchtowers are inputs, not authorities.
- Hacash L1 is the final funding and arbitration authority.
- An AI model may propose an action but is not a trusted signer. A deterministic policy process verifies and signs the exact commitment.

## Release-blocking safety invariants

1. Conservation: each accepted state preserves exact funded HAC in Zhu and exact funded satoshi.
2. Authorization: only channel parties authorize a channel-state change.
3. Monotonicity: successors strictly increase sequence and bind the previous accepted state hash.
4. No split state: different hashes for the same channel and sequence signed by one party form portable, independently verifiable equivocation evidence.
5. Exact payment: one intent binds amount, assets, recipient, fee limit, expiry, route commitment, and idempotency identity.
6. Exactly-once application: retry and crash recovery cannot apply a transition twice.
7. Durable-before-ack: safety-critical decisions are synced before acknowledgement.
8. Decision monotonicity: commit cannot become abort or vice versa.
9. Portable evidence: state credentials are not bound to one hub.
10. Honest finality: APIs distinguish `hub_coordinated`, `channel_signed`, and `l1_final`.
11. Unilateral exit: after L1 enforcement, either party can recover its latest enforceable balance without hub or counterparty cooperation.
12. Bounded agent authority: signatures bind asset, amount, recipient, fee, expiry, nonce, and capability scope.

## Liveness and Byzantine model

A failed coordinator must not lock funds permanently. Prepared transactions remain safe across partitions and recover to a durable decision. The final construction requires an L1 timeout/refund path; durable 2PC is the reliable fast path, not the trustless escape path. Overload is explicit and bounded, never a silent drop.

Mandatory adversarial cases include false liquidity; conflicting signed states; withheld decisions; false prepare ownership; replay, reorder, duplication, truncation and cross-network messages; identity downgrade/rotation; compromised agents making valid but policy-breaking requests; retry storms and Sybils; liquidity exhaustion; disk corruption and rollback; and colluding route hubs while at least one channel party is honest.

## Protocol layers and versioning

Layers are L1 arbitration; channel commitments/evidence; conditional multi-hop transfer; authenticated transport; bounded routing/gossip; wallet and agent policy; and operations. Routing or transport optimizations never alter signed state semantics.

Existing peer protocol `2.x` remains unchanged. Channel-state V2 uses `HACASH_L2_CHANNEL_STATE_V2`. A feature is advertised only after the node can validate, persist, serve, and recover it. Unknown required features fail closed. Canonical encodings are byte-defined, length-delimited, and protected by golden vectors. Wire changes need a domain/version; storage changes need migration and backward-load tests. Rollout order is verify, shadow-write, dual-serve, opt-in activation, mandatory enforcement.

## Channel-state commitment V2

The portable signed payload contains domain/schema, network genesis, 16-byte channel id, L1 funding anchor, sequence, predecessor hash, both party addresses, exact balances and funding totals for HAC/Zhu and satoshi, optional conditional root, and only an L1-required absolute expiry.

Validation is fail-closed: exact identifier sizes, unsigned big-endian integers, length-delimited strings, checked arithmetic, balance conservation, sequence above zero, an empty predecessor only at sequence one, and valid party signatures. Both signatures are required for mutual acceptance. `HACASH_L2_BILL_V1` remains readable and is never silently reinterpreted as V2.

## Negotiated V2 activation

Activation is an explicit opt-in to strict chain verification, not a balance transition. A draft can be created only from a mutually signed V2 state already verified against the registered L1 funding anchor. Exactly both channel parties sign the canonical activation hash; the hub never reuses V1 signatures and an AI agent must not auto-sign it.

After activation, a state above the durable verification head is accepted only at `head.sequence + 1` and only when its predecessor hash equals the head state hash. One-party observations may be retained as evidence, but the durable head advances only after both signatures merge. A different activation for the same funding incarnation is rejected; an identical retry is idempotent.

Activation changes neither balances nor payment settlement and supplies no unilateral exit. Trustless status still requires portable L1 inclusion/state proofs and an L1-enforceable close/arbitration construction.

### Current L1 capability gate

The hub queries `/query/capabilities` and accepts only a consistent mainnet response whose enabled actions are also registered. The active node exposes cooperative action 3; its consensus semantics require both channel parties to sign the L1 transaction and return the original funding distribution. It has no distribution fields and cannot settle a newer off-chain balance.

Legacy actions 23 and 27 are present in older source models but are not registered by the active node. Even a future node exposing those legacy codecs would not automatically make V2 enforceable: their reconciliation signing bytes differ from `HACASH_L2_CHANNEL_STATE_V2` and `HACASH_L2_CHANNEL_ACTIVATION_V1`. An agent must treat any missing, malformed, inconsistent, or incompatible capability response as a hard prohibition on signing and broadcasting.

## Equivocation evidence

A proof contains two complete canonical states, signatures, common channel, sequence, and signer. Both states independently validate; channel, sequence, parties, network, and funding anchor match; hashes differ; and the accused party signed both. Proofs are deterministic, portable, deduplicated, durable, and exportable. Initial handling records evidence and blocks unsafe advancement. Punishment waits for an explicit L1 rule.

## Distributed decisions and L1 escape

Authenticated durable prepare/commit/abort remains the crash-safe fast path. Its successor adds signed decision certificates, recovery from multiple authenticated sources, bounded deadlines, replay-safe descriptors, proof of one atomic outcome, and an L1-enforceable conditional claim/refund. A prepared participant never guesses abort while a durable commit may exist.

## Agent security

Every signing request binds identity/scope, payer, recipient, assets, maximum amount/fee, purpose or invoice, nonce/idempotency key, creation, hard expiry, and optional allowlist/human approval. The wallet process enforces per-payment, rolling, daily, open-liability and recipient limits; supports revocation; rate-limits signing; and keeps keys out of prompts, tools, logs, and hubs. Micropayments use signed aggregation/checkpoints rather than one durable write per tiny unit.

## Scale and release gates

Reproducible tests publish throughput, p50/p95/p99 latency, crash/partition recovery, fsync/group-commit cost, bytes per channel/payment/agent, gossip cost, retry-storm behavior, route success under skewed liquidity, and proof cost. They cover independent and hot channels, concurrent traffic, many hubs, millions of synthetic agents, adversarial traffic, and real-signature durable restarts.

Production requires canonical vectors; unit, property, replay, corruption and compatibility tests; process-level crash/partition tests; bounded resources; migration/rollback instructions; and independent review for crypto/L1 changes. "Trustless" is reserved for demonstrated unilateral L1 recovery. Before that, the accurate claim is non-custodial, authenticated, and crash-safe with explicit trust assumptions.

## Implementation order

1. Standalone V2 encoding, validation, signatures, vectors, and equivocation proofs without changing settlement.
2. Durable observation/evidence storage and read-only export.
3. Shadow V2 creation beside V1 bills with invariant comparison.
4. Negotiated activation and wallet verification.
5. End-to-end L1 unilateral close/arbitration.
6. Trustless conditional multi-hop recovery.
7. Measured storage, transport, routing, and privacy optimization.
