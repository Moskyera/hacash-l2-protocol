# Hacash L2 Protocol — Channel Chain Hub

**Standalone** L2 project (Channel Service Provider).
**Not** part of the miner / fullnode monorepo.

| | |
|--|--|
| **Protocol** | Hacash Layer-2 Channel Chain (instant payments) |
| **Role** | CSP hub — routing, multi-hub network, bills, wallet/agent API |
| **Custody** | None — keys stay in wallets / AI agents |
| **Binary** | `hacash-l2-hub` |

Official L2 docs: [layer-2](https://hacash.org/layer-2) · [CSP](https://hacash.org/layer-2-node) · [HVM](https://hacash.com/HVM)

The **miner / fullnode** lives separately under `hacash-fullnodedev`. This repo only talks to a fullnode via HTTP (`--fullnode host:port`) for channel queries.

---
## Download

Release archives are published separately for:

- Windows x64;
- Linux x86_64 and VPS;
- Docker deployments built from the pinned source.

Every archive includes a SHA-256 corruption check and GitHub build provenance.
See `README-HUB.txt` before public hosting. HPAY mainnet Fast Pay remains
fail-closed until all production readiness gates are reported.

---

## Build & run

```powershell
git clone https://github.com/Moskyera/hacash-l2-protocol.git
cd hacash-l2-protocol
cargo build --release
cargo test

# Opt-in: full fsync/local-apply crash matrix plus concurrent idempotency
# and network-partition recovery using real hub processes.
cargo test --test chaos_2pc -- --ignored --nocapture

# Opt-in: Linux/Docker three-hub SIGKILL, randomized restart ordering,
# network partitions, durable recovery, idempotency, and exact balances.
cargo test --test docker_chaos_3hub -- --ignored --nocapture

# Only the concurrent three-hub partition/SIGKILL soak:
cargo test --test docker_chaos_3hub linux_three_hub_concurrent_partition_soak -- --ignored --nocapture

# Optional heavier soak (up to 6 batches x 8 concurrent payments):
$env:HACASH_DOCKER_SOAK_BATCHES='3'
$env:HACASH_DOCKER_SOAK_CONCURRENCY='6'
cargo test --test docker_chaos_3hub linux_three_hub_concurrent_partition_soak -- --ignored --nocapture

.\target\release\hacash-l2-hub.exe `
  --bind 0.0.0.0:9090 `
  --public-url http://YOUR_IP:9090 `
  --provider-id MyHub `
  --fullnode 127.0.0.1:8080 `
  --api-token "change-me" `
  --state-path .\data\hub-state.json
```

Local multi-hub lab:

```powershell
.\target\release\hacash-l2-hub.exe --bind 127.0.0.1:9090 --provider-id HubA --state-path .\data\hub-a.json --identity-password lab-a --allow-private-peers
.\target\release\hacash-l2-hub.exe --bind 127.0.0.1:9091 --provider-id HubB --state-path .\data\hub-b.json --identity-password lab-b --bootstrap http://127.0.0.1:9090 --allow-private-peers
```

---

## Easy APIs (wallet + AI)

| Who | Entry |
|-----|--------|
| **AI agent (primary)** | `GET /v1/agent/v1/manifest` — **Hacash Agent Pay** |
| **Wallet** | `GET /v1/wallet/start` → `me` → `pay` → `sign` |

Agent: **[AGENT-PAYMENTS.md](AGENT-PAYMENTS.md)** · Roadmap: **[ROADMAP.md](ROADMAP.md)** · SDKs: **[sdk/](sdk/)**
V3 safety invariants and trustless rollout: **[PROTOCOL-SPEC-V3.md](PROTOCOL-SPEC-V3.md)**
UI: `/dashboard` · `/v1/wallet/ui` · Metrics: `/metrics` · Seeds: `/v1/seeds`

```
Agent:  manifest → quote → pay(idempotency_key) → inbox/sign → receipt
SDK:    drainInbox(key)  +  send({ from, to, amount, key })
```

---

## Protocol layers (in this repo)

| Phase | Feature |
|-------|---------|
| **Agent Pay (HAP)** | Full P0–P4 stack (see [ROADMAP.md](ROADMAP.md)) |
| **Global mesh** | Signed hello, capacity/fees, seeds URL, announce, VPS install |
| **Cross-hub settlement** | Authenticated durable prepare/commit/abort with exactly-once local application |
| **V3 safety foundation** | Durable L1-incarnation provenance, unsigned V2 shadow drafts, portable equivocation proofs, negotiated V2 verification activation; no settlement authority yet |
| Network | Multi-hub gossip, discovery, scoring |
| Whitepaper ops | Rebalance, deferred pay, close package, fee schedule |
| Smart UX | `/v1/wallet/*` |
| Phase B | Canonical payment message + secp256k1 |
| Phase C | Last reconciliation bill + dispute export |

V3 shadow migration endpoints:

- `POST /v1/channels/:id/refresh` strictly observes and persists one exact L1 funding incarnation from the configured fullnode.
- `GET /v1/channels/:id/state-v2/shadow` returns an unsigned V2 candidate. Sequence 1 has no predecessor; later sequences require exactly one mutually signed V2 predecessor.
- `POST /v1/channels/:id/state-v2/observe` verifies and durably stores party-signed V2 evidence. V1 signatures are never reused for the V2 signing domain.
- `GET /v1/channels/:id/state-v2/activation-draft/:state_hash` creates a canonical opt-in commitment only for an already stored, mutually signed V2 state.
- `POST /v1/channels/:id/state-v2/activate` accepts exactly both channel-party signatures and permanently enables gapless predecessor verification for that funding incarnation. It requires durable state and operator authorization when configured.
- `GET /v1/channels/:id/state-v2/activation` returns the certificate and latest mutually signed verification head. Activation never grants settlement authority or L1 enforceability.
- `GET /v1/channels/:id/l1-exit/readiness` queries the configured fullnode's actual registered/enabled action codecs and fails closed before wallet signing or broadcast.

Current Hacash mainnet nodes register cooperative action 3, which requires both channel parties to sign the L1 transaction and returns the original L1 funding distribution. It cannot apply an off-chain negotiated distribution. Legacy unilateral actions 23/27 are modeled in older source but are not registered by the active node, and V1/V2 bill signatures are not valid L1 transaction or legacy reconciliation signatures.

The configured fullnode remains a trust source until Hacash L1 supplies a portable inclusion/state proof and unilateral V2 enforcement. The API does not label these observations as L1-final or trustless.


**Παγκόσμιο δίκτυο (κάθε user → VPS hub):** **[NETWORK-GLOBAL.md](NETWORK-GLOBAL.md)** · install: `scripts/install-vps.sh` · prod docker: `docker-compose.prod.yml`

```bash
# Production identity + join community seeds
export HACASH_L2_IDENTITY_PASSWORD='…'
hacash-l2-hub --bind 0.0.0.0:9090 --public-url https://hub.example.com \
  --provider-id MyHub --bootstrap https://seed1.example \
  --seeds-url https://community.example/seeds.json --api-token '…'
```

Crypto is **self-contained** (`src/hacash_keys.rs`) — same algorithms as Hacash L1 wallets, no link to the miner crate tree.

---

## Relation to fullnode / miner

```
  [Wallet / AI] ──HTTP──► [hacash-l2-hub] ──HTTP query──► [fullnode]
       keys local              this repo                    hacash-fullnodedev
```

- Open/close channels on **L1 fullnode**
- Instant pay + bills coordinated on **this L2 hub**
- Mining is **unrelated** (separate binaries)
